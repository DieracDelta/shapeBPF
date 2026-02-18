use std::collections::HashMap;

use shapebpf_common::ipc::{MatchCriteria, Rule};
use shapebpf_common::RateConfig;

/// Rule engine: matches processes to rules using first-match-wins strategy.
pub struct RuleEngine {
    rules: Vec<Rule>,
    /// PID -> rule name for manually classified processes
    manual_classifications: HashMap<u32, String>,
}

impl RuleEngine {
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            manual_classifications: HashMap::new(),
        }
    }

    pub fn load_rules(&mut self, rules: Vec<Rule>) {
        self.rules = rules;
    }

    pub fn get_rules(&self) -> Vec<Rule> {
        self.rules.clone()
    }

    pub fn upsert_rule(&mut self, rule: Rule) {
        if let Some(existing) = self.rules.iter_mut().find(|r| r.name == rule.name) {
            *existing = rule;
        } else {
            self.rules.push(rule);
        }
    }

    pub fn delete_rule(&mut self, name: &str) {
        self.rules.retain(|r| r.name != name);
    }

    pub fn classify_process(&mut self, pid: u32, rule_name: &str) {
        self.manual_classifications
            .insert(pid, rule_name.to_string());
    }

    /// Find the matching rule for a process. Returns None if unclassified.
    pub fn match_process(
        &self,
        pid: u32,
        uid: u32,
        comm: &str,
        cgroup_path: &str,
        container_name: Option<&str>,
        service_unit: Option<&str>,
    ) -> Option<&Rule> {
        // Check manual classification first
        if let Some(rule_name) = self.manual_classifications.get(&pid) {
            return self.rules.iter().find(|r| r.name == *rule_name);
        }

        // First-match-wins
        self.rules.iter().find(|rule| {
            match &rule.match_criteria {
                MatchCriteria::User(user) => {
                    // Resolve username to UID for comparison
                    nix::unistd::User::from_name(user)
                        .ok()
                        .flatten()
                        .is_some_and(|u| u.uid.as_raw() == uid)
                }
                MatchCriteria::ContainerName(name) => {
                    container_name.is_some_and(|cn| cn == name.as_str())
                }
                MatchCriteria::ServiceUnit(unit) => {
                    service_unit.is_some_and(|su| su == unit.as_str())
                }
                MatchCriteria::CgroupPath(pattern) => cgroup_path.contains(pattern.as_str()),
                MatchCriteria::ProcessName(name) => comm == name.as_str(),
            }
        })
    }

    /// Find the matching rule for a cgroup by path-level criteria only.
    /// Skips ProcessName and User which require per-process info.
    pub fn match_cgroup(
        &self,
        cgroup_path: &str,
        container_name: Option<&str>,
        service_unit: Option<&str>,
    ) -> Option<&Rule> {
        self.rules.iter().find(|rule| match &rule.match_criteria {
            MatchCriteria::ContainerName(name) => {
                container_name.is_some_and(|cn| cn == name.as_str())
            }
            MatchCriteria::ServiceUnit(unit) => {
                service_unit.is_some_and(|su| su == unit.as_str())
            }
            MatchCriteria::CgroupPath(pattern) => cgroup_path.contains(pattern.as_str()),
            _ => false,
        })
    }

    /// Convert a matched rule to a RateConfig for the BPF map.
    pub fn rule_to_rate_config(rule: &Rule) -> RateConfig {
        RateConfig {
            egress_rate_bps: rule.egress_rate_bps.unwrap_or(0),
            ingress_rate_bps: rule.ingress_rate_bps.unwrap_or(0),
            priority: rule.priority,
            _pad: [0; 7],
        }
    }
}
