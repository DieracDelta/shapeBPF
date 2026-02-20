use std::collections::HashMap;
use std::path::{Path, PathBuf};

use shapebpf_common::ipc::{MatchCriteria, Rule};
use shapebpf_common::RateConfig;

/// Rule engine: matches processes to rules using first-match-wins strategy.
pub struct RuleEngine {
    rules: Vec<Rule>,
    /// PID -> rule name for manually classified processes
    manual_classifications: HashMap<u32, String>,
    /// Path to persist non-ephemeral rules as JSON
    rules_path: Option<PathBuf>,
}

impl RuleEngine {
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            manual_classifications: HashMap::new(),
            rules_path: None,
        }
    }

    pub fn set_rules_path(&mut self, path: PathBuf) {
        self.rules_path = Some(path);
    }

    pub fn load_rules(&mut self, rules: Vec<Rule>) {
        self.rules = rules;
    }

    /// Load rules from a JSON file on disk.
    pub fn load_rules_from_file(path: &Path) -> Result<Vec<Rule>, Box<dyn std::error::Error>> {
        let data = std::fs::read_to_string(path)?;
        let rules: Vec<Rule> = serde_json::from_str(&data)?;
        Ok(rules)
    }

    /// Persist non-ephemeral rules to the configured JSON file.
    pub fn save_rules(&self) {
        let Some(path) = &self.rules_path else {
            return;
        };
        let persistent: Vec<&Rule> = self.rules.iter().filter(|r| !r.ephemeral).collect();
        match serde_json::to_string_pretty(&persistent) {
            Ok(json) => {
                if let Err(e) = std::fs::write(path, json) {
                    log::error!("failed to save rules to {}: {e:#}", path.display());
                }
            }
            Err(e) => {
                log::error!("failed to serialize rules: {e:#}");
            }
        }
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
        self.save_rules();
    }

    pub fn delete_rule(&mut self, name: &str) {
        self.rules.retain(|r| r.name != name);
        self.save_rules();
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn make_rule(name: &str, ephemeral: bool) -> Rule {
        Rule {
            name: name.to_string(),
            match_criteria: MatchCriteria::ProcessName(name.to_string()),
            egress_rate_bps: Some(1_000_000),
            ingress_rate_bps: None,
            priority: 5,
            ephemeral,
        }
    }

    #[test]
    fn save_excludes_ephemeral_rules() {
        let file = NamedTempFile::new().unwrap();
        let path = file.path().to_path_buf();

        let mut engine = RuleEngine::new();
        engine.set_rules_path(path.clone());
        engine.upsert_rule(make_rule("persistent", false));
        engine.upsert_rule(make_rule("ephemeral", true));

        let saved: Vec<Rule> = RuleEngine::load_rules_from_file(&path).unwrap();
        assert_eq!(saved.len(), 1);
        assert_eq!(saved[0].name, "persistent");
    }

    #[test]
    fn upsert_auto_saves() {
        let file = NamedTempFile::new().unwrap();
        let path = file.path().to_path_buf();

        let mut engine = RuleEngine::new();
        engine.set_rules_path(path.clone());
        engine.upsert_rule(make_rule("rule1", false));

        let saved = RuleEngine::load_rules_from_file(&path).unwrap();
        assert_eq!(saved.len(), 1);
        assert_eq!(saved[0].name, "rule1");

        // Upsert same name updates in place
        let mut updated = make_rule("rule1", false);
        updated.priority = 9;
        engine.upsert_rule(updated);

        let saved = RuleEngine::load_rules_from_file(&path).unwrap();
        assert_eq!(saved.len(), 1);
        assert_eq!(saved[0].priority, 9);
    }

    #[test]
    fn delete_auto_saves() {
        let file = NamedTempFile::new().unwrap();
        let path = file.path().to_path_buf();

        let mut engine = RuleEngine::new();
        engine.set_rules_path(path.clone());
        engine.upsert_rule(make_rule("rule1", false));
        engine.upsert_rule(make_rule("rule2", false));

        engine.delete_rule("rule1");

        let saved = RuleEngine::load_rules_from_file(&path).unwrap();
        assert_eq!(saved.len(), 1);
        assert_eq!(saved[0].name, "rule2");
    }

    #[test]
    fn load_from_file_roundtrip() {
        let file = NamedTempFile::new().unwrap();
        let path = file.path().to_path_buf();

        let mut engine = RuleEngine::new();
        engine.set_rules_path(path.clone());
        engine.upsert_rule(make_rule("alpha", false));
        engine.upsert_rule(make_rule("beta", false));

        // Load into fresh engine
        let rules = RuleEngine::load_rules_from_file(&path).unwrap();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].name, "alpha");
        assert_eq!(rules[1].name, "beta");
        assert!(!rules[0].ephemeral);
    }

    #[test]
    fn load_from_missing_file_errors() {
        let result = RuleEngine::load_rules_from_file(Path::new("/tmp/nonexistent_shapebpf_test.json"));
        assert!(result.is_err());
    }

    #[test]
    fn load_json_without_ephemeral_field_defaults_false() {
        let json = r#"[{
            "name": "old_rule",
            "match_criteria": {"ProcessName": "bash"},
            "egress_rate_bps": null,
            "ingress_rate_bps": null,
            "priority": 5
        }]"#;
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(json.as_bytes()).unwrap();
        file.flush().unwrap();

        let rules = RuleEngine::load_rules_from_file(file.path()).unwrap();
        assert_eq!(rules.len(), 1);
        assert!(!rules[0].ephemeral);
    }

    #[test]
    fn no_rules_path_save_is_noop() {
        let mut engine = RuleEngine::new();
        // No set_rules_path — save_rules should silently do nothing
        engine.upsert_rule(make_rule("rule1", false));
        // If we got here without panic, the test passes
        assert_eq!(engine.get_rules().len(), 1);
    }

    #[test]
    fn delete_ephemeral_rule_not_in_file() {
        let file = NamedTempFile::new().unwrap();
        let path = file.path().to_path_buf();

        let mut engine = RuleEngine::new();
        engine.set_rules_path(path.clone());
        engine.upsert_rule(make_rule("persistent", false));
        engine.upsert_rule(make_rule("ephemeral", true));

        // Both exist in memory
        assert_eq!(engine.get_rules().len(), 2);

        // Only persistent on disk
        let saved = RuleEngine::load_rules_from_file(&path).unwrap();
        assert_eq!(saved.len(), 1);

        // Delete the ephemeral one
        engine.delete_rule("ephemeral");
        assert_eq!(engine.get_rules().len(), 1);

        // File still has only the persistent rule
        let saved = RuleEngine::load_rules_from_file(&path).unwrap();
        assert_eq!(saved.len(), 1);
        assert_eq!(saved[0].name, "persistent");
    }
}
