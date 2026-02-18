use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub general: GeneralConfig,
    pub default_rule: DefaultRuleConfig,
    #[serde(default)]
    pub rules: Vec<RuleConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneralConfig {
    pub interface: String,
    #[serde(default = "default_stats_interval")]
    pub stats_interval_ms: u64,
}

fn default_stats_interval() -> u64 {
    1000
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefaultRuleConfig {
    #[serde(default)]
    pub egress_rate_bps: u64,
    #[serde(default)]
    pub ingress_rate_bps: u64,
    #[serde(default = "default_priority")]
    pub priority: u8,
}

fn default_priority() -> u8 {
    8
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleConfig {
    pub name: String,
    #[serde(default)]
    pub user: Option<String>,
    #[serde(default)]
    pub container_name: Option<String>,
    #[serde(default)]
    pub service_unit: Option<String>,
    #[serde(default)]
    pub cgroup_path: Option<String>,
    #[serde(default)]
    pub process_name: Option<String>,
    #[serde(default)]
    pub egress_rate_bps: Option<u64>,
    #[serde(default)]
    pub ingress_rate_bps: Option<u64>,
    #[serde(default = "default_priority")]
    pub priority: u8,
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("reading config from {}", path.display()))?;
        toml::from_str(&content).context("parsing config TOML")
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let content = toml::to_string_pretty(self).context("serializing config")?;
        std::fs::write(path, content)
            .with_context(|| format!("writing config to {}", path.display()))
    }
}
