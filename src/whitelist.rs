use std::net::IpAddr;

use regex::RegexSet;
use serde::{Deserialize, Deserializer, de::Error};

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Whitelist {
    enable: bool,
    #[serde(deserialize_with = "deserialize_patterns")]
    hostnames: RegexSet,
    #[serde(deserialize_with = "deserialize_patterns")]
    ips: RegexSet,
}

impl Whitelist {
    pub fn allows(&self, hostname: &str, ip: IpAddr) -> bool {
        !self.enable
            || (self.hostnames.is_match(hostname)
                && self.ips.is_match(&ip.to_canonical().to_string()))
    }
}

fn deserialize_patterns<'de, D>(deserializer: D) -> Result<RegexSet, D::Error>
where
    D: Deserializer<'de>,
{
    let patterns = Vec::<String>::deserialize(deserializer)?;
    RegexSet::new(patterns).map_err(D::Error::custom)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_peer_ip_in_canonical_form_without_a_port() {
        let whitelist: Whitelist = toml::from_str(
            r#"
            enable = true
            hostnames = ['^kms-test\.example$']
            ips = ['^192\.0\.2\.10$', '^2001:db8::1$']
            "#,
        )
        .unwrap();
        for address in ["192.0.2.10", "::ffff:192.0.2.10", "2001:0db8:0:0:0:0:0:1"] {
            assert!(whitelist.allows("kms-test.example", address.parse().unwrap()));
        }
        assert!(!whitelist.allows("kms-test.example", "192.0.2.11".parse().unwrap()));
    }
}
