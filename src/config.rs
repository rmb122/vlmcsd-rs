use std::{fs, net::SocketAddr, path::Path};

use serde::Deserialize;

use crate::{products::Epids, whitelist::Whitelist};

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub listen: SocketAddr,
    pub hwid: String,
    pub activation_interval_minutes: u32,
    pub renewal_interval_minutes: u32,
    pub epids: Epids,
    pub whitelist: Whitelist,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: SocketAddr::from(([0, 0, 0, 0], 1688)),
            hwid: "3A1C049600B60076".into(),
            activation_interval_minutes: 120,
            renewal_interval_minutes: 10080,
            epids: Epids::default(),
            whitelist: Whitelist::default(),
        }
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, String> {
        let text = fs::read_to_string(path)
            .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
        Self::parse(&text).map_err(|error| format!("{}: {error}", path.display()))
    }

    fn parse(text: &str) -> Result<Self, String> {
        let config: Self = toml::from_str(text).map_err(|error| error.to_string())?;
        config.hardware_id()?;
        if config.activation_interval_minutes == 0 || config.renewal_interval_minutes == 0 {
            return Err("activation and renewal intervals must be positive minutes".into());
        }
        for (name, epid) in config.epids.entries() {
            let length = epid.encode_utf16().count();
            if !(1..=63).contains(&length) || epid.contains('\0') {
                return Err(format!(
                    "epids.{name} must contain 1 to 63 UTF-16 code units without NUL"
                ));
            }
        }
        Ok(config)
    }

    pub fn hardware_id(&self) -> Result<[u8; 8], String> {
        if self.hwid.len() != 16 || !self.hwid.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err("hwid must contain exactly 16 hexadecimal digits".into());
        }
        let mut result = [0; 8];
        for (index, byte) in result.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&self.hwid[index * 2..index * 2 + 2], 16)
                .expect("hexadecimal digits were checked");
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partial_configuration_overrides_only_specified_fields() {
        let config = Config::parse(
            r#"
            listen = "[::1]:1689"
            hwid = "0123456789abcdef"
            renewal_interval_minutes = 1440
            [epids]
            office2016 = "custom-office-server"
            office2021 = "custom-office-2021"
            "#,
        )
        .unwrap();
        assert_eq!(config.listen, "[::1]:1689".parse().unwrap());
        assert_eq!(
            config.hardware_id().unwrap(),
            [1, 35, 69, 103, 137, 171, 205, 239]
        );
        assert_eq!(config.renewal_interval_minutes, 1440);
        assert_eq!(config.activation_interval_minutes, 120);
        assert_eq!(config.epids.office2016, "custom-office-server");
        assert_eq!(config.epids.office2021, "custom-office-2021");
        assert_eq!(config.epids.office2024, Epids::default().office2024);
        assert_eq!(config.epids.windows, Epids::default().windows);
    }

    #[test]
    fn invalid_configuration_is_rejected_before_listening() {
        for input in [
            "listen = 'invalid-address'".to_owned(),
            "hwid = 'not-a-hardware-id'".to_owned(),
            "renewal_interval_minutes = 0".to_owned(),
            "activation_interval_minutes = -1".to_owned(),
            "renewal_intervl_minutes = 10".to_owned(),
            "[epids]\nwindows = ''".to_owned(),
            "[epids]\noffice2021 = ''".to_owned(),
            "[whitelist]\nhostnames = ['[']".to_owned(),
            "[whitelist]\nips = ['[']".to_owned(),
            format!("[epids]\nwindows = '{}'", "x".repeat(64)),
            format!("[epids]\nwindows = '{}'", "😀".repeat(32)),
            format!("[epids]\noffice2024 = '{}'", "x".repeat(64)),
        ] {
            assert!(Config::parse(&input).is_err(), "{input}");
        }
    }
}
