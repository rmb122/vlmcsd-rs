use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Epids {
    pub windows: String,
    pub win_china_gov: String,
    pub office2010: String,
    pub office2013: String,
    pub office2016: String,
    pub office2019: String,
    pub office2021: String,
    pub office2024: String,
}

impl Default for Epids {
    fn default() -> Self {
        // Windows and Office 2010-2019 identities use vlmcsd's embedded data.
        Self {
            windows: "03612-00206-556-123727-03-1033-17763.0000-2972018".into(),
            win_china_gov: "03612-03858-053-089516-03-1033-17763.0000-2972018".into(),
            office2010: "03612-00096-199-799188-03-1033-17763.0000-2972018".into(),
            office2013: "03612-00206-240-719639-03-1033-17763.0000-2972018".into(),
            office2016: "03612-00206-438-004532-03-1033-17763.0000-2972018".into(),
            office2019: "03612-00206-684-137669-03-1033-17763.0000-2972018".into(),
            // Newer Office identities use license-manager's product key IDs
            // with the same Windows Server 2019 host fields; see README.md.
            office2021: "03612-00206-578-810880-03-1033-17763.0000-0172025".into(),
            office2024: "03612-00206-601-010329-03-1033-17763.0000-0172025".into(),
        }
    }
}

impl Epids {
    pub fn entries(&self) -> [(&str, &str); 8] {
        [
            ("windows", &self.windows),
            ("win_china_gov", &self.win_china_gov),
            ("office2010", &self.office2010),
            ("office2013", &self.office2013),
            ("office2016", &self.office2016),
            ("office2019", &self.office2019),
            ("office2021", &self.office2021),
            ("office2024", &self.office2024),
        ]
    }

    pub fn for_kms_id(&self, id: [u8; 16]) -> &str {
        // GUIDs are in their on-wire little-endian representation.
        match id {
            [
                0x23,
                0xbf,
                0xa0,
                0x7b,
                0xf5,
                0xd0,
                0x72,
                0x40,
                0x91,
                0xd9,
                0xd5,
                0x5a,
                0xf5,
                0xa4,
                0x81,
                0xb6,
            ] => &self.win_china_gov,
            [
                0x46,
                0xf9,
                0x5a,
                0xe8,
                0x25,
                0x2e,
                0xb7,
                0x47,
                0x83,
                0xe1,
                0xbe,
                0xbc,
                0xeb,
                0xea,
                0xc6,
                0x11,
            ] => &self.office2010,
            [
                0xbf,
                0xf1,
                0xa6,
                0xe6,
                0x40,
                0x9d,
                0xc3,
                0x40,
                0xaa,
                0x9f,
                0xc7,
                0x7b,
                0xa2,
                0x15,
                0x78,
                0xc0,
            ] => &self.office2013,
            [
                0x1b,
                0xf6,
                0xb5,
                0x85,
                0x0b,
                0x32,
                0xe3,
                0x4b,
                0x81,
                0x4a,
                0xb7,
                0x6b,
                0x2b,
                0xfa,
                0xfc,
                0x82,
            ] => &self.office2016,
            [
                0xb1,
                0x9e,
                0x7d,
                0x61,
                0x36,
                0xef,
                0x82,
                0x4f,
                0x86,
                0xe0,
                0xa6,
                0x5a,
                0xe0,
                0x7b,
                0x96,
                0xc6,
            ] => &self.office2019,
            [
                0x16,
                0x0b,
                0xd5,
                0x86,
                0x08,
                0x48,
                0xaf,
                0x41,
                0xb8,
                0x3b,
                0xb3,
                0x38,
                0x27,
                0x43,
                0x18,
                0xb2,
            ] => &self.office2021,
            [
                0xb5,
                0x3c,
                0x97,
                0xa8,
                0x03,
                0xbf,
                0x4c,
                0x0a,
                0x9c,
                0xef,
                0x70,
                0x30,
                0x99,
                0x64,
                0x5a,
                0xb3,
            ] => &self.office2024,
            _ => &self.windows,
        }
    }
}
