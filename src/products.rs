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
}

impl Default for Epids {
    fn default() -> Self {
        // Fixed ePIDs from vlmcsd's embedded product data.
        Self {
            windows: "03612-00206-556-123727-03-1033-17763.0000-2972018".into(),
            win_china_gov: "03612-03858-053-089516-03-1033-17763.0000-2972018".into(),
            office2010: "03612-00096-199-799188-03-1033-17763.0000-2972018".into(),
            office2013: "03612-00206-240-719639-03-1033-17763.0000-2972018".into(),
            office2016: "03612-00206-438-004532-03-1033-17763.0000-2972018".into(),
            office2019: "03612-00206-684-137669-03-1033-17763.0000-2972018".into(),
        }
    }
}

impl Epids {
    pub fn entries(&self) -> [(&str, &str); 6] {
        [
            ("windows", &self.windows),
            ("win_china_gov", &self.win_china_gov),
            ("office2010", &self.office2010),
            ("office2013", &self.office2013),
            ("office2016", &self.office2016),
            ("office2019", &self.office2019),
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
            _ => &self.windows,
        }
    }
}
