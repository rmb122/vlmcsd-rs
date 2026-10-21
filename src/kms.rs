use std::net::IpAddr;

use crate::{
    config::Config,
    crypto::{
        self,
        aes::{Aes, xor},
    },
    wire::{Reader, put_u32},
};

pub const INVALID_DATA: u32 = 0x8007_000d;
const ACCESS_DENIED: u32 = 0x8007_0005;
const INTERNAL_ERROR: u32 = 0x8000_ffff;
const BASE_REQUEST_SIZE: usize = 236;

pub struct Service {
    config: Config,
    hardware_id: [u8; 8],
}

struct Request {
    version: u32,
    kms_id: [u8; 16],
    client_id: [u8; 16],
    minimum_clients: u32,
    timestamp: u64,
    hostname: String,
}

impl Request {
    fn parse(data: &[u8]) -> Result<Self, u32> {
        let mut reader = Reader::new(data.get(..BASE_REQUEST_SIZE).ok_or(INVALID_DATA)?);
        let version = reader.u32().map_err(|_| INVALID_DATA)?;
        reader.take(44).map_err(|_| INVALID_DATA)?;
        let kms_id = reader.array().map_err(|_| INVALID_DATA)?;
        let client_id = reader.array().map_err(|_| INVALID_DATA)?;
        let minimum_clients = reader.u32().map_err(|_| INVALID_DATA)?;
        let timestamp = reader.u64().map_err(|_| INVALID_DATA)?;
        reader.take(16).map_err(|_| INVALID_DATA)?;
        let hostname: Vec<u16> = reader
            .take(128)
            .map_err(|_| INVALID_DATA)?
            .chunks_exact(2)
            .map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]))
            .take_while(|unit| *unit != 0)
            .collect();
        let hostname = String::from_utf16(&hostname).map_err(|_| INVALID_DATA)?;
        if minimum_clients > 1000 {
            return Err(INVALID_DATA);
        }
        Ok(Self {
            version,
            kms_id,
            client_id,
            minimum_clients,
            timestamp,
            hostname,
        })
    }
}

impl Service {
    pub fn new(config: Config) -> Result<Self, String> {
        let hardware_id = config.hardware_id()?;
        Ok(Self {
            config,
            hardware_id,
        })
    }

    pub fn respond(&self, data: &[u8], peer_ip: IpAddr) -> Result<Vec<u8>, u32> {
        let mut random = [0; 32];
        getrandom::fill(&mut random).map_err(|error| {
            eprintln!("cannot obtain response randomness: {error}");
            INTERNAL_ERROR
        })?;
        self.create_response(data, &random, peer_ip)
    }

    fn create_response(
        &self,
        data: &[u8],
        random: &[u8; 32],
        peer_ip: IpAddr,
    ) -> Result<Vec<u8>, u32> {
        let version = Reader::new(data).u32().map_err(|_| INVALID_DATA)?;
        if !matches!(version, 0x0004_0000 | 0x0005_0000 | 0x0006_0000) {
            return Err(INVALID_DATA);
        }
        if version == 0x0004_0000 {
            // Like vlmcsd, accept the client's MAC without imposing a new policy.
            data.get(..BASE_REQUEST_SIZE + 16).ok_or(INVALID_DATA)?;
            let request = Request::parse(data)?;
            let mut response = self.base_response(&request, peer_ip)?;
            response.extend_from_slice(&crypto::v4_mac(&response));
            return Ok(response);
        }

        let v6 = version == 0x0006_0000;
        let aes = if v6 { Aes::v6() } else { Aes::v5() };
        // Decrypt the transmitted IV as the first block with a zero IV,
        // matching vlmcsd's salt handling for both V5 and V6.
        let mut decrypted = data.get(4..260).ok_or(INVALID_DATA)?.to_vec();
        aes.decrypt_cbc(&mut decrypted);
        let request_salt: [u8; 16] = decrypted[..16].try_into().unwrap();
        let request = Request::parse(&decrypted[16..])?;
        if request.version != version {
            return Err(INVALID_DATA);
        }

        let mut response = if v6 {
            random[16..].to_vec()
        } else {
            request_salt.to_vec()
        };
        response.extend_from_slice(&self.base_response(&request, peer_ip)?);
        let mut random_salt: [u8; 16] = random[..16].try_into().unwrap();
        let hash = crypto::sha256(&random_salt);
        xor(&mut random_salt, &request_salt);
        response.extend_from_slice(&random_salt);
        response.extend_from_slice(&hash);
        if v6 {
            response.extend_from_slice(&self.hardware_id);
            response.extend_from_slice(&request_salt);
            response.extend_from_slice(&crypto::v6_hmac(&response, request.timestamp));
        }
        aes.encrypt_cbc(&mut response);
        let mut result = version.to_le_bytes().to_vec();
        result.extend_from_slice(&response);
        Ok(result)
    }

    fn base_response(&self, request: &Request, peer_ip: IpAddr) -> Result<Vec<u8>, u32> {
        let peer_ip = peer_ip.to_canonical();
        let allowed = self.config.whitelist.allows(&request.hostname, peer_ip);
        let decision = if allowed { "allowed" } else { "denied" };
        eprintln!(
            "activation {decision}: hostname={:?} ip={peer_ip}",
            request.hostname
        );
        if !allowed {
            return Err(ACCESS_DENIED);
        }
        let epid: Vec<u16> = self
            .config
            .epids
            .for_kms_id(request.kms_id)
            .encode_utf16()
            .chain(Some(0))
            .collect();
        let mut response = Vec::with_capacity(44 + epid.len() * 2);
        put_u32(&mut response, request.version);
        put_u32(&mut response, (epid.len() * 2) as u32);
        for unit in epid {
            response.extend_from_slice(&unit.to_le_bytes());
        }
        response.extend_from_slice(&request.client_id);
        response.extend_from_slice(&request.timestamp.to_le_bytes());
        put_u32(&mut response, (request.minimum_clients * 2).max(1));
        put_u32(&mut response, self.config.activation_interval_minutes);
        put_u32(&mut response, self.config.renewal_interval_minutes);
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ENTROPY: &[u8; 32] = include_bytes!("../tests/fixtures/entropy.bin");
    const PEER_IP: IpAddr = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
    const VECTORS: [(&[u8], &[u8]); 3] = [
        (
            include_bytes!("../tests/fixtures/v4-request.bin"),
            include_bytes!("../tests/fixtures/v4-response.bin"),
        ),
        (
            include_bytes!("../tests/fixtures/v5-request.bin"),
            include_bytes!("../tests/fixtures/v5-response.bin"),
        ),
        (
            include_bytes!("../tests/fixtures/v6-request.bin"),
            include_bytes!("../tests/fixtures/v6-response.bin"),
        ),
    ];

    #[test]
    fn responses_match_independent_vlmcsd_vectors() {
        let service = Service::new(
            toml::from_str(
                r#"
                [whitelist]
                enable = true
                hostnames = ['^kms-test\.example$']
                ips = ['^127\.0\.0\.1$']
                "#,
            )
            .unwrap(),
        )
        .unwrap();
        for (request, expected) in VECTORS {
            let response = service.create_response(request, ENTROPY, PEER_IP).unwrap();
            assert_eq!(response, expected, "KMS V{}", request[2]);
        }
    }

    #[test]
    fn rejects_truncated_requests_and_unsupported_versions() {
        let service = Service::new(Config::default()).unwrap();
        for (request, _) in VECTORS {
            assert_eq!(
                service.create_response(&request[..request.len() - 1], ENTROPY, PEER_IP),
                Err(INVALID_DATA)
            );
        }
        for version in [0x0003_0000_u32, 0x0004_0001, 0x0007_0000] {
            let mut request = VECTORS[0].0.to_vec();
            request[..4].copy_from_slice(&version.to_le_bytes());
            assert_eq!(
                service.create_response(&request, ENTROPY, PEER_IP),
                Err(INVALID_DATA)
            );
        }
        let mut request = VECTORS[0].0.to_vec();
        request[80..84].copy_from_slice(&1001_u32.to_le_bytes());
        assert_eq!(
            service.create_response(&request, ENTROPY, PEER_IP),
            Err(INVALID_DATA)
        );
    }

    #[test]
    fn decodes_null_terminated_utf16_hostname_and_rejects_invalid_encoding() {
        let mut request = VECTORS[0].0.to_vec();
        request[108..236].fill(0xff);
        for (index, unit) in "工作站01.example".encode_utf16().chain(Some(0)).enumerate() {
            request[108 + index * 2..110 + index * 2].copy_from_slice(&unit.to_le_bytes());
        }
        assert_eq!(
            Request::parse(&request).unwrap().hostname,
            "工作站01.example"
        );

        request[108..112].copy_from_slice(&[0, 0xd8, 0, 0]);
        assert!(matches!(Request::parse(&request), Err(INVALID_DATA)));
    }
}
