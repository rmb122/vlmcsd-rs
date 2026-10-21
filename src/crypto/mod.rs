pub mod aes;

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

use aes::{Aes, xor};

pub fn v4_mac(message: &[u8]) -> [u8; 16] {
    let aes = Aes::v4();
    let mut padded = message.to_vec();
    padded.push(0x80);
    padded.resize(padded.len().next_multiple_of(16), 0);
    let mut mac = [0; 16];
    for block in padded.chunks_exact(16) {
        xor(&mut mac, block.try_into().unwrap());
        aes.encrypt_block(&mut mac);
    }
    mac
}

pub fn sha256(message: &[u8]) -> [u8; 32] {
    Sha256::digest(message).into()
}

pub fn v6_hmac(message: &[u8], timestamp: u64) -> [u8; 16] {
    let slot = (timestamp / 0x0000_0022_8168_89bd)
        .wrapping_mul(0x0000_0020_8cba_b5ed)
        .wrapping_add(0x3156_cd5a_c628_477a);
    let key = sha256(&slot.to_le_bytes());
    let mut mac =
        Hmac::<Sha256>::new_from_slice(&key[16..]).expect("HMAC accepts a key of any size");
    mac.update(message);
    mac.finalize().into_bytes()[16..].try_into().unwrap()
}
