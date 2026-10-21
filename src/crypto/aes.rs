// KMS uses 128-bit Rijndael blocks with a 160-bit key in V4, standard AES-128
// in V5, and three modified round keys in V6. See vlmcsd's crypto.c.
const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

const INVERSE_SBOX: [u8; 256] = {
    let mut inverse = [0; 256];
    let mut index = 0;
    while index < 256 {
        inverse[SBOX[index] as usize] = index as u8;
        index += 1;
    }
    inverse
};

pub struct Aes {
    keys: [[u8; 16]; 12],
    rounds: usize,
}

impl Aes {
    pub fn v4() -> Self {
        Self::new(&[
            0x05, 0x3d, 0x83, 0x07, 0xf9, 0xe5, 0xf0, 0x88, 0xeb, 0x5e, 0xa6, 0x68, 0x6c, 0xf0,
            0x37, 0xc7, 0xe4, 0xef, 0xd2, 0xd6,
        ])
    }

    pub fn v5() -> Self {
        Self::new(&[
            0xcd, 0x7e, 0x79, 0x6f, 0x2a, 0xb2, 0x5d, 0xcb, 0x55, 0xff, 0xc8, 0xef, 0x83, 0x64,
            0xc4, 0x70,
        ])
    }

    pub fn v6() -> Self {
        let mut aes = Self::new(&[
            0xa9, 0x4a, 0x41, 0x95, 0xe2, 0x01, 0x43, 0x2d, 0x9b, 0xcb, 0x46, 0x04, 0x05, 0xd8,
            0x4a, 0x21,
        ]);
        aes.keys[4][0] ^= 0x73;
        aes.keys[6][0] ^= 0x09;
        aes.keys[8][0] ^= 0xe4;
        aes
    }

    fn new(key: &[u8]) -> Self {
        let words = key.len() / 4;
        let rounds = words + 6;
        let mut expanded = [0; 192];
        expanded[..key.len()].copy_from_slice(key);
        let mut rcon = 1;
        for word in words..4 * (rounds + 1) {
            let offset = word * 4;
            let mut previous: [u8; 4] = expanded[offset - 4..offset].try_into().unwrap();
            if word % words == 0 {
                previous.rotate_left(1);
                previous = previous.map(|byte| SBOX[byte as usize]);
                previous[0] ^= rcon;
                rcon = xtime(rcon);
            }
            for index in 0..4 {
                expanded[offset + index] = expanded[offset - key.len() + index] ^ previous[index];
            }
        }
        let mut keys = [[0; 16]; 12];
        for (key, bytes) in keys.iter_mut().zip(expanded.chunks_exact(16)) {
            key.copy_from_slice(bytes);
        }
        Self { keys, rounds }
    }

    pub fn encrypt_block(&self, block: &mut [u8; 16]) {
        xor(block, &self.keys[0]);
        for round in 1..=self.rounds {
            for byte in block.iter_mut() {
                *byte = SBOX[*byte as usize];
            }
            shift_rows(block, false);
            if round != self.rounds {
                mix_columns(block, false);
            }
            xor(block, &self.keys[round]);
        }
    }

    fn decrypt_block(&self, block: &mut [u8; 16]) {
        xor(block, &self.keys[self.rounds]);
        for round in (0..self.rounds).rev() {
            shift_rows(block, true);
            for byte in block.iter_mut() {
                *byte = INVERSE_SBOX[*byte as usize];
            }
            xor(block, &self.keys[round]);
            if round != 0 {
                mix_columns(block, true);
            }
        }
    }

    pub fn encrypt_cbc(&self, data: &mut Vec<u8>) {
        let padding = 16 - data.len() % 16;
        data.resize(data.len() + padding, padding as u8);
        let mut previous = [0; 16];
        for bytes in data.chunks_exact_mut(16) {
            let block: &mut [u8; 16] = bytes.try_into().unwrap();
            xor(block, &previous);
            self.encrypt_block(block);
            previous = *block;
        }
    }

    pub fn decrypt_cbc(&self, data: &mut [u8]) {
        // Callers supply the fixed-size, block-aligned KMS encrypted request.
        assert!(data.len().is_multiple_of(16));
        let mut previous = [0; 16];
        for bytes in data.chunks_exact_mut(16) {
            let block: &mut [u8; 16] = bytes.try_into().unwrap();
            let ciphertext = *block;
            self.decrypt_block(block);
            xor(block, &previous);
            previous = ciphertext;
        }
    }
}

pub fn xor(block: &mut [u8; 16], other: &[u8; 16]) {
    for (byte, other) in block.iter_mut().zip(other) {
        *byte ^= other;
    }
}

fn xtime(value: u8) -> u8 {
    (value << 1) ^ if value & 0x80 != 0 { 0x1b } else { 0 }
}

fn multiply(mut value: u8, mut factor: u8) -> u8 {
    let mut result = 0;
    while factor != 0 {
        if factor & 1 != 0 {
            result ^= value;
        }
        value = xtime(value);
        factor >>= 1;
    }
    result
}

fn shift_rows(block: &mut [u8; 16], inverse: bool) {
    let original = *block;
    for column in 0..4 {
        for row in 0..4 {
            let source_column = if inverse {
                column + 4 - row
            } else {
                column + row
            } % 4;
            block[column * 4 + row] = original[source_column * 4 + row];
        }
    }
}

fn mix_columns(block: &mut [u8; 16], inverse: bool) {
    let coefficients = if inverse {
        [14, 11, 13, 9]
    } else {
        [2, 3, 1, 1]
    };
    for column in block.chunks_exact_mut(4) {
        let original: [u8; 4] = column.try_into().unwrap();
        for row in 0..4 {
            column[row] = 0;
            for index in 0..4 {
                column[row] ^= multiply(original[(row + index) % 4], coefficients[index]);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aes128_matches_fips197_example() {
        let aes = Aes::new(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
        let plaintext = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        let ciphertext = [
            0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4,
            0xc5, 0x5a,
        ];
        let mut block = plaintext;
        aes.encrypt_block(&mut block);
        assert_eq!(block, ciphertext);
        aes.decrypt_block(&mut block);
        assert_eq!(block, plaintext);
    }
}
