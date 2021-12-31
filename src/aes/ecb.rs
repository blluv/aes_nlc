use super::aes::Aes;

pub struct AesEcb {
    aes: Aes,
}

pub fn new(key: &[u8]) -> AesEcb {
    let mut aes = Aes {
        enc: Vec::new(),
        dec: Vec::new(),
    };
    aes.expand_key(key);

    AesEcb { aes: aes }
}

impl AesEcb {
    pub fn decrypt(self, data: &[u8], out: &mut [u8]) {
        assert_eq!(data.len() % 16, 0);

        for i in (0..data.len()).step_by(16) {
            self.aes.decrypt_block(&data[i..i + 16], &mut out[i..i + 16]);
        }
    }
}
