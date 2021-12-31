use super::constants::{RCON, SBOX0, SBOX1, TABLE_DEC0, TABLE_DEC1, TABLE_DEC2, TABLE_DEC3};

pub struct Aes {
    pub enc: Vec<u32>,
    pub dec: Vec<u32>,
}

impl Aes {
    pub fn expand_key(&mut self, key: &[u8]) {
        let key_size = key.len() / 4;
        let ks_size = key.len() + 28;
        for i in 0..key_size {
            self.enc.push(u32::from_be_bytes([
                key[4 * i + 0],
                key[4 * i + 1],
                key[4 * i + 2],
                key[4 * i + 3],
            ]));
        }
        for i in key_size..ks_size {
            let mut t = self.enc[i - 1];
            if i % key_size == 0 {
                t = (t << 8) | (t >> 24);
                t = ((SBOX0[(t >> 24) as usize] as u32) << 24)
                    | ((SBOX0[((t >> 16) & 0xff) as usize] as u32) << 16)
                    | ((SBOX0[((t >> 8) & 0xff) as usize] as u32) << 8)
                    | (SBOX0[(t & 0xff) as usize] as u32);
                t ^= (RCON[(i / key_size) as usize] as u32) << 24;
            } else if key_size > 6 && i % key_size == 4 {
                t = ((SBOX0[(t >> 24) as usize] as u32) << 24)
                    | ((SBOX0[((t >> 16) & 0xff) as usize] as u32) << 16)
                    | ((SBOX0[((t >> 8) & 0xff) as usize] as u32) << 8)
                    | (SBOX0[(t & 0xff) as usize] as u32);
            }
            self.enc.push(self.enc[i - key_size] ^ t);
        }
        for i in 0..ks_size {
            let ki = ks_size - i;
            let t;
            if i % 4 != 0 {
                t = self.enc[ki];
            } else {
                t = self.enc[ki - 4];
            }
            if i < 4 || ki <= 4 {
                self.dec.push(t);
            } else {
                self.dec.push(
                    TABLE_DEC0[SBOX0[(t >> 24) as usize] as usize]
                        ^ TABLE_DEC1[SBOX0[((t >> 16) & 0xff) as usize] as usize]
                        ^ TABLE_DEC2[SBOX0[((t >> 8) & 0xff) as usize] as usize]
                        ^ TABLE_DEC3[SBOX0[(t & 0xff) as usize] as usize],
                );
            }
        }
    }

    pub fn decrypt_block(&self, data: &[u8], out: &mut [u8]) {
        let mut s0 = u32::from_be_bytes(data[0..4].try_into().unwrap());
        let mut s1 = u32::from_be_bytes(data[4..8].try_into().unwrap());
        let mut s2 = u32::from_be_bytes(data[8..12].try_into().unwrap());
        let mut s3 = u32::from_be_bytes(data[12..16].try_into().unwrap());
        std::mem::swap(&mut s1, &mut s3);
        s0 ^= self.dec[0];
        s1 ^= self.dec[1];
        s2 ^= self.dec[2];
        s3 ^= self.dec[3];
        let mut t0;
        let mut t1;
        let mut t2;
        let mut t3;
        let mut k = 4;
        let nr = self.dec.len() / 4 - 2;
        for _ in 0..nr {
            t0 = self.dec[k + 0]
                ^ TABLE_DEC0[((s0 >> 24) & 0xff) as usize]
                ^ TABLE_DEC1[((s1 >> 16) & 0xff) as usize]
                ^ TABLE_DEC2[((s2 >> 8) & 0xff) as usize]
                ^ TABLE_DEC3[((s3) & 0xff) as usize];
            t1 = self.dec[k + 1]
                ^ TABLE_DEC0[((s1 >> 24) & 0xff) as usize]
                ^ TABLE_DEC1[((s2 >> 16) & 0xff) as usize]
                ^ TABLE_DEC2[((s3 >> 8) & 0xff) as usize]
                ^ TABLE_DEC3[((s0) & 0xff) as usize];
            t2 = self.dec[k + 2]
                ^ TABLE_DEC0[((s2 >> 24) & 0xff) as usize]
                ^ TABLE_DEC1[((s3 >> 16) & 0xff) as usize]
                ^ TABLE_DEC2[((s0 >> 8) & 0xff) as usize]
                ^ TABLE_DEC3[((s1) & 0xff) as usize];
            t3 = self.dec[k + 3]
                ^ TABLE_DEC0[((s3 >> 24) & 0xff) as usize]
                ^ TABLE_DEC1[((s0 >> 16) & 0xff) as usize]
                ^ TABLE_DEC2[((s1 >> 8) & 0xff) as usize]
                ^ TABLE_DEC3[((s2) & 0xff) as usize];
            k += 4;
            s0 = t0;
            s1 = t1;
            s2 = t2;
            s3 = t3;
        }
        t0 = self.dec[k]
            ^ ((SBOX1[(s0 >> 24) as usize] as u32) << 24
                | (SBOX1[((s1 >> 16) & 0xff) as usize] as u32) << 16
                | (SBOX1[((s2 >> 8) & 0xff) as usize] as u32) << 8
                | SBOX1[(s3 & 0xff) as usize] as u32);
        t1 = self.dec[k + 1]
            ^ ((SBOX1[(s1 >> 24) as usize] as u32) << 24
                | (SBOX1[((s2 >> 16) & 0xff) as usize] as u32) << 16
                | (SBOX1[((s3 >> 8) & 0xff) as usize] as u32) << 8
                | SBOX1[(s0 & 0xff) as usize] as u32);
        t2 = self.dec[k + 2]
            ^ ((SBOX1[(s2 >> 24) as usize] as u32) << 24
                | (SBOX1[((s3 >> 16) & 0xff) as usize] as u32) << 16
                | (SBOX1[((s0 >> 8) & 0xff) as usize] as u32) << 8
                | SBOX1[(s1 & 0xff) as usize] as u32);
        t3 = self.dec[k + 3]
            ^ ((SBOX1[(s3 >> 24) as usize] as u32) << 24
                | (SBOX1[((s0 >> 16) & 0xff) as usize] as u32) << 16
                | (SBOX1[((s1 >> 8) & 0xff) as usize] as u32) << 8
                | SBOX1[(s2 & 0xff) as usize] as u32);
        std::mem::swap(&mut t1, &mut t3);
        out[0..4].copy_from_slice(&t0.to_be_bytes());
        out[4..8].copy_from_slice(&t1.to_be_bytes());
        out[8..12].copy_from_slice(&t2.to_be_bytes());
        out[12..16].copy_from_slice(&t3.to_be_bytes());
    }
}
