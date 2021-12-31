mod aes;
pub use aes::*;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn aes_decrypt() {
        let c = aes::ecb::new(b"\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c");
        let mut out = [0; 16];
        c.decrypt(
            b"\x3a\xd7\x7b\xb4\x0d\x7a\x36\x60\xa8\x9e\xca\xf3\x24\x66\xef\x97",
            &mut out,
        );
        assert_eq!(
            &out,
            b"\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a"
        );
    }
}
