use crypto_types::*;

#[derive(Debug, PartialEq, Eq)]
pub struct CipherState<C: CipherType> {
    cipher: C,
    n: u64,
    overflow: bool
}

impl<C: CipherType> CipherState<C> {

    pub fn new(key: C::Key, n: u64) -> CipherState<C> {
        CipherState {
            cipher: C::new(key),
            n: n,
            overflow: false,
        }
    }

    pub fn encrypt_ad(&mut self, authtext: &[u8], plaintext: &[u8], out: &mut[u8]) {
        assert!(!self.overflow);
        self.cipher.encrypt(self.n, authtext, plaintext, out);
        self.n += 1;
        if self.n == 0 {
            self.overflow = true;
        }
    }

    pub fn decrypt_ad(&mut self, authtext: &[u8], ciphertext: &[u8], out: &mut[u8]) -> bool {
        assert!(!self.overflow);
        let result = self.cipher.decrypt(self.n, authtext, ciphertext, out);
        self.n += 1;
        if self.n == 0 {
            self.overflow = true;
        }
        result
    }

    pub fn encrypt(&mut self, plaintext: &[u8], out: &mut[u8]) {
        self.encrypt_ad(&[0u8;0], plaintext, out)
    }

    pub fn decrypt(&mut self, ciphertext: &[u8], out: &mut[u8]) -> bool {
        self.decrypt_ad(&[0u8;0], ciphertext, out)
    }
}

