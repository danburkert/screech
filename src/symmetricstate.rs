use utils::*;
use constants::*;
use crypto_types::*;
use cipherstate::*;

pub struct SymmetricState<'a, C> where C: CipherType + 'a {
    cipherstate: Option<CipherState<C>>,
    hasher: &'a mut HashType,
    h: [u8; MAXHASHLEN],
    ck: [u8; MAXHASHLEN],
    has_preshared_key: bool,
}

impl<'a, C> SymmetricState<'a, C> where C: CipherType {
    pub fn new(hasher: &'a mut HashType) -> SymmetricState<'a, C> {
        SymmetricState {
            cipherstate: None,
            hasher: hasher,
            h: [0u8; MAXHASHLEN],
            ck : [0u8; MAXHASHLEN],
            has_preshared_key: false,
        }
    }

    pub fn initialize(&mut self, handshake_name: &[u8]) {
        if handshake_name.len() <= self.hasher.hash_len() {
            self.h = [0u8; MAXHASHLEN];
            copy_memory(handshake_name, &mut self.h);
        } else {
            self.hasher.reset();
            self.hasher.input(handshake_name);
            self.hasher.result(&mut self.h);
        }
        copy_memory(&self.h, &mut self.ck);
        self.has_preshared_key = false;
    }

    pub fn mix_key(&mut self, data: &[u8]) {
        let hash_len = self.hasher.hash_len();
        let mut hkdf_output = ([0u8; MAXHASHLEN], [0u8; MAXHASHLEN]);
        self.hasher.hkdf(&self.ck[..hash_len], data, &mut hkdf_output.0, &mut hkdf_output.1);
        copy_memory(&hkdf_output.0, &mut self.ck);

        let mut key = C::Key::default();
        key.as_mut().copy_from_slice(&hkdf_output.1[..CIPHERKEYLEN]);
        self.cipherstate = Some(CipherState::new(key, 0));
    }

    pub fn mix_hash(&mut self, data: &[u8]) {
        let hash_len = self.hasher.hash_len();
        self.hasher.reset();
        self.hasher.input(&self.h[..hash_len]);
        self.hasher.input(data);
        self.hasher.result(&mut self.h);
    }

    pub fn mix_preshared_key(&mut self, psk: &[u8]) {
        let hash_len = self.hasher.hash_len();
        let mut hkdf_output = ([0u8; MAXHASHLEN], [0u8; MAXHASHLEN]);
        self.hasher.hkdf(&self.ck[..hash_len], psk, &mut hkdf_output.0, &mut hkdf_output.1);
        copy_memory(&hkdf_output.0, &mut self.ck);
        self.mix_hash(&hkdf_output.1[..hash_len]);
        self.has_preshared_key = true;
    }

    pub fn has_key(&self) -> bool {
       self.cipherstate.is_some()
    }

    pub fn has_preshared_key(&self) -> bool {
        self.has_preshared_key
    }

    pub fn encrypt_and_hash(&mut self, plaintext: &[u8], out: &mut [u8]) -> usize {
        let hash_len = self.hasher.hash_len();
        let output_len = if let Some(ref mut cipherstate) = self.cipherstate {
            cipherstate.encrypt_ad(&self.h[..hash_len], plaintext, out);
            plaintext.len() + TAGLEN
        } else {
            copy_memory(plaintext, out);
            plaintext.len()
        };
        self.mix_hash(&out[..output_len]);
        output_len
    }

    pub fn decrypt_and_hash(&mut self, data: &[u8], out: &mut [u8]) -> bool {
        let hash_len = self.hasher.hash_len();
        if let Some(ref mut cipherstate) = self.cipherstate {
            if !cipherstate.decrypt_ad(&self.h[..hash_len], data, out) {
                return false;
            }
        } else {
            copy_memory(data, out);
        }
        self.mix_hash(data);
        true
    }

    pub fn split(&mut self) -> (CipherState<C>, CipherState<C>) {
        let hash_len = self.hasher.hash_len();
        let mut hkdf_output = ([0u8; MAXHASHLEN], [0u8; MAXHASHLEN]);
        self.hasher.hkdf(&self.ck[..hash_len], &[0u8; 0],
                         &mut hkdf_output.0,
                         &mut hkdf_output.1);

        let mut key1 = C::Key::default();
        let mut key2 = C::Key::default();
        key1.as_mut().copy_from_slice(&hkdf_output.0[..CIPHERKEYLEN]);
        key2.as_mut().copy_from_slice(&hkdf_output.1[..CIPHERKEYLEN]);

        (CipherState::new(key1, 0), CipherState::new(key2, 0))
    }
}
