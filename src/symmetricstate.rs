use Cipher;
use Hash;
use constants::*;
use cipherstate::*;

pub struct SymmetricState<C, H> where C: Cipher, H: Hash {
    cipherstate: Option<CipherState<C>>,
    hasher: H,
    h: [u8; MAXHASHLEN],
    ck: [u8; MAXHASHLEN],
    has_preshared_key: bool,
}

impl<C, H> SymmetricState<C, H> where C: Cipher, H: Hash {
    pub fn new() -> SymmetricState<C, H> {
        SymmetricState {
            cipherstate: None,
            hasher: H::new(),
            h: [0u8; MAXHASHLEN],
            ck: [0u8; MAXHASHLEN],
            has_preshared_key: false,
        }
    }

    pub fn initialize(&mut self, handshake_name: &[u8]) {
        if handshake_name.len() <= H::hash_len() {
            self.h = [0u8; MAXHASHLEN];
            self.h[..handshake_name.len()].copy_from_slice(handshake_name);
        } else {
            self.hasher.reset();
            self.hasher.input(handshake_name);
            self.hasher.result(&mut self.h);
        }
        self.ck.copy_from_slice(&self.h);
        self.has_preshared_key = false;
    }

    pub fn mix_key(&mut self, data: &[u8]) {
        let mut hkdf_output = ([0u8; MAXHASHLEN], [0u8; MAXHASHLEN]);
        self.hasher.hkdf(&self.ck[..H::hash_len()], data, &mut hkdf_output.0, &mut hkdf_output.1);
        self.ck.copy_from_slice(&hkdf_output.0);

        let mut key = [0; CIPHERKEYLEN];
        key.as_mut().copy_from_slice(&hkdf_output.1[..CIPHERKEYLEN]);
        self.cipherstate = Some(CipherState::new(key, 0));
    }

    pub fn mix_hash(&mut self, data: &[u8]) {
        self.hasher.reset();
        self.hasher.input(&self.h[..H::hash_len()]);
        self.hasher.input(data);
        self.hasher.result(&mut self.h);
    }

    pub fn mix_preshared_key(&mut self, psk: &[u8]) {
        let mut hkdf_output = ([0u8; MAXHASHLEN], [0u8; MAXHASHLEN]);
        self.hasher.hkdf(&self.ck[..H::hash_len()], psk, &mut hkdf_output.0, &mut hkdf_output.1);
        self.ck.copy_from_slice(&hkdf_output.0);
        self.mix_hash(&hkdf_output.1[..H::hash_len()]);
        self.has_preshared_key = true;
    }

    pub fn has_key(&self) -> bool {
       self.cipherstate.is_some()
    }

    pub fn has_preshared_key(&self) -> bool {
        self.has_preshared_key
    }

    pub fn encrypt_and_hash(&mut self, plaintext: &[u8], out: &mut [u8]) -> usize {
        let output_len = if let Some(ref mut cipherstate) = self.cipherstate {
            cipherstate.encrypt_ad(&self.h[..H::hash_len()], plaintext, out);
            plaintext.len() + TAGLEN
        } else {
            out[..plaintext.len()].copy_from_slice(plaintext);
            plaintext.len()
        };
        self.mix_hash(&out[..output_len]);
        output_len
    }

    pub fn decrypt_and_hash(&mut self, data: &[u8], out: &mut [u8]) -> bool {
        if let Some(ref mut cipherstate) = self.cipherstate {
            if !cipherstate.decrypt_ad(&self.h[..H::hash_len()], data, out) {
                return false;
            }
        } else {
            out[..data.len()].copy_from_slice(data);
        }
        self.mix_hash(data);
        true
    }

    pub fn split(&mut self) -> (CipherState<C>, CipherState<C>) {
        let mut hkdf_output = ([0u8; MAXHASHLEN], [0u8; MAXHASHLEN]);
        self.hasher.hkdf(&self.ck[..H::hash_len()], &[0u8; 0],
                         &mut hkdf_output.0,
                         &mut hkdf_output.1);

        let mut key1 = [0; CIPHERKEYLEN];
        let mut key2 = [0; CIPHERKEYLEN];
        key1.as_mut().copy_from_slice(&hkdf_output.0[..CIPHERKEYLEN]);
        key2.as_mut().copy_from_slice(&hkdf_output.1[..CIPHERKEYLEN]);

        (CipherState::new(key1, 0), CipherState::new(key2, 0))
    }
}
