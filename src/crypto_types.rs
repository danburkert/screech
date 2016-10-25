use constants::*;

pub trait RandomType {
    fn fill_bytes(&mut self, out: &mut [u8]);
}

pub trait DhType {

    /// The type of the public key.
    ///
    /// The trait bounds allow the type to be used generically as a slice of bytes.
    type PrivateKey: AsRef<[u8]> + AsMut<[u8]> + Default;

    /// The type of the private key.
    ///
    /// The trait bounds allow the type to be used generically as a slice of bytes.
    type PublicKey: AsRef<[u8]> + AsMut<[u8]> + Default;

    /// Creates a new DhType with the provided private and public keys.
    fn new(private_key: Self::PrivateKey, public_key: Self::PublicKey) -> Self;

    /// Creates a new instance of the DhType with randomly generated keys.
    fn generate(rng: &mut RandomType) -> Self;

    /// Returns the name of the Diffie Hellman type.
    fn name() -> &'static str;

    /// Returns the size of the public key in bytes.
    fn pub_len() -> usize;

    /// Returns the public key.
    fn pubkey(&self) -> &Self::PublicKey;

    fn dh(&self, pubkey: &Self::PublicKey, out: &mut [u8]);
}

pub trait CipherType {

    /// The type of the cipher key.
    type Key: AsRef<[u8]> + AsMut<[u8]> + Default;

    /// The name of the cipher.
    fn name() -> &'static str;

    /// Creates a new instance of the cipher with the provided key.
    fn new(key: Self::Key) -> Self;

    fn encrypt(&self, nonce: u64, authtext: &[u8], plaintext: &[u8], out: &mut[u8]);
    fn decrypt(&self, nonce: u64, authtext: &[u8], ciphertext: &[u8], out: &mut[u8]) -> bool;
}

pub trait HashType {

    /// Creates a new instance of the hash type.
    fn new() -> Self;

    /// The name of the hash type.
    fn name() -> &'static str;

    /// The block length of the hash type in bytes.
    fn block_len() -> usize;

    /// The hash length of the hash type in bytes.
    fn hash_len() -> usize;

    /* These functions operate on internal state:
     * call reset(), then input() repeatedly, then get result() */
    fn reset(&mut self);
    fn input(&mut self, data: &[u8]);
    fn result(&mut self, out: &mut [u8]);

    /* The hmac and hkdf functions modify internal state
     * but ignore previous state, they're one-shot, static-like functions */
    fn hmac(&mut self, key: &[u8], data: &[u8], out: &mut [u8]) {
        assert!(key.len() <= Self::block_len());
        let mut ipad = [0x36u8; MAXBLOCKLEN];
        let mut opad = [0x5cu8; MAXBLOCKLEN];
        for count in 0..key.len() {
            ipad[count] ^= key[count];
            opad[count] ^= key[count];
        }
        self.reset();
        self.input(&ipad[..Self::block_len()]);
        self.input(data);
        let mut inner_output = [0u8; MAXHASHLEN];
        self.result(&mut inner_output);
        self.reset();
        self.input(&opad[..Self::block_len()]);
        self.input(&inner_output[..Self::hash_len()]);
        self.result(out);
    }

    fn hkdf(&mut self, chaining_key: &[u8], input_key_material: &[u8], out1: &mut [u8], out2: & mut[u8]) {
        let mut temp_key = [0u8; MAXHASHLEN];
        let mut in2 = [0u8; MAXHASHLEN+1];
        self.hmac(chaining_key, input_key_material, &mut temp_key);
        self.hmac(&temp_key, &[1u8], out1);
        in2[..Self::hash_len()].copy_from_slice(&out1[..Self::hash_len()]);
        in2[Self::hash_len()] = 2;
        self.hmac(&temp_key, &in2[..Self::hash_len()+1], out2);
    }
}
