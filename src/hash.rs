use constants::{MAXBLOCKLEN, MAXHASHLEN};

/// A collision-resistent cryptographic hash function.
pub trait Hash {

    /// Creates a new instance of the hash function.
    fn new() -> Self;

    /// The name of the hash function.
    fn name() -> &'static str;

    /// The block length of the hash function in bytes.
    fn block_len() -> usize;

    /// The hash length of the hash function in bytes.
    fn hash_len() -> usize;

    /// Resets the internal state of the hash function.
    ///
    /// This should be called before computing a new hash digest.
    fn reset(&mut self);

    /// Adds input to the hash function. May be called multiple times before retrieving the hash
    /// digest with `result`.
    fn input(&mut self, data: &[u8]);

    /// Copies the hash result of the input data into `out`. The result will be `hash_len()` bytes.
    fn result(&mut self, out: &mut [u8]);

    /// **`HMAC-HASH(key, data)`**: Applies `HMAC` from
    /// [rfc2104](https://www.ietf.org/rfc/rfc2104.txt) using this hash function.
    ///
    /// The internal state of the hash function is modified.
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

    /// **`HKDF(chaining_key, input_key_material)`**:  Takes a `chaining_key` byte sequence of
    /// length `hash_len()`, and an `input_key_material` byte sequence with length either zero
    /// bytes, 32 bytes, or `DHLEN` bytes.  Returns two byte sequences of length `hash_len()`, as
    /// follows:
    /// * Sets `temp_key = HMAC-HASH(chaining_key, input_key_material)`.
    /// * Sets `output1 = HMAC-HASH(temp_key, byte(0x01))`.
    /// * Sets `output2 = HMAC-HASH(temp_key, output1 || byte(0x02))`.
    /// * Returns the pair `(output1, output2)`.
    ///
    /// Note that `temp_key`, `output1`, and `output2` are all `hash_len()` bytes in length.  Also
    /// note that the `HKDF()` function is simply `HKDF` from
    /// [rfc5869](https://www.ietf.org/rfc/rfc5869.txt) with the `chaining_key` as HKDF `salt`, and
    /// zero-length HKDF `info`.
    ///
    /// The internal state of the hash function is modified.
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

#[cfg(feature = "rust-crypto")]
mod rust_crypto {

    extern crate crypto;

    use std::fmt;

    use self::crypto::blake2b;
    use self::crypto::blake2s;
    use self::crypto::digest::Digest;
    use self::crypto::sha2;

    use super::Hash;

    pub struct Sha256 {
        hasher: sha2::Sha256
    }

    impl Hash for Sha256 {

        fn new() -> Sha256 {
            Sha256 {
                hasher: sha2::Sha256::new(),
            }
        }

        fn block_len() -> usize {
            64
        }

        fn hash_len() -> usize {
            32
        }

        fn name() -> &'static str {
            "SHA256"
        }

        fn reset(&mut self) {
            self.hasher = sha2::Sha256::new();
        }

        fn input(&mut self, data: &[u8]) {
            self.hasher.input(data);
        }

        fn result(&mut self, out: &mut [u8]) {
            self.hasher.result(out);
        }
    }

    impl fmt::Debug for Sha256 {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "SHA256")
        }
    }

    impl Default for Sha256 {
        fn default() -> Sha256 {
            Sha256::new()
        }
    }

    pub struct Sha512 {
        hasher: sha2::Sha512
    }

    impl Hash for Sha512 {

        fn new() -> Sha512 {
            Sha512 {
                hasher: sha2::Sha512::new(),
            }
        }

        fn name() -> &'static str {
            "SHA512"
        }

        fn block_len() -> usize {
            128
        }

        fn hash_len() -> usize {
            64
        }

        fn reset(&mut self) {
            self.hasher = sha2::Sha512::new();
        }

        fn input(&mut self, data: &[u8]) {
            self.hasher.input(data);
        }

        fn result(&mut self, out: &mut [u8]) {
            self.hasher.result(out);
        }
    }

    impl fmt::Debug for Sha512 {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "SHA512")
        }
    }

    impl Default for Sha512 {
        fn default() -> Sha512 {
            Sha512::new()
        }
    }

    pub struct Blake2b {
        hasher: blake2b::Blake2b
    }

    impl Hash for Blake2b {

        fn new() -> Blake2b {
            Blake2b {
                hasher: blake2b::Blake2b::new(64),
            }
        }

        fn name() -> &'static str {
            "BLAKE2b"
        }

        fn block_len() -> usize {
            128
        }

        fn hash_len() -> usize {
            64
        }

        fn reset(&mut self) {
            self.hasher = blake2b::Blake2b::new(64);
        }

        fn input(&mut self, data: &[u8]) {
            crypto::digest::Digest::input(&mut self.hasher, data);
        }

        fn result(&mut self, out: &mut [u8]) {
            crypto::digest::Digest::result(&mut self.hasher, out);
        }
    }

    impl fmt::Debug for Blake2b {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "BLAKE2b")
        }
    }

    impl Default for Blake2b {
        fn default() -> Blake2b {
            Blake2b::new()
        }
    }

    pub struct Blake2s {
        hasher: blake2s::Blake2s
    }

    impl Hash for Blake2s {

        fn new() -> Blake2s {
            Blake2s {
                hasher: blake2s::Blake2s::new(32),
            }
        }

        fn name() -> &'static str {
            "BLAKE2s"
        }

        fn block_len() -> usize {
            64
        }

        fn hash_len() -> usize {
            32
        }

        fn reset(&mut self) {
            self.hasher = blake2s::Blake2s::new(32);
        }

        fn input(&mut self, data: &[u8]) {
            crypto::digest::Digest::input(&mut self.hasher, data);
        }

        fn result(&mut self, out: &mut [u8]) {
            crypto::digest::Digest::result(&mut self.hasher, out);
        }
    }

    impl fmt::Debug for Blake2s {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "BLAKE2s")
        }
    }

    impl Default for Blake2s {
        fn default() -> Blake2s {
            Blake2s::new()
        }
    }

    #[cfg(test)]
    mod test {

        extern crate rustc_serialize;

        use self::rustc_serialize::hex::ToHex;

        use super::*;
        use hash::Hash;

        #[test]
        fn sha256() {
            let mut output = [0u8; 32];
            let mut hasher = Sha256::new();
            hasher.input(b"abc");
            hasher.result(&mut output);
            assert!(output.to_hex() == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        }

        #[test]
        fn hmac_sha256_rfc4231_case_3() {
            let key = [0xaa; 20];
            let data = [0xdd; 50];
            let mut output = [0u8; 32];
            let mut hasher = Sha256::new();
            hasher.hmac(&key, &data, &mut output);
            assert_eq!(output.to_hex(), "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe");
        }

        #[test]
        fn hmac_sha512_rfc4231_case_3() {
            let key = [0xaa; 20];
            let data = [0xdd; 50];
            let mut output = [0u8; 64];
            let mut hasher = Sha512::new();
            hasher.hmac(&key, &data, &mut output);
            assert!(output.to_hex() == "fa73b0089d56a284efb0f0756c890be9\
                                        b1b5dbdd8ee81a3655f83e33b2279d39\
                                        bf3e848279a722c806b485a47e67c807\
                                        b946a337bee8942674278859e13292fb");
        }

        #[test]
        fn blake2b() {
            // draft-saarinen-blake2-06
            let mut output = [0u8; 64];
            let mut hasher = Blake2b::new();
            hasher.input(b"abc");
            hasher.result(&mut output);
            assert!(output.to_hex() == "ba80a53f981c4d0d6a2797b69f12f6e9\
                                        4c212f14685ac4b74b12bb6fdbffa2d1\
                                        7d87c5392aab792dc252d5de4533cc95\
                                        18d38aa8dbf1925ab92386edd4009923");
        }

        #[test]
        fn blake2s() {
            // draft-saarinen-blake2-06
            let mut output = [0u8; 32];
            let mut hasher = Blake2s::new();
            hasher.input(b"abc");
            hasher.result(&mut output);
            assert_eq!(output.to_hex(), "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982");
        }
    }
}
