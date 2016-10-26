use random::Random;

/// A Diffie-Hellman key exchange function.
pub trait DiffieHellman {

    /// The type of the public key.
    ///
    /// The trait bounds allow the type to be used generically as a slice of bytes.
    type PrivateKey: AsRef<[u8]> + AsMut<[u8]> + Default;

    /// The type of the private key.
    ///
    /// The trait bounds allow the type to be used generically as a slice of bytes.
    type PublicKey: AsRef<[u8]> + AsMut<[u8]> + Default;

    /// Creates a new DiffieHellman function with the provided private and public keys.
    fn new(private_key: Self::PrivateKey, public_key: Self::PublicKey) -> Self;

    /// Creates a new instance of the DiffieHellman function with randomly generated keys.
    fn generate(rng: &mut Random) -> Self;

    /// Returns the name of the Diffie Hellman type.
    fn name() -> &'static str;

    /// Returns the size of the public key in bytes.
    fn pub_len() -> usize;

    /// Returns the public key.
    fn public_key(&self) -> &Self::PublicKey;

    /// Performs a DH calculation between the private key in this Diffie-Helman instance and
    /// `public_key` and returns an output sequence of bytes of length `DHLEN`.
    ///
    /// If the function detects an invalid `public_key`, the output may be all zeros or any other
    /// value that doesn't leak information about the private key.
    fn dh(&self, public_key: &Self::PublicKey, out: &mut [u8]);
}

#[cfg(feature = "rust-crypto")]
pub mod rust_crypto {

    extern crate crypto;

    use std::fmt;

    use self::crypto::curve25519::{curve25519, curve25519_base};

    use super::DiffieHellman;
    use random::Random;

    #[derive(Clone)]
    pub struct X25519 {
        private_key: [u8; 32],
        public_key: [u8; 32],
    }

    impl DiffieHellman for X25519 {
        type PrivateKey = [u8; 32];
        type PublicKey = [u8; 32];

        fn new(private_key: [u8; 32], public_key: [u8; 32]) -> X25519 {
            X25519 {
                private_key: private_key,
                public_key: public_key,
            }
        }

        fn generate(rng: &mut Random) -> X25519 {
            let mut private_key = [0; 32];
            rng.fill_bytes(&mut private_key);
            private_key[0] &= 248;
            private_key[31] &= 127;
            private_key[31] |= 64;
            let public_key = curve25519_base(&private_key);
            X25519 {
                private_key: private_key,
                public_key: public_key,
            }
        }

        fn name() -> &'static str {
            "25519"
        }

        fn pub_len() -> usize {
            32
        }

        fn public_key(&self) -> &[u8; 32] {
            &self.public_key
        }

        fn dh(&self, public_key: &[u8; 32], out: &mut [u8]) {
            let result = curve25519(&self.private_key, public_key);
            out[..result.len()].copy_from_slice(&result);
        }
    }

    impl fmt::Debug for X25519 {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "X25519")
        }
    }

    #[cfg(test)]
    mod test {

        extern crate rustc_serialize;

        use self::rustc_serialize::hex::{FromHex, ToHex};

        use diffie_hellman::DiffieHellman;
        use super::X25519;

        #[test]
        fn x25519() {
            // - draft-curves-10
            let mut privkey = [0; 32];
            privkey.copy_from_slice(&"a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4".from_hex().unwrap());
            let mut pubkey = [0u8; 32];
            pubkey.copy_from_slice(&"e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c".from_hex().unwrap());
            let keypair = X25519::new(privkey, pubkey);

            let mut output = [0u8; 32];
            keypair.dh(&pubkey, &mut output);
            assert_eq!(output.to_hex(), "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");
        }
    }
}
