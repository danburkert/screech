extern crate byteorder;

mod cipher;
mod cipherstate;
mod constants;
mod diffie_hellman;
mod handshakecryptoowner;
mod handshakestate;
mod hash;
mod patterns;
mod random;
mod symmetricstate;

pub use cipher::Cipher;
pub use diffie_hellman::DiffieHellman;
pub use hash::Hash;
pub use random::Random;

#[cfg(feature = "rust-crypto")]
pub use diffie_hellman::rust_crypto::*;
#[cfg(feature = "rust-crypto")]
pub use hash::rust_crypto::*;
#[cfg(feature = "rust-crypto")]
pub use cipher::rust_crypto::*;
#[cfg(feature = "rand")]
pub use random::rand::*;

#[cfg(feature = "rust-crypto")]
pub mod rust_crypto {
    pub use diffie_hellman::rust_crypto::*;
    pub use hash::rust_crypto::*;
    pub use cipher::rust_crypto::*;
}

#[cfg(feature = "rand")]
pub mod rand {
    pub use random::rand::*;
}

pub use cipherstate::CipherState;
pub use handshakecryptoowner::HandshakeCryptoOwner;
pub use handshakestate::HandshakeState;
pub use patterns::HandshakePattern;
