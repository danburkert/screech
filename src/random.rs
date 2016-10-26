/// A cryptographically-secure random number generator.
pub trait Random {
    fn fill_bytes(&mut self, out: &mut [u8]);
}

#[cfg(feature = "rand")]
pub mod rand {

    extern crate rand;

    use self::rand::{OsRng, Rng};
    use super::Random;

    /// A random number generator that retrieves randomness straight from the operating system.
    pub struct SystemRandom {
        rng: OsRng
    }

    impl Default for SystemRandom {
        fn default() -> SystemRandom {
            SystemRandom {
                rng: OsRng::new().unwrap()
            }
        }
    }

    impl Random for SystemRandom {
        fn fill_bytes(&mut self, out: &mut [u8]) {
            self.rng.fill_bytes(out);
        }
    }
}
