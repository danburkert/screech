use crypto_types::*;
use cipherstate::*;

pub struct HandshakeCryptoOwner<R: RandomType + Default, 
                          D: DhType + Default, 
                          C: CipherType + Default, 
                          H: HashType + Default> {
    pub rng: R,
    pub cipherstate: CipherState<C>,
    pub hasher: H,
    pub s: Option<D>,
    pub e: Option<D>,
    pub rs: Option<D::PublicKey>,
    pub re: Option<D::PublicKey>,
}

impl<R: RandomType + Default, 
     D: DhType + Default, 
     C: CipherType + Default, 
     H: HashType + Default> Default for HandshakeCryptoOwner<R, D, C, H> {

    fn default() -> HandshakeCryptoOwner<R, D, C, H> {
        HandshakeCryptoOwner{
            rng : Default::default(),
            cipherstate: Default::default(),
            hasher: Default::default(),
            s: None,
            e: None,
            rs: None,
            re: None,
        }
    }
}

impl<R: RandomType + Default, 
     D: DhType + Default, 
     C: CipherType + Default, 
     H: HashType + Default> HandshakeCryptoOwner<R, D, C, H> {

    pub fn new() -> HandshakeCryptoOwner<R, D, C, H> {
        Default::default()
    }

    pub fn set_s(&mut self, s: D) {
        self.s = Some(s);
    }

    pub fn set_e(&mut self, e: D) {
        self.e = Some(e);
    }

    pub fn set_rs(&mut self, rs: D::PublicKey) {
        self.rs = Some(rs);
    }

    pub fn set_re(&mut self, re: D::PublicKey) {
        self.re = Some(re);
    }
 }

