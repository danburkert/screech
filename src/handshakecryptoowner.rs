use crypto_types::*;

pub struct HandshakeCryptoOwner<R, D> where R: RandomType, D: DhType {
    pub rng: R,
    pub s: Option<D>,
    pub e: Option<D>,
    pub rs: Option<D::PublicKey>,
    pub re: Option<D::PublicKey>,
}

impl<R, D> Default for HandshakeCryptoOwner<R, D> where R: RandomType + Default, D: DhType {
    fn default() -> HandshakeCryptoOwner<R, D> {
        HandshakeCryptoOwner{
            rng : Default::default(),
            s: None,
            e: None,
            rs: None,
            re: None,
        }
    }
}

impl<R, D> HandshakeCryptoOwner<R, D> where R: RandomType + Default, D: DhType {

    pub fn new() -> HandshakeCryptoOwner<R, D> {
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

