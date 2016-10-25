use crypto_types::*;

pub struct HandshakeCryptoOwner<R, D, H>
where R: RandomType,
      D: DhType,
      H: HashType {
    pub rng: R,
    pub hasher: H,
    pub s: Option<D>,
    pub e: Option<D>,
    pub rs: Option<D::PublicKey>,
    pub re: Option<D::PublicKey>,
}

impl<R, D, H> Default for HandshakeCryptoOwner<R, D, H>
where R: RandomType + Default,
      D: DhType,
      H: HashType + Default {
    fn default() -> HandshakeCryptoOwner<R, D, H> {
        HandshakeCryptoOwner{
            rng : Default::default(),
            hasher: Default::default(),
            s: None,
            e: None,
            rs: None,
            re: None,
        }
    }
}

impl<R, D, H> HandshakeCryptoOwner<R, D, H>
where R: RandomType + Default,
      D: DhType,
      H: HashType + Default {

    pub fn new() -> HandshakeCryptoOwner<R, D, H> {
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

