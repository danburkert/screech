use constants::*;
use utils::*;
use crypto_types::*;
use cipherstate::*;
use symmetricstate::*;
use patterns::*;
use handshakecryptoowner::*;

#[derive(Debug)]
pub enum NoiseError { DecryptError }

pub struct HandshakeState<'a, D, C> where D: DhType,
                                          C: CipherType + 'a {
    symmetricstate : SymmetricState<'a, C>,        /* for handshaking */
    s: Option<D>,
    e: D,
    rs: Option<D::PublicKey>,
    re: Option<D::PublicKey>,
    my_turn_to_send: bool,
    message_patterns: &'static [&'static [Token]],
    message_index: usize,
}

impl<'a, D, C> HandshakeState<'a, D, C>
where D: DhType + Clone + Default,
      D::PublicKey: Clone,
      C: CipherType {

    pub fn new_from_owner<R: RandomType + Default,
                          H: HashType + Default>
                         (owner: &'a mut HandshakeCryptoOwner<R, D, H>,
                          initiator: bool,
                          handshake_pattern: HandshakePattern,
                          prologue: &[u8],
                          optional_preshared_key: Option<&[u8]>) -> HandshakeState<'a, D, C> {
        HandshakeState::<'a>::new(
            &mut owner.rng,
            &mut owner.hasher,
            owner.s.clone(),
            owner.e.clone(),
            owner.rs.clone(),
            owner.re.clone(),
            initiator,
            handshake_pattern,
            prologue,
            optional_preshared_key)
    }

    pub fn new(rng: &'a mut RandomType,
               hasher: &'a mut HashType,
               s: Option<D>,
               e: Option<D>,
               rs: Option<D::PublicKey>,
               re: Option<D::PublicKey>,
               initiator: bool,
               handshake_pattern: HandshakePattern,
               prologue: &[u8],
               optional_preshared_key: Option<&[u8]>) -> HandshakeState<'a, D, C> {

        let e = e.unwrap_or_else(|| D::generate(rng));

        let mut handshake_name = &mut [0; 128];
        let handshake_name = {
            let mut name_len = 0;
            for component in &[optional_preshared_key.map_or("Noise", |_| "NoisePSK"),
                               "_", handshake_pattern.name(),
                               "_", D::name(),
                               "_", C::name(),
                               "_", hasher.name()] {
                handshake_name[name_len..name_len + component.len()].copy_from_slice(component.as_bytes());
                name_len += component.len();
            }
            &handshake_name[..name_len]
        };

        let mut symmetricstate = SymmetricState::new(hasher);
        symmetricstate.initialize(handshake_name);
        symmetricstate.mix_hash(prologue);

        if let Some(preshared_key) = optional_preshared_key {
            symmetricstate.mix_preshared_key(preshared_key);
        }

        if initiator {
            for token in handshake_pattern.initiator_pre_msg_pattern() {
                match *token {
                    Token::s => symmetricstate.mix_hash(s.as_ref().unwrap().pubkey().as_ref()),
                    Token::e => symmetricstate.mix_hash(e.pubkey().as_ref()),
                    _ => unreachable!()
                }
            }
            for token in handshake_pattern.recipient_pre_msg_pattern() {
                match *token {
                    Token::s => symmetricstate.mix_hash(rs.as_ref().unwrap().as_ref()),
                    Token::e => symmetricstate.mix_hash(re.as_ref().unwrap().as_ref()),
                    _ => unreachable!()
                }
            }
        } else {
            for token in handshake_pattern.initiator_pre_msg_pattern() {
                match *token {
                    Token::s => symmetricstate.mix_hash(rs.as_ref().unwrap().as_ref()),
                    Token::e => symmetricstate.mix_hash(re.as_ref().unwrap().as_ref()),
                    _ => unreachable!()
                }
            }
            for token in handshake_pattern.recipient_pre_msg_pattern() {
                match *token {
                    Token::s => symmetricstate.mix_hash(s.as_ref().unwrap().pubkey().as_ref()),
                    Token::e => symmetricstate.mix_hash(e.pubkey().as_ref()),
                    _ => unreachable!()
                }
            }
        }

        HandshakeState {
            symmetricstate: symmetricstate,
            s: s,
            e: e,
            rs: rs,
            re: re,
            my_turn_to_send: initiator,
            message_patterns: handshake_pattern.msg_patterns(),
            message_index: 0,
        }
    }

    fn dh(&mut self, local_s: bool, remote_s: bool) {
        let mut dh_out = [0u8; MAXDHLEN];
        let mut dh_out = &mut dh_out[..D::pub_len()];

        match (local_s, remote_s) {
            (true, true) => self.s().dh(self.rs(), &mut dh_out),
            (true, false) => self.s().dh(self.re(), &mut dh_out),
            (false, true) => self.e.dh(self.rs(), &mut dh_out),
            (false, false) => self.e.dh(self.re(), &mut dh_out),
        }

        self.symmetricstate.mix_key(dh_out);
    }

    pub fn write_message(&mut self,
                         payload: &[u8],
                         message: &mut [u8])
                         -> (usize, Option<(CipherState<C>, CipherState<C>)>) {
        assert!(self.my_turn_to_send);
        let tokens = self.message_patterns[self.message_index];
        self.message_index += 1;

        let mut byte_index = 0;
        for token in tokens {
            match *token {
                Token::e => {
                    let pubkey = self.e.pubkey().as_ref();
                    copy_memory(pubkey, &mut message[byte_index..]);
                    byte_index += pubkey.len();
                    self.symmetricstate.mix_hash(pubkey);
                    if self.symmetricstate.has_preshared_key() {
                        self.symmetricstate.mix_key(pubkey);
                    }
                },
                Token::s => {
                    let HandshakeState { ref s, ref mut symmetricstate, .. } = *self;
                    byte_index += symmetricstate.encrypt_and_hash(s.as_ref().unwrap().pubkey().as_ref(),
                                                                  &mut message[byte_index..]);
                },
                Token::ee => self.dh(false, false),
                Token::es => self.dh(false, true),
                Token::se => self.dh(true, false),
                Token::ss => self.dh(true, true),
            }
        }
        self.my_turn_to_send = false;
        byte_index += self.symmetricstate.encrypt_and_hash(payload, &mut message[byte_index..]);
        assert!(byte_index <= MAXMSGLEN);

        let cipherstates = if self.message_index >= self.message_patterns.len() {
            Some(self.symmetricstate.split())
        } else {
            None
        };
        (byte_index, cipherstates)
    }

    pub fn read_message(&mut self,
                        message: &[u8],
                        payload: &mut [u8])
                        -> Result<(usize, Option<(CipherState<C>, CipherState<C>)>), NoiseError> {
        assert!(!self.my_turn_to_send);
        assert!(message.len() <= MAXMSGLEN);

        let tokens = self.message_patterns[self.message_index];
        self.message_index += 1;

        let mut ptr = message;
        for token in tokens {
            match *token {
                Token::e => {
                    let mut re = D::PublicKey::default();
                    re.as_mut().copy_from_slice(&ptr[..D::pub_len()]);
                    ptr = &ptr[D::pub_len()..];
                    self.symmetricstate.mix_hash(re.as_ref());
                    if self.symmetricstate.has_preshared_key() {
                        self.symmetricstate.mix_key(re.as_ref());
                    }
                    self.re = Some(re);
                },
                Token::s => {
                    let data = if self.symmetricstate.has_key() {
                        let temp = &ptr[..D::pub_len() + TAGLEN];
                        ptr = &ptr[D::pub_len() + TAGLEN..];
                        temp
                    } else {
                        let temp = &ptr[..D::pub_len()];
                        ptr = &ptr[D::pub_len()..];
                        temp
                    };
                    let mut rs = D::PublicKey::default();
                    if !self.symmetricstate.decrypt_and_hash(data, rs.as_mut()) {
                        return Err(NoiseError::DecryptError);
                    }
                    self.rs = Some(rs);
                },
                Token::ee => self.dh(false, false),
                Token::es => self.dh(true, false),
                Token::se => self.dh(false, true),
                Token::ss => self.dh(true, true),
            }
        }
        if !self.symmetricstate.decrypt_and_hash(ptr, payload) {
            return Err(NoiseError::DecryptError);
        }
        self.my_turn_to_send = true;
        let cipherstates = if self.message_index >= self.message_patterns.len() {
            Some(self.symmetricstate.split())
        } else {
            None
        };
        let payload_len = if self.symmetricstate.has_key() { ptr.len() - TAGLEN } else { ptr.len() };
        Ok((payload_len, cipherstates))
    }

    fn s(&self) -> &D {
        self.s.as_ref().unwrap()
    }

    fn rs(&self) -> &D::PublicKey {
        self.rs.as_ref().unwrap()
    }

    fn re(&self) -> &D::PublicKey {
        self.re.as_ref().unwrap()
    }
}
