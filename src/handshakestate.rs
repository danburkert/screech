use constants::*;
use utils::*;
use crypto_types::*;
use cipherstate::*;
use symmetricstate::*;
use patterns::*;
use handshakecryptoowner::*;

#[derive(Debug)]
pub enum NoiseError {DecryptError}

pub struct HandshakeState<'a> {
    rng : &'a mut RandomType,                    /* for generating ephemerals */
    symmetricstate : SymmetricState<'a>,         /* for handshaking */
    cipherstate1: &'a mut CipherStateType,       /* for I->R transport msgs */
    cipherstate2: &'a mut CipherStateType,       /* for I<-R transport msgs */ 
    s: &'a DhType,
    e: &'a mut DhType,
    rs: &'a mut [u8],
    re: &'a mut [u8],
    has_s: bool,
    has_e: bool,
    has_rs: bool,
    has_re: bool,
    my_turn_to_send: bool,
    message_patterns: &'static [&'static [Token]],
    message_index: usize,
}

impl<'a> HandshakeState<'a> {

    pub fn new_from_owner<R: RandomType + Default,
                          D: DhType + Default,
                          C: CipherType + Default,
                          H: HashType + Default>
                         (owner: &'a mut HandshakeCryptoOwner<R, D, C, H>,
                          initiator: bool,
                          handshake_pattern: HandshakePattern,
                          prologue: &[u8],
                          optional_preshared_key: Option<&[u8]>,
                          cipherstate1: &'a mut CipherStateType,
                          cipherstate2: &'a mut CipherStateType) -> HandshakeState<'a> {

        let dhlen = owner.s.pub_len();
        HandshakeState::<'a>::new(
            &mut owner.rng,
            &mut owner.cipherstate,
            &mut owner.hasher,
            &owner.s, &mut owner.e,
            &mut owner.rs[..dhlen],
            &mut owner.re[..dhlen],
            owner.has_s, owner.has_e, owner.has_rs, owner.has_re,
            initiator, handshake_pattern, prologue, optional_preshared_key,
            cipherstate1, cipherstate2)
    }

    pub fn new(rng: &'a mut RandomType,
               cipherstate: &'a mut CipherStateType,
               hasher: &'a mut HashType,
               s : &'a DhType,
               e : &'a mut DhType,
               rs: &'a mut [u8],
               re: &'a mut [u8],
               has_s: bool,
               has_e: bool,
               has_rs: bool,
               has_re: bool,
               initiator: bool,
               handshake_pattern: HandshakePattern,
               prologue: &[u8],
               optional_preshared_key: Option<&[u8]>,
               cipherstate1: &'a mut CipherStateType,
               cipherstate2: &'a mut CipherStateType) -> HandshakeState<'a> {

        // Check that trait objects are pointing to consistent types
        // (same cipher, same DH) by looking at names
        assert_eq!(cipherstate.name(), cipherstate1.name());
        assert_eq!(cipherstate1.name(), cipherstate2.name());
        assert_eq!(s.name(), e.name());

        // Check that public keys are the correct length
        assert_eq!(s.pub_len(), e.pub_len());
        assert!(s.pub_len() <= rs.len());
        assert!(s.pub_len() <= re.len());

        let mut handshake_name = &mut [0; 128];
        let handshake_name = {
            let mut name_len = 0;
            for component in &[optional_preshared_key.map_or("Noise", |_| "NoisePSK"),
                               "_", handshake_pattern.name(),
                               "_", s.name(),
                               "_", cipherstate.name(),
                               "_", hasher.name()] {
                handshake_name[name_len..name_len + component.len()].copy_from_slice(component.as_bytes());
                name_len += component.len();
            }
            &handshake_name[..name_len]
        };

        let mut symmetricstate = SymmetricState::new(cipherstate, hasher);
        symmetricstate.initialize(handshake_name);
        symmetricstate.mix_hash(prologue);

        if let Some(preshared_key) = optional_preshared_key {
            symmetricstate.mix_preshared_key(preshared_key);
        }

        if initiator {
            for token in handshake_pattern.initiator_pre_msg_pattern() {
                match *token {
                    Token::s => {assert!(has_s); symmetricstate.mix_hash(s.pubkey());},
                    Token::e => {assert!(has_e); symmetricstate.mix_hash(e.pubkey());},
                    _ => unreachable!()
                }
            }
            for token in handshake_pattern.recipient_pre_msg_pattern() {
                match *token {
                    Token::s => {assert!(has_rs); symmetricstate.mix_hash(rs);},
                    Token::e => {assert!(has_re); symmetricstate.mix_hash(re);},
                    _ => unreachable!()
                }
            }
        } else {
            for token in handshake_pattern.initiator_pre_msg_pattern() {
                match *token {
                    Token::s => {assert!(has_rs); symmetricstate.mix_hash(rs);},
                    Token::e => {assert!(has_re); symmetricstate.mix_hash(re);},
                    _ => unreachable!()
                }
            }
            for token in handshake_pattern.recipient_pre_msg_pattern() {
                match *token {
                    Token::s => {assert!(has_s); symmetricstate.mix_hash(s.pubkey());},
                    Token::e => {assert!(has_e); symmetricstate.mix_hash(e.pubkey());},
                    _ => unreachable!()
                }
            }
        }

        HandshakeState {
            rng: rng,
            symmetricstate: symmetricstate,
            cipherstate1: cipherstate1,
            cipherstate2: cipherstate2,
            s: s,
            e: e,
            rs: rs,
            re: re,
            has_s: has_s,
            has_e: has_e,
            has_rs: has_rs,
            has_re: has_re,
            my_turn_to_send: initiator,
            message_patterns: handshake_pattern.msg_patterns(),
            message_index: 0,
        }
    }

    fn dh_len(&self) -> usize {
        self.s.pub_len()
    }

    fn dh(&mut self, local_s: bool, remote_s: bool) {
        assert!(!local_s || self.has_s);
        assert!(local_s || self.has_e);
        assert!(!remote_s || self.has_rs);
        assert!(remote_s || self.has_re);

        let dh_len = self.dh_len();
        let mut dh_out = [0u8; MAXDHLEN];
        if local_s && remote_s {
            self.s.dh(self.rs, &mut dh_out);
        }
        if local_s && !remote_s {
            self.s.dh(self.re, &mut dh_out);
        }
        if !local_s && remote_s {
            self.e.dh(self.rs, &mut dh_out);
        }
        if !local_s && !remote_s {
            self.e.dh(self.re, &mut dh_out);
        }
        self.symmetricstate.mix_key(&dh_out[..dh_len]);
    }

    pub fn write_message(&mut self,
                         payload: &[u8],
                         message: &mut [u8]) -> (usize, bool) {
        assert!(self.my_turn_to_send);
        let tokens = self.message_patterns[self.message_index];
        self.message_index += 1;

        let mut byte_index = 0;
        for token in tokens {
            match *token {
                Token::e => {
                    self.e.generate(self.rng); 
                    let pubkey = self.e.pubkey();
                    copy_memory(pubkey, &mut message[byte_index..]);
                    byte_index += self.s.pub_len();
                    self.symmetricstate.mix_hash(pubkey);
                    if self.symmetricstate.has_preshared_key() {
                        self.symmetricstate.mix_key(pubkey);
                    }
                    self.has_e = true;
                },
                Token::s => {
                    assert!(self.has_s);
                    byte_index += self.symmetricstate.encrypt_and_hash(
                                        self.s.pubkey(),
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
        let last = self.message_index >= self.message_patterns.len();
        if last {
            self.symmetricstate.split(self.cipherstate1, self.cipherstate2);
        }
        (byte_index, last)
    }

    pub fn read_message(&mut self,
                        message: &[u8],
                        payload: &mut [u8]) -> Result<(usize, bool), NoiseError> {
        assert!(!self.my_turn_to_send);
        assert!(message.len() <= MAXMSGLEN);

        let tokens = self.message_patterns[self.message_index];
        self.message_index += 1;

        let dh_len = self.dh_len();
        let mut ptr = message;
        for token in tokens {
            match *token {
                Token::e => {
                    copy_memory(&ptr[..dh_len], self.re);
                    ptr = &ptr[dh_len..];
                    self.symmetricstate.mix_hash(self.re);
                    if self.symmetricstate.has_preshared_key() {
                        self.symmetricstate.mix_key(self.re);
                    }
                    self.has_re = true;
                },
                Token::s => {
                    let data = if self.symmetricstate.has_key() {
                        let temp = &ptr[..dh_len + TAGLEN];
                        ptr = &ptr[dh_len + TAGLEN..];
                        temp
                    } else {
                        let temp = &ptr[..dh_len];
                        ptr = &ptr[dh_len..];
                        temp
                    };
                    if !self.symmetricstate.decrypt_and_hash(data, self.rs) {
                        return Err(NoiseError::DecryptError);
                    }
                    self.has_rs = true;
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
        let last = self.message_index >= self.message_patterns.len();
        if last {
            self.symmetricstate.split(self.cipherstate1, self.cipherstate2);
        }
        let payload_len = if self.symmetricstate.has_key() { ptr.len() - TAGLEN } else { ptr.len() };
        Ok((payload_len, last))
    }
}
