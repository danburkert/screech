/// Handshake Tokens
///
/// The Noise Protocol handshake patterns are specified in terms of messages comprised of these
/// tokens.
#[allow(non_camel_case_types)]
#[derive(Copy, Clone, Debug)]
pub enum Token {

    /// Ephemeral Public Key
    e,

    /// Static Public Key
    s,

    /// Diffie Hellman Ephemeral/Ephemeral
    ///
    /// a Diffie Hellman operation between the initiators ephemeral key and the recipients
    /// ephemeral key.
    ee,

    /// Diffie Hellman Ephemeral/Static
    ///
    /// a Diffie Hellman operation between the initiators ephemeral key and the recipients static
    /// key.
    es,

    /// Diffie Hellman Static/Static
    ///
    /// a Diffie Hellman operation between the initiators static key and the recipients ephemeral
    /// key.
    se,

    /// Diffie Hellman Static/Static
    ///
    /// a Diffie Hellman operation between the initiators static key and the recipients ephemeral
    /// key.
    ss,
}

/// Noise Protocol handshake patterns
///
/// ### One-way Patterns
///
/// One-way patterns are named with a single character, which indicates the status of the sender's
/// static key:
///
/// * **`N`** = **`N`**o static key for sender
/// * **`K`** = Static key for sender **`K`**nown to recipient
/// * **`X`** = Static key for sender **`X`**mitted ("transmitted") to recipient
///
/// ### Interactive Patterns
///
/// Interactive patterns are named with two characters, which indicate the status of the initator
/// and responder's static keys:
///
/// The first character refers to the initiator's static key:
///
/// * **`N`** = **`N`**o static key for initiator
/// * **`K`** = Static key for initiator **`K`**nown to responder
/// * **`X`** = Static key for initiator **`X`**mitted ("transmitted") to responder
/// * **`I`** = Static key for initiator **`I`**mmediately transmitted to responder,
///             despite reduced or absent identity hiding
///
/// The second character refers to the responder's static key:
///
/// * **`N`** = **`N`**o static key for responder
/// * **`K`** = Static key for responder **`K`**nown to responder
/// * **`X`** = Static key for responder **`X`**mitted ("transmitted") to initiator
#[derive(Copy, Clone, Debug)]
pub enum HandshakePattern {

    /* One-Way Patterns */

    /// ```noise
    /// Noise_N(rs):
    ///   <- s
    ///   ...
    ///   -> e, es
    /// ```
    N,


    /// ```noise
    /// Noise_K(s, rs):
    ///   -> s
    ///   <- s
    ///   ...
    ///   -> e, es, ss
    /// ```
    K,

    /// ```noise
    /// Noise_X(s, rs):
    ///   <- s
    ///   ...
    ///   -> e, es, s, ss
    /// ```
    X,

    /* Interactive Patterns */

    /// ```noise
    /// Noise_NN():
    ///   -> e
    ///   <- e, ee
    /// ```
    NN,

    /// ```noise
    /// Noise_NK(rs):
    ///   <- s
    ///   ...
    ///   -> e, es
    ///   <- e, ee
    /// ```
    NK,

    /// ```noise
    /// Noise_NX(rs):
    ///   -> e
    ///   <- e, ee, s, es
    /// ```
    NX,

    /// ```noise
    /// Noise_KN(s):
    ///   -> s
    ///   ...
    ///   -> e
    ///   <- e, ee, se
    /// ```
    KN,

    /// ```noise
    /// Noise_KK(s, rs):
    ///   -> s
    ///   <- s
    ///   ...
    ///   -> e, es, ss
    ///   <- e, ee, se
    KK,

    /// ```noise
    /// Noise_KX(s, rs):
    ///   -> s
    ///   ...
    ///   -> e
    ///   <- e, ee, se, s, es
    /// ```
    KX,

    /// ```noise
    /// Noise_XN(s):
    ///   -> e
    ///   <- e, ee
    ///   -> s, se
    /// ```
    XN,

    /// ```noise
    /// Noise_XK(s, rs):
    ///   <- s
    ///   ...
    ///   -> e, es
    ///   <- e, ee
    ///   -> s, se
    /// ```
    XK,

    /// ```noise
    /// Noise_XX(s, rs):
    ///   -> e
    ///   <- e, ee, s, es
    ///   -> s, se
    /// ```
    XX,

    /// ```noise
    /// Noise_IN(s):
    ///   -> e, s
    ///   <- e, ee, se
    /// ```
    IN,

    /// ```noise
    /// Noise_IK(s, rs):
    ///   <- s
    ///   ...
    ///   -> e, es, s, ss
    ///   <- e, ee, se
    /// ```
    IK,

    /// ```noise
    /// Noise_IX(s, rs):
    ///   -> e, s
    ///   <- e, ee, se, s, es
    /// ```
    IX,

    /// ```noise
    /// Noise_XXfallback(s, rs, re):
    ///   <- e
    ///   ...
    ///   -> e, ee, s, se
    ///   <- s, es
    /// ```
    XXfallback,
}

impl HandshakePattern {
    pub fn name(&self) -> &'static str {
        match *self {
            HandshakePattern::N => "N",
            HandshakePattern::K => "K",
            HandshakePattern::X => "X",
            HandshakePattern::NN => "NN",
            HandshakePattern::NK => "NK",
            HandshakePattern::NX => "NX",
            HandshakePattern::KN => "KN",
            HandshakePattern::KK => "KK",
            HandshakePattern::KX => "KX",
            HandshakePattern::XN => "XN",
            HandshakePattern::XK => "XK",
            HandshakePattern::XX => "XX",
            HandshakePattern::IN => "IN",
            HandshakePattern::IK => "IK",
            HandshakePattern::IX => "IX",
            HandshakePattern::XXfallback => "XXfallback",
        }
    }

    pub fn initiator_pre_msg_pattern(&self) -> &'static [Token] {
        const S: &'static [Token] = &[Token::s];
        match *self {
            HandshakePattern::K
                | HandshakePattern::KN
                | HandshakePattern::KK
                | HandshakePattern::KX => S,
            _ => &[],
        }
    }

    pub fn recipient_pre_msg_pattern(&self) -> &'static [Token] {
        const S: &'static [Token] = &[Token::s];
        const E: &'static [Token] = &[Token::e];
        match *self {
            HandshakePattern::N
                | HandshakePattern::K
                | HandshakePattern::X
                | HandshakePattern::NK
                | HandshakePattern::XK
                | HandshakePattern::KK
                | HandshakePattern::IK => S,
            HandshakePattern::XXfallback => E,
            _ => &[],
        }
    }

    pub fn msg_patterns(&self) -> &'static [&'static [Token]] {
        const N: &'static [&'static [Token]] = &[&[Token::e, Token::es]];
        const K: &'static [&'static [Token]] = &[&[Token::e, Token::es, Token::ss]];
        const X: &'static [&'static [Token]] = &[&[Token::e, Token::es, Token::s, Token::ss]];
        const NN: &'static [&'static [Token]] = &[&[Token::e],
                                                  &[Token::e, Token::ee]];
        const NK: &'static [&'static [Token]] = &[&[Token::e, Token::es],
                                                  &[Token::e, Token::ee]];
        const NX: &'static [&'static [Token]] = &[&[Token::e],
                                                  &[Token::e, Token::ee, Token::s, Token::se]];
        const KN: &'static [&'static [Token]] = &[&[Token::e],
                                                  &[Token::e, Token::ee, Token::es]];
        const KK: &'static [&'static [Token]] = &[&[Token::e, Token::es, Token::ss],
                                                  &[Token::e, Token::ee, Token::es]];
        const KX: &'static [&'static [Token]] = &[&[Token::e],
                                                  &[Token::e, Token::ee, Token::es, Token::s, Token::se]];
        const XN: &'static [&'static [Token]] = &[&[Token::e],
                                                  &[Token::e, Token::ee],
                                                  &[Token::s, Token::se]];
        const XK: &'static [&'static [Token]] = &[&[Token::e, Token::es],
                                                  &[Token::e, Token::ee],
                                                  &[Token::s, Token::se]];
        const XX: &'static [&'static [Token]] = &[&[Token::e],
                                                  &[Token::e, Token::ee, Token::s, Token::se],
                                                  &[Token::s, Token::se]];
        const IN: &'static [&'static [Token]] = &[&[Token::e, Token::s],
                                                  &[Token::e, Token::ee, Token::es]];
        const IK: &'static [&'static [Token]] = &[&[Token::e, Token::es, Token::s, Token::ss],
                                                  &[Token::e, Token::ee, Token::es]];
        const IX: &'static [&'static [Token]] = &[&[Token::e, Token::s],
                                                  &[Token::e, Token::ee, Token::es, Token::s, Token::se]];
        const XX_FALLBACK: &'static [&'static [Token]] = &[&[Token::e, Token::ee, Token::s, Token::se],
                                                           &[Token::s, Token::se]];

        match *self {
            HandshakePattern::N => N,
            HandshakePattern::K => K,
            HandshakePattern::X => X,
            HandshakePattern::NN => NN,
            HandshakePattern::NK => NK,
            HandshakePattern::NX => NX,
            HandshakePattern::XN => XN,
            HandshakePattern::XK => XK,
            HandshakePattern::XX => XX,
            HandshakePattern::KN => KN,
            HandshakePattern::KK => KK,
            HandshakePattern::KX => KX,
            HandshakePattern::IN => IN,
            HandshakePattern::IK => IK,
            HandshakePattern::IX => IX,
            HandshakePattern::XXfallback => XX_FALLBACK,
        }
    }
}
