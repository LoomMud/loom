// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! Minimal client-side telnet codec for the load bot (R4, OBI-40).
//!
//! Offers the alpha-relevant options (NAWS, TTYPE, CHARSET, GMCP, MSSP;
//! design spec §8.2, [OBI-26](/OBI/issues/OBI-26) "R1a") right after
//! connecting, answers the subnegotiation requests those options use, and
//! strips every IAC sequence from the inbound byte stream so line/prompt
//! matching never sees control bytes.
//!
//! Against today's Phase 0 driver (refuse-all, no options implemented) this
//! degrades to: the bot sends three `IAC WILL` offers and one unprompted
//! NAWS subnegotiation, the server answers with `IAC WONT`/`IAC DONT`
//! refusals (or nothing), and the bot otherwise behaves like a plain-text
//! client. Once R1a lands the same bot exercises the real negotiation.

const IAC: u8 = 255;
const DONT: u8 = 254;
const DO: u8 = 253;
const WONT: u8 = 252;
const WILL: u8 = 251;
const SB: u8 = 250;
const SE: u8 = 240;

const OPT_TTYPE: u8 = 24;
const OPT_NAWS: u8 = 31;
const OPT_CHARSET: u8 = 42;
const OPT_MSSP: u8 = 70;
const OPT_GMCP: u8 = 201;

const TTYPE_SEND: u8 = 1;
const TTYPE_IS: u8 = 0;
const CHARSET_REQUEST: u8 = 1;
const CHARSET_ACCEPTED: u8 = 2;

/// Bytes to write right after connecting: offer the options a real alpha
/// client would (spec §8.2). Harmless against Phase 0's refuse-all stub;
/// exercises R1a's negotiation state machine once it lands.
pub fn initial_negotiation(width: u16, height: u16) -> Vec<u8> {
    let mut out = vec![
        IAC,
        WILL,
        OPT_TTYPE, //
        IAC,
        WILL,
        OPT_NAWS, //
        IAC,
        WILL,
        OPT_CHARSET,
    ];
    // Real clients send the NAWS subnegotiation unprompted once they've
    // offered the option, rather than waiting for a DO.
    out.extend_from_slice(&[IAC, SB, OPT_NAWS]);
    out.extend_from_slice(&width.to_be_bytes());
    out.extend_from_slice(&height.to_be_bytes());
    out.extend_from_slice(&[IAC, SE]);
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Data,
    Iac,
    IacVerb(u8),
    /// In a subnegotiation body; `true` once the option byte has been read.
    Sub(bool),
    SubIac,
}

/// Strips telnet control sequences from an inbound byte stream and builds
/// the outbound responses the alpha options need. One instance per
/// connection; `feed` may be called with arbitrarily split chunks.
#[derive(Debug)]
pub struct TelnetClientCodec {
    state: State,
    sub_opt: u8,
    sub_buf: Vec<u8>,
    client_name: String,
}

impl TelnetClientCodec {
    pub fn new(client_name: impl Into<String>) -> Self {
        Self {
            state: State::Data,
            sub_opt: 0,
            sub_buf: Vec::new(),
            client_name: client_name.into(),
        }
    }

    /// Feeds raw bytes off the wire. Returns `(text, response)`: `text` is
    /// the decoded stream with every IAC sequence removed, and `response`
    /// is what the caller should write back (may be empty).
    pub fn feed(&mut self, chunk: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let mut text = Vec::with_capacity(chunk.len());
        let mut out = Vec::new();

        for &byte in chunk {
            match self.state {
                State::Data => {
                    if byte == IAC {
                        self.state = State::Iac;
                    } else {
                        text.push(byte);
                    }
                }
                State::Iac => match byte {
                    IAC => {
                        text.push(IAC);
                        self.state = State::Data;
                    }
                    DO | DONT | WILL | WONT => {
                        self.state = State::IacVerb(byte);
                    }
                    SB => {
                        self.state = State::Sub(false);
                        self.sub_buf.clear();
                    }
                    _ => self.state = State::Data,
                },
                State::IacVerb(verb) => {
                    out.extend(self.respond_to_verb(verb, byte));
                    self.state = State::Data;
                }
                State::Sub(has_opt) => {
                    if !has_opt {
                        self.sub_opt = byte;
                        self.state = State::Sub(true);
                    } else if byte == IAC {
                        self.state = State::SubIac;
                    } else {
                        self.sub_buf.push(byte);
                    }
                }
                State::SubIac => {
                    if byte == SE {
                        out.extend(self.respond_to_subnegotiation());
                        self.state = State::Data;
                    } else if byte == IAC {
                        self.sub_buf.push(IAC);
                        self.state = State::Sub(true);
                    } else {
                        // Malformed (bare IAC <not SE/IAC> inside SB): drop
                        // back into the subnegotiation body.
                        self.state = State::Sub(true);
                    }
                }
            }
        }

        (text, out)
    }

    fn respond_to_verb(&mut self, verb: u8, option: u8) -> Vec<u8> {
        match (verb, option) {
            (DO, OPT_GMCP) => vec![IAC, WILL, OPT_GMCP],
            (DO, OPT_TTYPE | OPT_NAWS | OPT_CHARSET) => Vec::new(), // already offered WILL
            (WILL, OPT_MSSP) => vec![IAC, DO, OPT_MSSP],
            (DO, opt) => vec![IAC, WONT, opt],
            (WILL, opt) => vec![IAC, DONT, opt],
            _ => Vec::new(),
        }
    }

    fn respond_to_subnegotiation(&mut self) -> Vec<u8> {
        let opt = self.sub_opt;
        let payload = std::mem::take(&mut self.sub_buf);
        match opt {
            OPT_TTYPE if payload.first() == Some(&TTYPE_SEND) => {
                let mut out = vec![IAC, SB, OPT_TTYPE, TTYPE_IS];
                out.extend_from_slice(self.client_name.to_uppercase().as_bytes());
                out.extend_from_slice(&[IAC, SE]);
                out
            }
            OPT_CHARSET if payload.first() == Some(&CHARSET_REQUEST) => {
                let mut out = vec![IAC, SB, OPT_CHARSET, CHARSET_ACCEPTED];
                out.extend_from_slice(b"UTF-8");
                out.extend_from_slice(&[IAC, SE]);
                out
            }
            _ => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_will_wont_and_passes_text_through() {
        let mut codec = TelnetClientCodec::new("bot");
        let (text, resp) = codec.feed(&[IAC, WONT, 1, b'h', b'i', b'\n']);
        assert_eq!(text, b"hi\n");
        assert!(resp.is_empty());
    }

    #[test]
    fn responds_to_ttype_send_with_is() {
        let mut codec = TelnetClientCodec::new("botaaa");
        let (text, resp) = codec.feed(&[IAC, SB, OPT_TTYPE, TTYPE_SEND, IAC, SE]);
        assert!(text.is_empty());
        assert_eq!(
            resp,
            [IAC, SB, OPT_TTYPE, TTYPE_IS]
                .iter()
                .chain(b"BOTAAA")
                .chain(&[IAC, SE])
                .copied()
                .collect::<Vec<u8>>()
        );
    }

    #[test]
    fn responds_to_charset_request_with_utf8() {
        let mut codec = TelnetClientCodec::new("bot");
        let mut req = vec![IAC, SB, OPT_CHARSET, CHARSET_REQUEST, b';' /* sep */];
        req.extend_from_slice(b"UTF-8");
        req.extend_from_slice(&[IAC, SE]);
        let (_, resp) = codec.feed(&req);
        assert_eq!(resp[..4], [IAC, SB, OPT_CHARSET, CHARSET_ACCEPTED]);
        assert_eq!(&resp[4..resp.len() - 2], b"UTF-8");
    }

    #[test]
    fn will_gmcp_from_server_is_accepted() {
        let mut codec = TelnetClientCodec::new("bot");
        let (_, resp) = codec.feed(&[IAC, DO, OPT_GMCP]);
        assert_eq!(resp, vec![IAC, WILL, OPT_GMCP]);
    }

    #[test]
    fn unknown_do_is_refused() {
        let mut codec = TelnetClientCodec::new("bot");
        let (_, resp) = codec.feed(&[IAC, DO, 99]);
        assert_eq!(resp, vec![IAC, WONT, 99]);
    }

    #[test]
    fn handles_split_iac_sequences_across_feeds() {
        let mut codec = TelnetClientCodec::new("bot");
        let (t1, r1) = codec.feed(&[b'a', IAC]);
        let (t2, r2) = codec.feed(&[WONT, 1, b'b', b'\n']);
        assert_eq!(t1, b"a");
        assert_eq!(t2, b"b\n");
        assert!(r1.is_empty() && r2.is_empty());
    }

    #[test]
    fn escaped_iac_in_subnegotiation_is_preserved() {
        let mut codec = TelnetClientCodec::new("bot");
        // SB TTYPE SEND, with an escaped IAC IAC byte pair in the middle
        // (not realistic for TTYPE, but exercises the escape path).
        let (_, resp) = codec.feed(&[IAC, SB, OPT_TTYPE, TTYPE_SEND, IAC, IAC, IAC, SE]);
        assert_eq!(resp[..4], [IAC, SB, OPT_TTYPE, TTYPE_IS]);
    }

    #[test]
    fn initial_negotiation_offers_ttype_naws_charset() {
        let bytes = initial_negotiation(80, 24);
        assert_eq!(&bytes[0..3], &[IAC, WILL, OPT_TTYPE]);
        assert_eq!(&bytes[3..6], &[IAC, WILL, OPT_NAWS]);
        assert_eq!(&bytes[6..9], &[IAC, WILL, OPT_CHARSET]);
        assert_eq!(&bytes[9..12], &[IAC, SB, OPT_NAWS]);
        assert_eq!(&bytes[bytes.len() - 2..], &[IAC, SE]);
    }
}
