// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! Telnet option negotiation (RFC 1143 "Q method") and the alpha option set:
//! NAWS (window size), TTYPE (incl. the MTTS cycle), GMCP (JSON messages)
//! and MSSP (static server status). MCCP2 is explicitly out of scope here
//! (deferred to Phase 2, spec R4) and gets the same blanket refusal as any
//! other unsupported option.
//!
//! The Q method tracks two independent state machines per option: `us`
//! (do *we* perform the option -- driven by WILL/WONT) and `him` (does the
//! *peer* perform it -- driven by DO/DONT). Every state transition either
//! lands in a stable `No`/`Yes` state or a `WantX`/`WantXOpposite`
//! transitional state that never re-sends a request; that's what keeps two
//! well-behaved (or even maliciously repetitive) peers from looping
//! negotiation forever (RFC 1143 §7).

use std::collections::HashMap;

use tracing::warn;

pub const IAC: u8 = 255;
pub const DONT: u8 = 254;
pub const DO: u8 = 253;
pub const WONT: u8 = 252;
pub const WILL: u8 = 251;
pub const SB: u8 = 250;
pub const SE: u8 = 240;

pub const OPT_TTYPE: u8 = 24;
pub const OPT_NAWS: u8 = 31;
pub const OPT_MSSP: u8 = 70;
/// MCCP2 (compression): explicitly deferred to Phase 2 (spec R4). Kept as
/// a named constant (rather than a bare `86`) purely for the regression
/// test that pins the "still refused" behaviour.
#[allow(dead_code)]
pub const OPT_MCCP2: u8 = 86;
pub const OPT_GMCP: u8 = 201;

const TTYPE_IS: u8 = 0;
const TTYPE_SEND: u8 = 1;
const MSSP_VAR: u8 = 1;
const MSSP_VAL: u8 = 2;

/// A cap on the MTTS terminal-type cycle (spec §7): well-behaved clients
/// signal "no more names" by repeating their first response, but a
/// misbehaving client that never repeats must not make us `SEND` forever.
const MAX_TTYPE_ROUNDS: u8 = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum QState {
    #[default]
    No,
    Yes,
    WantNo,
    WantNoOpposite,
    WantYes,
    // Reachable only once a `request_disable` counterpart to
    // `request_enable` exists (we never disable an option we offered in
    // the alpha); kept so the state table matches RFC 1143 in full.
    #[allow(dead_code)]
    WantYesOpposite,
}

impl QState {
    /// We asked to enable this side of the option (send WILL/DO). Returns
    /// `true` if that means actually sending the byte now (`No -> WantYes`);
    /// any other starting state means a request is already outstanding (or
    /// pointless), so nothing new goes on the wire.
    fn request_enable(&mut self) -> bool {
        match *self {
            QState::No => {
                *self = QState::WantYes;
                true
            }
            QState::WantNo => {
                *self = QState::WantNoOpposite;
                false
            }
            QState::Yes | QState::WantYes | QState::WantNoOpposite | QState::WantYesOpposite => {
                false
            }
        }
    }

    /// Peer asked us to enable this side (received DO if `self` is `us`,
    /// WILL if `self` is `him`). `supported` says whether we're willing.
    /// Returns `Some(true)` to reply "yes" (WILL/DO), `Some(false)` to
    /// reply "no" (WONT/DONT), `None` to stay silent.
    fn recv_request(&mut self, supported: bool) -> Option<bool> {
        match *self {
            QState::No => {
                if supported {
                    *self = QState::Yes;
                    Some(true)
                } else {
                    Some(false)
                }
            }
            QState::Yes => None,
            QState::WantNo => {
                // Answered DO/WILL to our DONT/WONT: a negotiation error
                // (RFC 1143 §7). Accept the peer's answer rather than loop.
                *self = QState::No;
                None
            }
            QState::WantNoOpposite => {
                *self = QState::Yes;
                None
            }
            QState::WantYes => {
                *self = QState::Yes;
                None
            }
            QState::WantYesOpposite => {
                *self = QState::WantNo;
                Some(false)
            }
        }
    }

    /// Peer asked us to disable this side (received DONT/WONT).
    fn recv_refuse(&mut self) -> Option<bool> {
        match *self {
            QState::No => None,
            QState::Yes => {
                *self = QState::No;
                Some(false)
            }
            QState::WantNo => {
                *self = QState::No;
                None
            }
            QState::WantNoOpposite => {
                *self = QState::WantYes;
                Some(true)
            }
            QState::WantYes => {
                *self = QState::No;
                None
            }
            QState::WantYesOpposite => {
                *self = QState::No;
                None
            }
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct OptionNego {
    us: QState,
    him: QState,
}

/// Structured events the codec produces from telnet subnegotiations. These
/// carry no `ConnId`; `run_connection` (lib.rs) attaches it before handing
/// them to the world as `NetEvent`s.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TelnetEvent {
    WindowSize(u16, u16),
    TerminalType(String),
    Gmcp(GmcpMessage),
}

/// GMCP payloads the world cares about get a structured variant
/// (`Core.Hello`, `Core.Supports.*`); everything else (including `Char.*`,
/// which the driver gives no semantics of its own) is the generic
/// `Package` variant so unknown/future packages don't get silently
/// dropped, without needing a seam change every time a new package shows
/// up. This is the cross-seam surface named in OBI-26's acceptance
/// criteria (CTO decision recorded on the owning issue before merge).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GmcpMessage {
    CoreHello {
        client: String,
        version: String,
    },
    CoreSupportsSet(Vec<String>),
    CoreSupportsAdd(Vec<String>),
    CoreSupportsRemove(Vec<String>),
    /// Any package/message other than `Core.Hello`/`Core.Supports.*`
    /// (`Char.*` included). `payload` is `Value::Null` for a GMCP message
    /// with no body (that's valid GMCP, not an error); malformed JSON is
    /// never delivered here at all -- `parse_gmcp` drops the whole frame.
    Package {
        module: String,
        payload: serde_json::Value,
    },
}

/// Parses one GMCP frame. Returns `None` if the frame isn't valid UTF-8 or
/// its JSON payload doesn't parse -- the caller drops the frame entirely
/// rather than deliver a `Package { payload: Value::Null, .. }`, since
/// `Null` is reserved for "module with no payload" (valid GMCP).
fn parse_gmcp(body: &[u8]) -> Option<GmcpMessage> {
    let text = std::str::from_utf8(body).ok()?;
    let (package_message, payload_str) = match text.find(char::is_whitespace) {
        Some(idx) => (&text[..idx], text[idx..].trim_start()),
        None => (text, ""),
    };
    let payload: serde_json::Value = if payload_str.is_empty() {
        serde_json::Value::Null
    } else {
        match serde_json::from_str(payload_str) {
            Ok(v) => v,
            Err(err) => {
                warn!(package_message, %err, "malformed GMCP payload, dropping frame");
                return None;
            }
        }
    };

    Some(match package_message {
        "Core.Hello" => {
            let client = payload
                .get("client")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            let version = payload
                .get("version")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            GmcpMessage::CoreHello { client, version }
        }
        "Core.Supports.Set" => GmcpMessage::CoreSupportsSet(string_array(&payload)),
        "Core.Supports.Add" => GmcpMessage::CoreSupportsAdd(string_array(&payload)),
        "Core.Supports.Remove" => GmcpMessage::CoreSupportsRemove(string_array(&payload)),
        other => GmcpMessage::Package {
            module: other.to_string(),
            payload,
        },
    })
}

fn string_array(value: &serde_json::Value) -> Vec<String> {
    value
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// Encodes an outbound GMCP message (`IAC SB GMCP <pkg.msg> <json> IAC SE`),
/// escaping any stray `IAC` bytes in the JSON body (RFC 855 subnegotiation
/// framing; JSON text won't normally contain byte 255, but a string literal
/// could round-trip arbitrary bytes so we escape defensively).
pub fn encode_gmcp(package_message: &str, payload: &serde_json::Value) -> Vec<u8> {
    let json = if payload.is_null() {
        String::new()
    } else {
        serde_json::to_string(payload).unwrap_or_default()
    };
    let mut body = Vec::with_capacity(package_message.len() + json.len() + 1);
    body.extend_from_slice(package_message.as_bytes());
    if !json.is_empty() {
        body.push(b' ');
        body.extend_from_slice(json.as_bytes());
    }

    let mut out = Vec::with_capacity(body.len() + 6);
    out.push(IAC);
    out.push(SB);
    out.push(OPT_GMCP);
    for &b in &body {
        out.push(b);
        if b == IAC {
            out.push(IAC);
        }
    }
    out.push(IAC);
    out.push(SE);
    out
}

fn ttype_send() -> Vec<u8> {
    vec![IAC, SB, OPT_TTYPE, TTYPE_SEND, IAC, SE]
}

fn mssp_frame(fields: &[(String, String)]) -> Vec<u8> {
    let mut out = vec![IAC, SB, OPT_MSSP];
    for (name, value) in fields {
        out.push(MSSP_VAR);
        out.extend_from_slice(name.as_bytes());
        out.push(MSSP_VAL);
        out.extend_from_slice(value.as_bytes());
    }
    out.push(IAC);
    out.push(SE);
    out
}

#[derive(Debug, Default)]
struct TtypeCycle {
    first: Option<String>,
    rounds: u8,
}

/// Per-connection telnet option negotiation state and subnegotiation
/// dispatch. Owned by `TelnetCodec` (lib.rs), one per connection.
#[derive(Debug, Default)]
pub struct TelnetOptionTable {
    options: HashMap<u8, OptionNego>,
    ttype: TtypeCycle,
    mssp_fields: Vec<(String, String)>,
    /// The client's advertised `Core.Supports` package set (spec §7). Kept
    /// here rather than in the VM per the CTO decision on OBI-26: it's
    /// connection/protocol bookkeeping, not world state.
    supports: std::collections::HashSet<String>,
}

/// Whether we (the server) are willing to enable our side of an option
/// when the peer asks (`DO <option>`).
fn us_supported(option: u8) -> bool {
    matches!(option, OPT_GMCP | OPT_MSSP)
}

/// Whether we want the peer to enable their side of an option when they
/// offer it unprompted (`WILL <option>`).
fn him_supported(option: u8) -> bool {
    matches!(option, OPT_NAWS | OPT_TTYPE | OPT_GMCP)
}

impl TelnetOptionTable {
    pub fn new(mssp_fields: Vec<(String, String)>) -> Self {
        Self {
            options: HashMap::new(),
            ttype: TtypeCycle::default(),
            mssp_fields,
            supports: std::collections::HashSet::new(),
        }
    }

    /// The client's current `Core.Supports` package set, as tracked from
    /// `Core.Supports.Set/Add/Remove` frames. Connection-local bookkeeping
    /// (spec §7); the world never sees this directly. Not consumed by any
    /// caller yet in the alpha (no GMCP-aware world hook exists until the
    /// `NetEvent::Gmcp` apply lands) -- kept `pub` and tested directly so
    /// the tracking itself is proven now.
    #[allow(dead_code)]
    pub fn supports(&self) -> &std::collections::HashSet<String> {
        &self.supports
    }

    fn entry(&mut self, option: u8) -> &mut OptionNego {
        self.options.entry(option).or_default()
    }

    /// Whether *we* are currently enabled to speak `option` to the peer
    /// (i.e. `us == Yes`). Used to gate outbound GMCP on having actually
    /// negotiated it, rather than trusting the caller.
    pub fn is_enabled_us(&self, option: u8) -> bool {
        self.options.get(&option).map(|n| n.us) == Some(QState::Yes)
    }

    /// Startup negotiation the server always offers: ask the client to do
    /// NAWS/TTYPE, offer to do GMCP/MSSP ourselves.
    pub fn start(&mut self) -> Vec<u8> {
        let mut out = Vec::new();
        if self.entry(OPT_NAWS).him.request_enable() {
            out.extend_from_slice(&[IAC, DO, OPT_NAWS]);
        }
        if self.entry(OPT_TTYPE).him.request_enable() {
            out.extend_from_slice(&[IAC, DO, OPT_TTYPE]);
        }
        if self.entry(OPT_GMCP).us.request_enable() {
            out.extend_from_slice(&[IAC, WILL, OPT_GMCP]);
        }
        if self.entry(OPT_MSSP).us.request_enable() {
            out.extend_from_slice(&[IAC, WILL, OPT_MSSP]);
        }
        out
    }

    /// Handles one `IAC <verb> <option>`. Returns bytes to send in reply
    /// (may be empty) plus any side effects the transition triggers (e.g.
    /// `TTYPE SEND` once the client agrees to do TTYPE).
    pub fn handle_verb(&mut self, verb: u8, option: u8) -> Vec<u8> {
        let mut out = Vec::new();
        match verb {
            WILL => {
                let nego = self.entry(option);
                let was_yes = nego.him == QState::Yes;
                match nego.him.recv_request(him_supported(option)) {
                    Some(true) => out.extend_from_slice(&[IAC, DO, option]),
                    Some(false) => out.extend_from_slice(&[IAC, DONT, option]),
                    None => {}
                }
                let now_yes = self.options.get(&option).map(|n| n.him) == Some(QState::Yes);
                if !was_yes && now_yes && option == OPT_TTYPE {
                    out.extend_from_slice(&ttype_send());
                }
            }
            WONT => {
                match self.entry(option).him.recv_refuse() {
                    Some(true) => {
                        // recv_refuse only returns Some(true) transitioning
                        // WantNoOpposite -> WantYes, i.e. we still want it.
                        out.extend_from_slice(&[IAC, DO, option]);
                    }
                    Some(false) => {
                        // Yes -> No: RFC 1143 requires acknowledging a
                        // disable, or a Q-method peer is stuck in WANTNO
                        // forever waiting for our answer.
                        out.extend_from_slice(&[IAC, DONT, option]);
                    }
                    None => {}
                }
            }
            DO => {
                let was_yes = self.entry(option).us == QState::Yes;
                match self.entry(option).us.recv_request(us_supported(option)) {
                    Some(true) => out.extend_from_slice(&[IAC, WILL, option]),
                    Some(false) => out.extend_from_slice(&[IAC, WONT, option]),
                    None => {}
                }
                let now_yes = self.options.get(&option).map(|n| n.us) == Some(QState::Yes);
                if !was_yes && now_yes && option == OPT_MSSP {
                    out.extend_from_slice(&mssp_frame(&self.mssp_fields));
                }
            }
            DONT => match self.entry(option).us.recv_refuse() {
                Some(true) => {
                    out.extend_from_slice(&[IAC, WILL, option]);
                }
                Some(false) => {
                    out.extend_from_slice(&[IAC, WONT, option]);
                }
                None => {}
            },
            _ => unreachable!("caller only dispatches DO/DONT/WILL/WONT"),
        }
        out
    }

    /// Handles one complete subnegotiation body (`sub_buf[0]` is the option
    /// byte, the rest is the payload). Returns any bytes to send back plus
    /// a structured event for the world, if the option produced one.
    ///
    /// Deliberately lenient: this dispatches on the option byte alone, not
    /// on whether that option's negotiation ever reached `Yes` (e.g. a
    /// client that sends `IAC SB GMCP ... IAC SE` without having completed
    /// `WILL`/`DO GMCP` first still gets parsed). A client sending data for
    /// an option it never agreed to enable is a protocol quirk, not an
    /// attack surface -- the frame is well-formed and size-capped either
    /// way -- so we take the data rather than add a second state check on
    /// every subnegotiation for no real gain.
    pub fn handle_subnegotiation(&mut self, sub_buf: &[u8]) -> (Vec<u8>, Option<TelnetEvent>) {
        let Some((&option, body)) = sub_buf.split_first() else {
            return (Vec::new(), None);
        };

        match option {
            OPT_NAWS => {
                if body.len() < 4 {
                    return (Vec::new(), None);
                }
                let width = u16::from_be_bytes([body[0], body[1]]);
                let height = u16::from_be_bytes([body[2], body[3]]);
                (Vec::new(), Some(TelnetEvent::WindowSize(width, height)))
            }
            OPT_TTYPE => {
                let Some((&TTYPE_IS, name)) = body.split_first() else {
                    return (Vec::new(), None);
                };
                let name = String::from_utf8_lossy(name).into_owned();

                let is_repeat = self.ttype.first.as_deref() == Some(name.as_str());
                if self.ttype.first.is_none() {
                    self.ttype.first = Some(name.clone());
                }
                self.ttype.rounds = self.ttype.rounds.saturating_add(1);

                let cycle_done =
                    (is_repeat && self.ttype.rounds > 1) || self.ttype.rounds >= MAX_TTYPE_ROUNDS;
                let out = if cycle_done { Vec::new() } else { ttype_send() };
                (out, Some(TelnetEvent::TerminalType(name)))
            }
            OPT_GMCP => match parse_gmcp(body) {
                Some(msg) => {
                    match &msg {
                        GmcpMessage::CoreSupportsSet(pkgs) => {
                            self.supports = pkgs.iter().cloned().collect();
                        }
                        GmcpMessage::CoreSupportsAdd(pkgs) => {
                            self.supports.extend(pkgs.iter().cloned());
                        }
                        GmcpMessage::CoreSupportsRemove(pkgs) => {
                            for pkg in pkgs {
                                self.supports.remove(pkg);
                            }
                        }
                        _ => {}
                    }
                    (Vec::new(), Some(TelnetEvent::Gmcp(msg)))
                }
                None => (Vec::new(), None),
            },
            _ => (Vec::new(), None),
        }
    }
}
