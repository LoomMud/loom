// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: LicenseRef-Oberfield-Proprietary

//! End-to-end proof that real `.wf` source runs on the bytecode VM: parse →
//! resolve/check (`loom-compiler`) → codegen → verify → execute
//! (`loom_vm::bcvm::Interpreter`). This is the OBI-31 "codegen path" slice;
//! it deliberately stays self-contained (a `Host` that resolves virtual
//! calls back into the *same* module and stores program variables in a
//! flat map) rather than depending on `World`/`ObjectTable`, which is the
//! next integration step.

use std::collections::HashMap;

use loom_compiler::mudlib::{Outcome, Session};
use loom_vm::bcvm::{Host, Interpreter, Limits, MapData, RtError, Value, compile_and_verify};
use loom_vm::object::ObjectId;

/// A `Host` for a single object running one program with no inheritance:
/// virtual dispatch and "the object's own program" are the same thing, so
/// resolving `Virtual { name }` just means "call `name` in this module" —
/// exactly like an in-module `Static` call, except it goes through `Host`
/// because the *interpreter* cannot know that no override exists (that is
/// exactly what makes virtual dispatch hot-reload-friendly in the general
/// case: only the object table can say what "the current program" is).
struct SingleProgramHost<'a> {
    module: &'a loom_compiler::bytecode::Module,
    vars: HashMap<String, Value>,
}

impl Host for SingleProgramHost<'_> {
    fn self_object(&self) -> ObjectId {
        ObjectId {
            index: 0,
            generation: 0,
        }
    }

    fn call_static(
        &mut self,
        program: &str,
        _name: &str,
        _args: Vec<Value>,
    ) -> Result<Value, RtError> {
        Err(RtError::new(format!(
            "no parent program {program} (this fixture has no inherit)"
        )))
    }

    fn call_virtual(&mut self, name: &str, args: Vec<Value>) -> Result<Value, RtError> {
        // A fresh `Interpreter` over the same module and the same `Host`
        // state (reborrowed): a *new* heap-allocated call stack, not a
        // recursive Rust call re-entering the same one (see the module
        // doc comment on `vm::Host`).
        let limits = Limits::default();
        let mut ticks = 1_000_000u64;
        let mut interp = Interpreter::new(self.module, self, &limits, &mut ticks);
        interp.call(name, args)
    }

    fn call_other(
        &mut self,
        _recv: Value,
        name: &str,
        _args: Vec<Value>,
    ) -> Result<Value, RtError> {
        Err(RtError::new(format!(
            "no other objects in this fixture (called `{name}`)"
        )))
    }

    fn call_efun(&mut self, name: &str, _args: Vec<Value>) -> Result<Value, RtError> {
        Err(RtError::new(format!("efun `{name}` needs a World host")))
    }

    fn load_global(&mut self, _owner: &str, name: &str) -> Value {
        self.vars.get(name).cloned().unwrap_or(Value::Null)
    }

    fn store_global(&mut self, _owner: &str, name: &str, v: Value) {
        self.vars.insert(name.to_string(), v);
    }
}

const ROOM_WF: &str = r#"
var short_desc: string = "A room"
var exits: {string: string} = {:}

fn create() {
}

fn set_short(s: string) {
    short_desc = s
}

fn add_exit(dir: string, dest: string) {
    exits[dir] = dest
}

pub fn short() -> string {
    return short_desc
}

pub fn long() -> string {
    return "An empty room."
}

pub fn exit_dest(dir: string) -> string? {
    return exits[dir]
}

pub fn look() -> string {
    let names = keys(exits)
    return $"{short()}\n{long()}\nExits: {join(names, ", ")}\n"
}
"#;

fn compile_room() -> loom_compiler::bytecode::Module {
    let mut files = HashMap::new();
    files.insert("/std/room".to_string(), ROOM_WF.to_string());
    let mut session = Session::new(files);
    match session.compile("/std/room") {
        Outcome::Ok(checked) => {
            compile_and_verify(&checked.hir).expect("codegen + verify must succeed on valid HIR")
        }
        Outcome::Failed(report) => panic!("check failed:\n{report}"),
        Outcome::Missing(msg) => panic!("{msg}"),
    }
}

#[test]
fn real_source_runs_end_to_end_on_the_bytecode_vm() {
    let module = compile_room();
    // A real object instantiation runs each `var`'s initialiser before any
    // function body (that step lives in `World`, not this VM slice yet;
    // see the module doc comment), so seed the two declared defaults by
    // hand: `var short_desc: string = "A room"` and
    // `var exits: {string: string} = {:}`.
    let mut host = SingleProgramHost {
        module: &module,
        vars: HashMap::from([
            ("short_desc".to_string(), Value::str("A room")),
            ("exits".to_string(), Value::map(MapData::default())),
        ]),
    };
    let limits = Limits::default();
    let mut ticks = 1_000_000u64;

    {
        let mut interp = Interpreter::new(&module, &mut host, &limits, &mut ticks);
        interp.call("create", vec![]).unwrap();
    }
    {
        let mut interp = Interpreter::new(&module, &mut host, &limits, &mut ticks);
        interp
            .call(
                "add_exit",
                vec![Value::str("north"), Value::str("/domains/start/yard")],
            )
            .unwrap();
    }
    {
        let mut interp = Interpreter::new(&module, &mut host, &limits, &mut ticks);
        interp
            .call("set_short", vec![Value::str("The Great Hall")])
            .unwrap();
    }

    let out = {
        let mut interp = Interpreter::new(&module, &mut host, &limits, &mut ticks);
        interp.call("look", vec![]).unwrap()
    };
    assert_eq!(
        out.as_str().unwrap(),
        "The Great Hall\nAn empty room.\nExits: north\n"
    );

    let dest = {
        let mut interp = Interpreter::new(&module, &mut host, &limits, &mut ticks);
        interp.call("exit_dest", vec![Value::str("north")]).unwrap()
    };
    assert_eq!(dest.as_str(), Some("/domains/start/yard"));

    let missing = {
        let mut interp = Interpreter::new(&module, &mut host, &limits, &mut ticks);
        interp.call("exit_dest", vec![Value::str("south")]).unwrap()
    };
    assert!(matches!(missing, Value::Null));
}

/// The bytecode verifier is the trust boundary (spec §5.8/§5.9): prove it
/// actually runs on the encode/decode round trip too, not just the
/// freshly-codegen'd `Module` (matches the acceptance criterion pattern
/// used by `loom-compiler`'s `bytecode_fixtures` test).
#[test]
fn module_survives_an_encode_decode_round_trip_and_still_runs() {
    let module = compile_room();
    let bytes = loom_compiler::bytecode::encode(&module);
    let module = loom_compiler::bytecode::decode(&bytes).expect("decode");
    loom_compiler::verify::verify(&module).expect("verify after round trip");

    let mut host = SingleProgramHost {
        module: &module,
        vars: HashMap::from([("short_desc".to_string(), Value::str("A room"))]),
    };
    let limits = Limits::default();
    let mut ticks = 1_000u64;
    let mut interp = Interpreter::new(&module, &mut host, &limits, &mut ticks);
    let short = interp.call("short", vec![]).unwrap();
    assert_eq!(short.as_str(), Some("A room"));
}
