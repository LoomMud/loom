# Efun reference

Generated from `loom_vm::efuns` (privilege class, tick cost, arity) and `loom_compiler::efuns` (parameter/return types) by `cargo test -p loom-vm efuns_reference_doc_is_up_to_date -- --ignored` (regenerate with `UPDATE_EFUNS_DOC=1`). Do not hand-edit.

| Efun | Signature | Privilege | Tick cost |
|---|---|---|---|
| `self` | `self() -> Object` | P0 | 1 |
| `this_player` | `this_player() -> Optional(Object)` | P0 | 1 |
| `load_object` | `load_object(String) -> Object` | P0 | 50 |
| `clone_object` | `clone_object(String) -> Object` | P0 | 50 |
| `find_object` | `find_object(String) -> Optional(Object)` | P0 | 5 |
| `object_name` | `object_name(Object) -> String` | P0 | 1 |
| `environment` | `environment(Optional(Object)?) -> Optional(Object)` | P0 | 1 |
| `inventory` | `inventory(Object) -> Array(Object)` | P0 | 2 |
| `move_to` | `move_to(Object) -> Void` | P0 | 2 |
| `send` | `send(Optional(Object), String) -> Void` | P0 | 2 |
| `disconnect` | `disconnect(Optional(Object)) -> Void` | P2 | 2 |
| `bind_connection` | `bind_connection(Object) -> Void` | P3 | 2 |
| `compile_object` | `compile_object(String) -> Optional(String)` | P1 | 500 |
| `upgrade_all` | `upgrade_all(String) -> Int` | P1 | 50 |
| `len` | `len(string \| [T] \| {K: V}) -> Int` | P0 | 1 |
| `split` | `split(String, String) -> Array(String)` | P0 | 5 |
| `join` | `join(Array(String), String) -> String` | P0 | 5 |
| `keys` | `keys({K: V}) -> [K]` | P0 | 2 |
| `trim` | `trim(String) -> String` | P0 | 1 |
| `call_out` | `call_out(String, Int) -> Int` | P0 | 5 |
| `remove_call_out` | `remove_call_out(Int) -> Bool` | P0 | 2 |
| `set_heartbeat` | `set_heartbeat(Bool) -> Void` | P0 | 2 |
| `random` | `random(Int) -> Int` | P0 | 1 |
| `time` | `time() -> Int` | P0 | 1 |
| `users` | `users() -> Array(Object)` | P0 | 2 |
| `lower` | `lower(String) -> String` | P0 | 1 |
| `to_int` | `to_int(String) -> Optional(Int)` | P0 | 1 |
| `destructed` | `destructed(Optional(Object)) -> Bool` | P0 | 1 |
| `destruct` | `destruct(Object) -> Void` | P2 | 5 |
| `read_file` | `read_file(String) -> Optional(String)` | P1 | 20 |
| `write_file` | `write_file(String, String) -> Bool` | P1 | 20 |
| `account_create` | `account_create(String, String) -> Int` | P3 | 50 |
| `account_login` | `account_login(String, String) -> Int` | P3 | 50 |
