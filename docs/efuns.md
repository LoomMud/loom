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
| `set_echo` | `set_echo(Optional(Object), Bool) -> Void` | P0 | 2 |
| `bind_connection` | `bind_connection(Object) -> Void` | P3 | 2 |
| `compile_object` | `compile_object(String) -> Optional(String)` | P1 | 500 |
| `upgrade_all` | `upgrade_all(String) -> Int` | P1 | 50 |
| `canary_update` | `canary_update(String, Int, Int, Int) -> Optional(String)` | P1 | 500 |
| `canary_status` | `canary_status(String) -> Optional(Map(String, Any))` | P1 | 5 |
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
| `account_create` | `account_create(String, String) -> Int` | P3 | 50 |
| `account_login` | `account_login(String, String) -> Int` | P3 | 50 |
| `getuid` | `getuid() -> String` | P0 | 1 |
| `geteuid` | `geteuid() -> String` | P0 | 1 |
| `effective_principal` | `effective_principal() -> String` | P0 | 1 |
| `seteuid` | `seteuid(String) -> Void` | P3 | 10 |
| `read_file` | `read_file(String) -> Optional(String)` | P0 | 20 |
| `write_file` | `write_file(String, String) -> Bool` | P1 | 50 |
| `save_object` | `save_object(String) -> Bool` | P1 | 100 |
| `restore_object` | `restore_object(String) -> Bool` | P0 | 50 |
| `unguarded` | `unguarded(String, Array(Any)?) -> Any` | P4 | 10 |
| `roles_tier` | `roles_tier(String) -> Int` | P0 | 2 |
| `roles_is_member` | `roles_is_member(String, String) -> Bool` | P0 | 2 |
| `roles_is_lead` | `roles_is_lead(String, String) -> Bool` | P0 | 2 |
| `roles_has_grant` | `roles_has_grant(String, String, String) -> Bool` | P0 | 3 |
| `roles_policy` | `roles_policy(Int) -> Map(String, Int)` | P0 | 3 |
| `roles_domains` | `roles_domains(String) -> Array(String)` | P0 | 3 |
| `roles_set_tier` | `roles_set_tier(String, Int, String) -> Int` | P3 | 50 |
| `roles_set_member` | `roles_set_member(String, String, String, String) -> Int` | P3 | 50 |
| `roles_grant` | `roles_grant(String, String, String, Optional(Int), String) -> Int` | P3 | 50 |
| `roles_revoke_grant` | `roles_revoke_grant(String, String, String, String) -> Int` | P3 | 50 |
| `roles_propose_tier` | `roles_propose_tier(String, Int, String) -> Int` | P3 | 50 |
| `roles_approve` | `roles_approve(Int) -> Int` | P3 | 50 |
| `errors` | `errors(String?) -> Array(Map(String, Any))` | P1 | 20 |
| `profile_start` | `profile_start(String) -> Void` | P1 | 10 |
| `profile_stop` | `profile_stop(Bool?) -> String` | P1 | 10 |
