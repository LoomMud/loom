// SPDX-FileCopyrightText: 2026 Oberfield
// SPDX-License-Identifier: AGPL-3.0-only

//! `Value` <-> on-disk JSON for `save_object`/`restore_object` (spec §8.1,
//! OBI-171): the file-format half of persistence. [`crate::bcvm::
//! schema_convert`] is the other half (by-name migration of a decoded
//! value against the *current* program's schema, spec §7.3).
//!
//! **Encoding, spec r5 §7.3's "portable form":**
//! - `null`/`bool`/`int`/`string` encode as the matching JSON type.
//! - `float`: a finite value as a JSON number; non-finite (`NaN`/`inf`/
//!   `-inf`, which JSON itself cannot represent) as `{"$float": "nan" |
//!   "inf" | "-inf"}`.
//! - An array encodes as a JSON array, elementwise.
//! - A map (and a struct or enum, via [`crate::bcvm::schema_convert::
//!   struct_portable`]/[`crate::bcvm::schema_convert::enum_portable`] --
//!   both already produce a plain [`Value::map`]) encodes as `{"$map":
//!   [[k, v], ...]}`: a JSON array of key/value pairs, not a JSON object,
//!   because a Weft map key can be `int`/`bool`/`object` as well as
//!   `string` (checker rule W0264), and only a pair list round-trips a
//!   non-string key. A struct's field-name map and an enum's `$variant`/
//!   `$payload` map both happen to have only string keys, but they go
//!   through this exact same generic path -- `hydrate` (schema_convert.rs)
//!   is what gives the decoded map its struct/enum *meaning*, keyed off
//!   the target type, not anything tagged at encode time.
//! - An object reference (`Value::Object`) encodes as JSON `null`: a live
//!   id from a previous driver run cannot mean anything after a restart
//!   (same spirit as spec §5.2.2 rule 4, "function values are never
//!   saved", just not its own numbered rule).
//!
//! Decoding ([`decode_value`]) is purely structural (it has no `Ty` to
//! consult) and produces a *portable* [`Value`]: scalars/arrays/maps, with
//! no struct/enum identity at all. [`crate::bcvm::schema_convert::hydrate`]
//! is what turns that back into a real, type-conforming value (or
//! correctly reports it can't).

use serde_json::{Map as JsonMap, Number, Value as Json};

use crate::bcvm::heap::{HeapObj, MapData, Value};

/// `Value` -> the on-disk JSON form described in the module docs.
pub fn encode_value(v: &Value) -> Json {
    match v {
        Value::Null => Json::Null,
        Value::Bool(b) => Json::Bool(*b),
        Value::Int(n) => Json::Number(Number::from(*n)),
        Value::Float(f) if f.is_finite() => Number::from_f64(*f).map_or(Json::Null, Json::Number),
        Value::Float(f) => {
            let tag = if f.is_nan() {
                "nan"
            } else if *f > 0.0 {
                "inf"
            } else {
                "-inf"
            };
            let mut m = JsonMap::new();
            m.insert("$float".to_string(), Json::String(tag.to_string()));
            Json::Object(m)
        }
        // A live object reference never survives a restart; see module docs.
        Value::Object(_) => Json::Null,
        Value::Heap(h) => match &**h {
            HeapObj::Str(s) => Json::String(s.to_string()),
            HeapObj::Array(a) => Json::Array(a.items().iter().map(encode_value).collect()),
            HeapObj::Map(m) => encode_map(m),
            HeapObj::Struct(sv) => encode_value(&crate::bcvm::schema_convert::struct_portable(sv)),
            HeapObj::Enum(ev) => encode_value(&crate::bcvm::schema_convert::enum_portable(ev)),
            // Spec r5 §5.2.2 rule 4: function values are never saved.
            HeapObj::Fn(_) => Json::Null,
        },
    }
}

fn encode_map(m: &MapData) -> Json {
    let pairs = m
        .entries
        .iter()
        .map(|(k, v)| Json::Array(vec![encode_value(k), encode_value(v)]))
        .collect();
    let mut obj = JsonMap::new();
    obj.insert("$map".to_string(), Json::Array(pairs));
    Json::Object(obj)
}

/// The on-disk JSON form -> a portable `Value` (no struct/enum identity;
/// see the module docs). Never fails: anything it cannot make sense of
/// (an unrecognised tagged object, a non-finite-looking `$float` with a
/// bad tag) decodes to `Value::Null`, which [`crate::bcvm::
/// schema_convert::hydrate`] then treats as a lossy mismatch against
/// whatever type it's checked against, same as any other shape it
/// doesn't recognise -- a corrupt/foreign byte in one field never panics
/// `restore_object`.
pub fn decode_value(j: &Json) -> Value {
    match j {
        Json::Null => Value::Null,
        Json::Bool(b) => Value::Bool(*b),
        Json::Number(n) => {
            if let Some(i) = n.as_i64() {
                Value::Int(i)
            } else if let Some(f) = n.as_f64() {
                Value::Float(f)
            } else {
                Value::Null
            }
        }
        Json::String(s) => Value::str(s),
        Json::Array(items) => Value::array(items.iter().map(decode_value).collect()),
        Json::Object(obj) => {
            if let Some(Json::Array(pairs)) = obj.get("$map") {
                let mut m = MapData::default();
                for pair in pairs {
                    if let Json::Array(kv) = pair
                        && kv.len() == 2
                    {
                        m.insert(decode_value(&kv[0]), decode_value(&kv[1]));
                    }
                }
                Value::map(m)
            } else if let Some(tag) = obj.get("$float").and_then(Json::as_str) {
                match tag {
                    "nan" => Value::Float(f64::NAN),
                    "inf" => Value::Float(f64::INFINITY),
                    "-inf" => Value::Float(f64::NEG_INFINITY),
                    _ => Value::Null,
                }
            } else {
                Value::Null
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bcvm::heap::{EnumVal, StructVal};
    use std::rc::Rc;

    fn roundtrip(v: Value) -> Value {
        decode_value(&encode_value(&v))
    }

    #[test]
    fn scalars_round_trip() {
        assert!(roundtrip(Value::Null).equals(&Value::Null));
        assert!(roundtrip(Value::Bool(true)).equals(&Value::Bool(true)));
        assert!(roundtrip(Value::Int(-42)).equals(&Value::Int(-42)));
        assert!(roundtrip(Value::Float(1.5)).equals(&Value::Float(1.5)));
        assert!(roundtrip(Value::str("hi")).equals(&Value::str("hi")));
    }

    #[test]
    fn non_finite_float_round_trips() {
        assert!(matches!(roundtrip(Value::Float(f64::NAN)), Value::Float(f) if f.is_nan()));
        assert!(roundtrip(Value::Float(f64::INFINITY)).equals(&Value::Float(f64::INFINITY)));
        assert!(
            roundtrip(Value::Float(f64::NEG_INFINITY)).equals(&Value::Float(f64::NEG_INFINITY))
        );
    }

    #[test]
    fn array_round_trips() {
        let v = Value::array(vec![Value::Int(1), Value::str("x"), Value::Null]);
        assert!(roundtrip(v.clone()).equals(&v));
    }

    #[test]
    fn map_with_non_string_keys_round_trips() {
        let mut m = MapData::default();
        m.insert(Value::Int(1), Value::str("one"));
        m.insert(Value::Bool(true), Value::str("yes"));
        let v = Value::map(m);
        assert!(roundtrip(v.clone()).equals(&v));
    }

    #[test]
    fn struct_value_encodes_as_a_field_map() {
        let sv = StructVal {
            module: Rc::from("/std/item"),
            name: Rc::from("Stats"),
            fields: vec![(Rc::from("hp"), Value::Int(10))],
        };
        let encoded = encode_value(&Value::struct_val(sv));
        // Decodes to a portable map keyed by field name -- no struct
        // identity survives decode, by design (see module docs).
        let decoded = decode_value(&encoded);
        let m = decoded.as_map().expect("struct decodes to a map");
        assert!(
            m.get(&Value::str("hp"))
                .expect("hp field present")
                .equals(&Value::Int(10))
        );
    }

    #[test]
    fn enum_value_encodes_as_variant_and_payload() {
        let ev = EnumVal {
            module: Rc::from("/std/combat"),
            name: Rc::from("DamageKind"),
            variant: Rc::from("Fire"),
            payload: vec![Value::Int(5)],
        };
        let decoded = decode_value(&encode_value(&Value::enum_val(ev)));
        let m = decoded.as_map().expect("enum decodes to a map");
        assert!(
            m.get(&Value::str("$variant"))
                .expect("variant present")
                .equals(&Value::str("Fire"))
        );
        let payload = m
            .get(&Value::str("$payload"))
            .expect("payload present")
            .as_array()
            .expect("payload is an array");
        assert!(payload[0].equals(&Value::Int(5)));
    }

    #[test]
    fn object_reference_drops_to_null() {
        let id = crate::object::ObjectId {
            index: 3,
            generation: 0,
        };
        assert!(roundtrip(Value::Object(id)).equals(&Value::Null));
    }

    #[test]
    fn unrecognised_tagged_object_decodes_to_null_not_a_panic() {
        let mut obj = JsonMap::new();
        obj.insert("$something_unknown".to_string(), Json::Bool(true));
        assert!(decode_value(&Json::Object(obj)).equals(&Value::Null));
    }
}
