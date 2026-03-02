use serde::de::{DeserializeSeed, Error as DeError, MapAccess, SeqAccess, Visitor};
use serde_json::Value;
use std::fmt;
use thiserror::Error;

const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;

#[derive(Debug, Error)]
pub enum CanonError {
    #[error("invalid JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("canonicalization failed: {0}")]
    Canonicalization(String),
    #[error("duplicate key found: {0}")]
    DuplicateKey(String),
    #[error("integer value outside interoperable range at {path}: {value}")]
    IntegerOutOfRange { path: String, value: String },
}

pub fn parse_json_strict(raw: &[u8]) -> Result<Value, CanonError> {
    let mut deserializer = serde_json::Deserializer::from_slice(raw);
    let value = StrictValueSeed.deserialize(&mut deserializer)?;
    deserializer.end()?;
    validate_numbers(&value, "$")?;
    Ok(value)
}

pub fn canonicalize_json_strict(raw: &[u8]) -> Result<Vec<u8>, CanonError> {
    let value = parse_json_strict(raw)?;
    canonicalize_value(&value)
}

pub fn canonicalize_value(value: &Value) -> Result<Vec<u8>, CanonError> {
    validate_numbers(value, "$")?;
    serde_json_canonicalizer::to_vec(value)
        .map_err(|err| CanonError::Canonicalization(err.to_string()))
}

#[allow(clippy::collapsible_if)]
fn validate_numbers(value: &Value, path: &str) -> Result<(), CanonError> {
    match value {
        Value::Number(number) => {
            if let Some(i) = number.as_i64() {
                if i.unsigned_abs() > MAX_SAFE_INTEGER as u64 {
                    return Err(CanonError::IntegerOutOfRange {
                        path: path.to_owned(),
                        value: i.to_string(),
                    });
                }
            } else if let Some(u) = number.as_u64() {
                if u > MAX_SAFE_INTEGER as u64 {
                    return Err(CanonError::IntegerOutOfRange {
                        path: path.to_owned(),
                        value: u.to_string(),
                    });
                }
            }
            Ok(())
        }
        Value::Array(values) => {
            for (index, child) in values.iter().enumerate() {
                let child_path = format!("{path}[{index}]");
                validate_numbers(child, &child_path)?;
            }
            Ok(())
        }
        Value::Object(map) => {
            for (key, child) in map {
                let child_path = format!("{path}.{key}");
                validate_numbers(child, &child_path)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

struct StrictValueSeed;

impl<'de> DeserializeSeed<'de> for StrictValueSeed {
    type Value = Value;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictValueVisitor)
    }
}

struct StrictValueVisitor;

impl<'de> Visitor<'de> for StrictValueVisitor {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("any valid JSON value")
    }

    fn visit_bool<E>(self, v: bool) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Ok(Value::Bool(v))
    }

    fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Ok(Value::Number(v.into()))
    }

    fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Ok(Value::Number(v.into()))
    }

    fn visit_f64<E>(self, v: f64) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        if !v.is_finite() {
            return Err(E::custom("non-finite numbers are not allowed"));
        }
        serde_json::Number::from_f64(v)
            .map(Value::Number)
            .ok_or_else(|| E::custom("invalid floating point value"))
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Ok(Value::String(v.to_owned()))
    }

    fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Ok(Value::String(v))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Ok(Value::Null)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Ok(Value::Null)
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(item) = seq.next_element_seed(StrictValueSeed)? {
            values.push(item);
        }
        Ok(Value::Array(values))
    }

    fn visit_map<A>(self, mut map_access: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut object = serde_json::Map::new();
        while let Some(key) = map_access.next_key::<String>()? {
            if object.contains_key(&key) {
                return Err(A::Error::custom(format!("duplicate key found: {key}")));
            }
            let value = map_access.next_value_seed(StrictValueSeed)?;
            object.insert(key, value);
        }
        Ok(Value::Object(object))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicate_keys_are_rejected() {
        let input = br#"{"a":1,"a":2}"#;
        let error = parse_json_strict(input).expect_err("duplicate keys should fail");
        match error {
            CanonError::Json(source) => {
                assert!(source.to_string().contains("duplicate key"));
            }
            _ => panic!("expected serde_json duplicate key parse error"),
        }
    }

    #[test]
    fn canonicalization_orders_keys() {
        let input = br#"{"z":1,"a":2}"#;
        let bytes = canonicalize_json_strict(input).expect("canonicalization should work");
        assert_eq!(String::from_utf8(bytes).unwrap(), r#"{"a":2,"z":1}"#);
    }

    #[test]
    fn large_integer_is_rejected() {
        let input = br#"{"n":9007199254740992}"#;
        let error = canonicalize_json_strict(input).expect_err("large integer should fail");
        match error {
            CanonError::IntegerOutOfRange { .. } => {}
            _ => panic!("expected IntegerOutOfRange"),
        }
    }

    #[test]
    fn key_order_uses_utf16_code_units() {
        let input = br#"{"\uD83D\uDE00":"grin","\uFB33":"dalet","a":"latin"}"#;
        let bytes = canonicalize_json_strict(input).expect("canonicalization should work");
        assert_eq!(
            String::from_utf8(bytes).unwrap(),
            format!(
                "{{\"a\":\"latin\",\"{}\":\"grin\",\"{}\":\"dalet\"}}",
                '\u{1F600}', '\u{FB33}'
            )
        );
    }
}
