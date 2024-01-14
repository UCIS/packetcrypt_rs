extern crate serde;
use hex::FromHex;
use serde::{Deserialize, Deserializer};
use serde::de::Error;

pub fn from_hex_4<'de, D>(deserializer: D) -> Result<[u8; 4], D::Error> where D: Deserializer<'de> {
    String::deserialize(deserializer).and_then(|string| {
        <[u8; 4]>::from_hex(&string).map_err(|err| Error::custom(err.to_string()))
    })
}

pub fn from_hex_32<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error> where D: Deserializer<'de> {
    String::deserialize(deserializer).and_then(|string| {
        <[u8; 32]>::from_hex(&string).map_err(|err| Error::custom(err.to_string()))
    })
}

pub fn from_hex_opt_32<'de, D>(deserializer: D) -> Result<Option<[u8; 32]>, D::Error> where D: Deserializer<'de> {
    let maybe_string: Option<&[u8]> = Deserialize::deserialize(deserializer)?;
    if let Some(ref string) = maybe_string {
        <[u8; 32]>::from_hex(&string).map(|v| Some(v)).map_err(|err| Error::custom(err.to_string()))
    } else {
        Ok(None)
    }
}

