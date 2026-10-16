//! Wire format between personality runtimes and the engine.
//!
//! Each message is a 4-byte big-endian length followed by that many bytes of
//! JSON. A connection serves one host: its first request must be `hello`.
//!
//! | Op | Parameters | Result |
//! | --- | --- | --- |
//! | `hello` | `host` | `{name, os, base}` |
//! | `section` | `name`: identity, os_info, hardware, network, agent | object or null |
//! | `list` | `name`: users, groups, software, services, interfaces | array |
//! | `reg.key_exists` | `key` | bool |
//! | `reg.key_path` | `key` | the key's spelling, or error `not_found` |
//! | `reg.query_value` | `key`, `name` | `{name, type, data}`, or error `not_found` |
//! | `reg.enum_values` | `key` | array of `{name, type, data}` |
//! | `reg.enum_subkeys` | `key` | array of names |
//! | `resolved` | none | the whole host, as `xvm-profile resolve` prints it |

use std::io::{self, Read, Write};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// Largest message either side accepts.
pub const MAX_MESSAGE: usize = 16 * 1024 * 1024;

#[derive(Debug, Serialize, Deserialize)]
pub struct Request {
    pub id: u64,
    pub op: String,
    #[serde(flatten)]
    pub params: Map<String, Value>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct ErrorBody {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Response {
    pub id: u64,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorBody>,
}

impl Response {
    pub fn ok(id: u64, result: Value) -> Self {
        Response {
            id,
            ok: true,
            result: Some(result),
            error: None,
        }
    }

    pub fn err(id: u64, code: &str, message: impl Into<String>) -> Self {
        Response {
            id,
            ok: false,
            result: None,
            error: Some(ErrorBody {
                code: code.into(),
                message: message.into(),
            }),
        }
    }
}

/// Error codes. `unsupported` means the op is not implemented; it is also a logged gap.
pub mod code {
    pub const BAD_REQUEST: &str = "bad_request";
    pub const NO_HOST: &str = "no_host";
    pub const UNKNOWN_HOST: &str = "unknown_host";
    pub const NOT_FOUND: &str = "not_found";
    pub const HAS_SUBKEYS: &str = "has_subkeys";
    pub const UNSUPPORTED: &str = "unsupported";
}

pub fn write_message<W: Write, T: Serialize>(w: &mut W, msg: &T) -> io::Result<()> {
    let body = serde_json::to_vec(msg).map_err(io::Error::other)?;
    if body.len() > MAX_MESSAGE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "message too large",
        ));
    }
    let len = u32::try_from(body.len()).map_err(io::Error::other)?;
    w.write_all(&len.to_be_bytes())?;
    w.write_all(&body)?;
    w.flush()
}

/// Read one message. `Ok(None)` means the peer closed the connection cleanly.
pub fn read_message<R: Read>(r: &mut R) -> io::Result<Option<Vec<u8>>> {
    let mut len = [0u8; 4];
    match r.read_exact(&mut len) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_MESSAGE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "message too large",
        ));
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body)?;
    Ok(Some(body))
}
