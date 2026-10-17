//! Reading X.509 certificates from DER.
//!
//! Written from ITU-T X.690 (DER) and RFC 5280 (certificate profile).
//! Reads only what the census functions need: version, serial number,
//! issuer, validity and subject. Everything else is kept as raw bytes.

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerError(pub String);

impl fmt::Display for DerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "bad certificate: {}", self.0)
    }
}

impl std::error::Error for DerError {}

fn bad<T>(msg: impl Into<String>) -> Result<T, DerError> {
    Err(DerError(msg.into()))
}

const INTEGER: u8 = 0x02;
const OID: u8 = 0x06;
const UTF8_STRING: u8 = 0x0c;
const PRINTABLE_STRING: u8 = 0x13;
const T61_STRING: u8 = 0x14;
const IA5_STRING: u8 = 0x16;
const UTC_TIME: u8 = 0x17;
const GENERALIZED_TIME: u8 = 0x18;
const UNIVERSAL_STRING: u8 = 0x1c;
const BMP_STRING: u8 = 0x1e;
const SEQUENCE: u8 = 0x30;
const SET: u8 = 0x31;
const VERSION_TAG: u8 = 0xa0;

/// One TLV: its tag, its contents and the whole encoding.
#[derive(Debug, Clone, Copy)]
struct Tlv<'a> {
    tag: u8,
    content: &'a [u8],
    whole: &'a [u8],
}

struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Reader { rest: data }
    }

    fn is_empty(&self) -> bool {
        self.rest.is_empty()
    }

    fn peek_tag(&self) -> Option<u8> {
        self.rest.first().copied()
    }

    fn next(&mut self) -> Result<Tlv<'a>, DerError> {
        let data = self.rest;
        let (&tag, after) = data.split_first().ok_or(DerError("truncated tag".into()))?;
        if tag & 0x1f == 0x1f {
            return bad("multi-byte tags are not used in certificates");
        }
        let (&first, after) = after
            .split_first()
            .ok_or(DerError("truncated length".into()))?;
        let (len, after) = if first < 0x80 {
            (first as usize, after)
        } else {
            let n = (first & 0x7f) as usize;
            if n == 0 || n > 4 || after.len() < n {
                return bad("bad length");
            }
            let len = after[..n]
                .iter()
                .fold(0usize, |acc, &b| (acc << 8) | b as usize);
            (len, &after[n..])
        };
        if after.len() < len {
            return bad("content runs past the end");
        }
        let header = data.len() - after.len();
        self.rest = &after[len..];
        Ok(Tlv {
            tag,
            content: &after[..len],
            whole: &data[..header + len],
        })
    }

    fn expect(&mut self, tag: u8, what: &str) -> Result<Tlv<'a>, DerError> {
        let tlv = self.next()?;
        if tlv.tag != tag {
            return bad(format!("expected {what}, found tag 0x{:02x}", tlv.tag));
        }
        Ok(tlv)
    }
}

/// One attribute of a distinguished name, such as CN=DigiCert Inc.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attribute {
    /// Dotted OID, such as "2.5.4.3" for commonName.
    pub oid: String,
    pub value: String,
}

/// A distinguished name: its relative names in order, and its encoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Name {
    pub attributes: Vec<Attribute>,
    pub der: Vec<u8>,
}

impl Name {
    pub fn first(&self, oid: &str) -> Option<&str> {
        self.attributes
            .iter()
            .find(|a| a.oid == oid)
            .map(|a| a.value.as_str())
    }
}

pub const OID_COMMON_NAME: &str = "2.5.4.3";
pub const OID_ORGANIZATIONAL_UNIT: &str = "2.5.4.11";
pub const OID_ORGANIZATION: &str = "2.5.4.10";
pub const OID_EMAIL: &str = "1.2.840.113549.1.9.1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Certificate {
    pub der: Vec<u8>,
    /// 0 for v1, 1 for v2, 2 for v3, as stored.
    pub version: u32,
    /// Big-endian, as encoded (leading zero kept).
    pub serial: Vec<u8>,
    pub issuer: Name,
    /// Seconds since the Unix epoch.
    pub not_before: i64,
    pub not_after: i64,
    pub subject: Name,
}

impl Certificate {
    pub fn parse(der: &[u8]) -> Result<Certificate, DerError> {
        let mut outer = Reader::new(der);
        let cert = outer.expect(SEQUENCE, "Certificate")?;
        if !outer.is_empty() {
            return bad("data after the certificate");
        }
        let mut cert = Reader::new(cert.content);
        let tbs = cert.expect(SEQUENCE, "TBSCertificate")?;
        let mut tbs = Reader::new(tbs.content);

        let version = if tbs.peek_tag() == Some(VERSION_TAG) {
            let explicit = tbs.next()?;
            let int = Reader::new(explicit.content).expect(INTEGER, "version")?;
            int.content
                .iter()
                .fold(0u32, |acc, &b| (acc << 8) | b as u32)
        } else {
            0
        };
        let serial = tbs.expect(INTEGER, "serialNumber")?.content.to_vec();
        tbs.expect(SEQUENCE, "signature")?;
        let issuer = name(tbs.expect(SEQUENCE, "issuer")?)?;
        let validity = tbs.expect(SEQUENCE, "validity")?;
        let mut validity = Reader::new(validity.content);
        let not_before = time(validity.next()?)?;
        let not_after = time(validity.next()?)?;
        let subject = name(tbs.expect(SEQUENCE, "subject")?)?;
        Ok(Certificate {
            der: der.to_vec(),
            version,
            serial,
            issuer,
            not_before,
            not_after,
            subject,
        })
    }
}

fn name(seq: Tlv<'_>) -> Result<Name, DerError> {
    let mut attributes = Vec::new();
    let mut rdns = Reader::new(seq.content);
    while !rdns.is_empty() {
        let set = rdns.expect(SET, "RelativeDistinguishedName")?;
        let mut atvs = Reader::new(set.content);
        while !atvs.is_empty() {
            let atv = atvs.expect(SEQUENCE, "AttributeTypeAndValue")?;
            let mut atv = Reader::new(atv.content);
            let oid = oid(atv.expect(OID, "attribute type")?.content)?;
            let value = string(atv.next()?)?;
            attributes.push(Attribute { oid, value });
        }
    }
    Ok(Name {
        attributes,
        der: seq.whole.to_vec(),
    })
}

fn oid(bytes: &[u8]) -> Result<String, DerError> {
    let mut arcs = Vec::new();
    let mut value: u64 = 0;
    for (i, &b) in bytes.iter().enumerate() {
        value = (value << 7) | (b & 0x7f) as u64;
        if b & 0x80 == 0 {
            if arcs.is_empty() {
                let first = (value / 40).min(2);
                arcs.push(first);
                arcs.push(value - first * 40);
            } else {
                arcs.push(value);
            }
            value = 0;
        } else if i == bytes.len() - 1 || value > u64::MAX >> 7 {
            return bad("bad OID");
        }
    }
    if arcs.is_empty() {
        return bad("empty OID");
    }
    Ok(arcs
        .iter()
        .map(u64::to_string)
        .collect::<Vec<_>>()
        .join("."))
}

fn string(tlv: Tlv<'_>) -> Result<String, DerError> {
    let c = tlv.content;
    Ok(match tlv.tag {
        UTF8_STRING | PRINTABLE_STRING | IA5_STRING => String::from_utf8_lossy(c).into_owned(),
        // Read as Latin-1, the common practice for TeletexString.
        T61_STRING => c.iter().map(|&b| b as char).collect(),
        BMP_STRING => {
            let units: Vec<u16> = c
                .chunks(2)
                .map(|p| u16::from_be_bytes([p[0], *p.get(1).unwrap_or(&0)]))
                .collect();
            String::from_utf16_lossy(&units)
        }
        UNIVERSAL_STRING => c
            .chunks(4)
            .filter_map(|p| p.try_into().ok().map(u32::from_be_bytes))
            .map(|u| char::from_u32(u).unwrap_or(char::REPLACEMENT_CHARACTER))
            .collect(),
        tag => return bad(format!("unsupported string tag 0x{tag:02x}")),
    })
}

/// UTCTime (YYMMDDHHMMSSZ, years 1950 to 2049) or GeneralizedTime
/// (YYYYMMDDHHMMSSZ), as RFC 5280 section 4.1.2.5 requires them.
fn time(tlv: Tlv<'_>) -> Result<i64, DerError> {
    let text = std::str::from_utf8(tlv.content).map_err(|_| DerError("bad time".into()))?;
    let digits = text
        .strip_suffix('Z')
        .ok_or(DerError("time is not in UTC".into()))?;
    let num = |s: &str| {
        s.parse::<i64>()
            .map_err(|_| DerError(format!("bad time {text}")))
    };
    let (year, rest) = match tlv.tag {
        UTC_TIME if digits.len() == 12 => {
            let yy = num(&digits[..2])?;
            (if yy < 50 { 2000 + yy } else { 1900 + yy }, &digits[2..])
        }
        GENERALIZED_TIME if digits.len() == 14 => (num(&digits[..4])?, &digits[4..]),
        _ => return bad(format!("bad time {text}")),
    };
    let (month, day) = (num(&rest[0..2])?, num(&rest[2..4])?);
    let (hour, minute, second) = (num(&rest[4..6])?, num(&rest[6..8])?, num(&rest[8..10])?);
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return bad(format!("bad time {text}"));
    }
    Ok(days_from_civil(year, month, day) * 86_400 + hour * 3600 + minute * 60 + second)
}

/// Days from 1970-01-01 to a date in the proleptic Gregorian calendar.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIGICERT: &[u8] = include_bytes!(
        "../../../control/profiles/example-windows/certs/digicert-assured-id-root-ca.der"
    );

    #[test]
    fn reads_the_digicert_root() {
        let cert = Certificate::parse(DIGICERT).unwrap();
        assert_eq!(cert.version, 2);
        assert_eq!(
            cert.serial,
            [
                0x0c, 0xe7, 0xe0, 0xe5, 0x17, 0xd8, 0x46, 0xfe, 0x8f, 0xe5, 0x60, 0xfc, 0x1b, 0xf0,
                0x30, 0x39
            ]
        );
        assert_eq!(
            cert.subject.first(OID_COMMON_NAME),
            Some("DigiCert Assured ID Root CA")
        );
        assert_eq!(
            cert.subject.first(OID_ORGANIZATIONAL_UNIT),
            Some("www.digicert.com")
        );
        assert_eq!(cert.subject.first(OID_ORGANIZATION), Some("DigiCert Inc"));
        assert_eq!(cert.subject.first("2.5.4.6"), Some("US"));
        assert_eq!(cert.issuer, cert.subject, "self-signed root");
        // 2006-11-10 and 2031-11-10, both 00:00:00 UTC.
        assert_eq!(cert.not_before, 1_163_116_800);
        assert_eq!(cert.not_after, 1_952_035_200);
        // The name keeps its exact encoding.
        assert_eq!(cert.subject.der[0], SEQUENCE);
        assert!(
            DIGICERT
                .windows(cert.subject.der.len())
                .any(|w| w == cert.subject.der)
        );
    }

    #[test]
    fn rejects_damaged_input() {
        assert!(Certificate::parse(&[]).is_err());
        assert!(Certificate::parse(&DIGICERT[..DIGICERT.len() - 1]).is_err());
        let mut extra = DIGICERT.to_vec();
        extra.push(0);
        assert!(Certificate::parse(&extra).is_err());
        assert!(Certificate::parse(&[0x30, 0x84, 0xff, 0xff, 0xff, 0xff]).is_err());
    }

    #[test]
    fn decodes_oids_and_times() {
        assert_eq!(oid(&[0x55, 0x04, 0x03]).unwrap(), "2.5.4.3");
        assert_eq!(
            oid(&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01]).unwrap(),
            OID_EMAIL
        );
        let t = |tag, s: &str| {
            time(Tlv {
                tag,
                content: s.as_bytes(),
                whole: &[],
            })
        };
        assert_eq!(t(UTC_TIME, "700101000000Z").unwrap(), 0);
        assert_eq!(t(UTC_TIME, "491231235959Z").unwrap(), 2_524_607_999);
        assert_eq!(
            t(GENERALIZED_TIME, "20500101000000Z").unwrap(),
            2_524_608_000
        );
        assert!(t(UTC_TIME, "700101000000").is_err());
        assert!(t(UTC_TIME, "701301000000Z").is_err());
    }
}
