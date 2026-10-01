//! Just enough DNS for a guest's lookups: one question in, an A answer, an
//! empty answer, or a refusal out. Every name is answered from the rules
//! and the fake range; nothing is forwarded.

use std::net::Ipv4Addr;

use thiserror::Error;

pub const TYPE_A: u16 = 1;
pub const TYPE_AAAA: u16 = 28;
const HEADER: usize = 12;
const NAME_BYTES_MAX: usize = 255;
/// Answers live briefly: the fake address is stable, but rules change.
pub const TTL_S: u32 = 60;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DnsError {
    #[error("a DNS message too short")]
    Short,
    #[error("not one standard query")]
    NotAQuery,
    #[error("a malformed name")]
    Name,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Query {
    pub id: u16,
    pub name: String,
    pub qtype: u16,
    /// The question as sent, echoed in the answer.
    question: Vec<u8>,
    rd: bool,
}

pub fn parse_query(b: &[u8]) -> Result<Query, DnsError> {
    if b.len() < HEADER {
        return Err(DnsError::Short);
    }
    let id = u16::from_be_bytes([b[0], b[1]]);
    let flags = u16::from_be_bytes([b[2], b[3]]);
    let qd = u16::from_be_bytes([b[4], b[5]]);
    // QR clear, opcode 0 (a standard query), one question.
    if flags & 0x8000 != 0 || (flags >> 11) & 0xf != 0 || qd != 1 {
        return Err(DnsError::NotAQuery);
    }
    let mut i = HEADER;
    let mut labels: Vec<String> = Vec::new();
    // Bounded by NAME_BYTES_MAX and the message's length.
    loop {
        let len = *b.get(i).ok_or(DnsError::Short)? as usize;
        i += 1;
        if len == 0 {
            break;
        }
        if len > 63 || i + len > b.len() || i - HEADER > NAME_BYTES_MAX {
            return Err(DnsError::Name);
        }
        let label = std::str::from_utf8(&b[i..i + len]).map_err(|_| DnsError::Name)?;
        labels.push(label.to_ascii_lowercase());
        i += len;
    }
    if i + 4 > b.len() {
        return Err(DnsError::Short);
    }
    let qtype = u16::from_be_bytes([b[i], b[i + 1]]);
    let question = b[HEADER..i + 4].to_vec();
    Ok(Query { id, name: labels.join("."), qtype, question, rd: flags & 0x0100 != 0 })
}

fn header(q: &Query, rcode: u16, answers: u16) -> Vec<u8> {
    // QR, RA, and RD as asked.
    let flags = 0x8080 | if q.rd { 0x0100 } else { 0 } | rcode;
    let mut out = Vec::with_capacity(HEADER + q.question.len() + 16);
    out.extend_from_slice(&q.id.to_be_bytes());
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&answers.to_be_bytes());
    out.extend_from_slice(&[0, 0, 0, 0]);
    out.extend_from_slice(&q.question);
    out
}

pub fn answer_a(q: &Query, ip: Ipv4Addr) -> Vec<u8> {
    let mut out = header(q, 0, 1);
    // The name as a pointer to the question's (offset 12).
    out.extend_from_slice(&[0xc0, 0x0c]);
    out.extend_from_slice(&TYPE_A.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&TTL_S.to_be_bytes());
    out.extend_from_slice(&4u16.to_be_bytes());
    out.extend_from_slice(&ip.octets());
    out
}

/// The name exists but has no record of this type (an AAAA for an IPv4
/// guest), so a client falls back to A.
pub fn answer_empty(q: &Query) -> Vec<u8> {
    header(q, 0, 0)
}

pub fn answer_nxdomain(q: &Query) -> Vec<u8> {
    header(q, 3, 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(name: &str, qtype: u16) -> Vec<u8> {
        let mut b = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for l in name.split('.') {
            b.push(l.len() as u8);
            b.extend_from_slice(l.as_bytes());
        }
        b.push(0);
        b.extend_from_slice(&qtype.to_be_bytes());
        b.extend_from_slice(&1u16.to_be_bytes());
        b
    }

    #[test]
    fn parse_and_answer() {
        let q = parse_query(&query("Model.Example.com", TYPE_A)).unwrap();
        assert_eq!((q.id, q.name.as_str(), q.qtype), (0x1234, "model.example.com", TYPE_A));
        let a = answer_a(&q, Ipv4Addr::new(198, 18, 0, 1));
        assert_eq!(&a[0..2], &[0x12, 0x34]);
        assert_eq!(u16::from_be_bytes([a[6], a[7]]), 1, "one answer");
        assert_eq!(&a[a.len() - 4..], &[198, 18, 0, 1]);
        let n = answer_nxdomain(&q);
        assert_eq!(n[3] & 0x0f, 3);
        assert_eq!(answer_empty(&q)[7], 0);
    }

    #[test]
    fn refuses_malformed() {
        assert_eq!(parse_query(&[0; 5]), Err(DnsError::Short));
        let mut resp = query("a.b", TYPE_A);
        resp[2] |= 0x80;
        assert_eq!(parse_query(&resp), Err(DnsError::NotAQuery));
        let mut two = query("a.b", TYPE_A);
        two[5] = 2;
        assert_eq!(parse_query(&two), Err(DnsError::NotAQuery));
        let mut long = query("a", TYPE_A);
        long[12] = 64;
        assert!(parse_query(&long).is_err());
        let cut = query("abc.def", TYPE_A);
        assert!(parse_query(&cut[..cut.len() - 3]).is_err());
    }
}
