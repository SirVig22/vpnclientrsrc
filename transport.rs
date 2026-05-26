use crate::packet::TYPE_DATA;

pub fn encapsulate(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + data.len());
    out.push(TYPE_DATA);
    out.extend_from_slice(data);
    out
}

pub fn decapsulate(data: &[u8]) -> Option<&[u8]> {
    if data.len() < 2 { return None; }
    if data[0] != TYPE_DATA { return None; }
    Some(&data[1..])
}