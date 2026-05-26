use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Nonce, AeadInPlace
};


pub fn encrypt<'a>(cipher: &Aes256Gcm, data: &[u8], out: &'a mut Vec<u8>) -> &'a [u8] {

    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    out.clear();
    out.extend_from_slice(&nonce);
    out.extend_from_slice(data);

    let tag = cipher.encrypt_in_place_detached(&nonce, b"", &mut out[12..]).expect("enc failed");

    out.extend_from_slice(&tag);

    out
}

pub fn decrypt(cipher: &Aes256Gcm, data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < 12 { return None; }
    let nonce: [u8; 12] = data[..12].try_into().unwrap();
    cipher.decrypt(&nonce.into(), &data[12..]).ok()
}