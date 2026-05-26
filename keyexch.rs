use hkdf::Hkdf;
use rand_core::OsRng;
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey};

pub struct KeyExchange {
    secret: EphemeralSecret,
    pub public_key: PublicKey,
}

impl KeyExchange {
    pub fn new() -> Self {
        let secret = EphemeralSecret::random_from_rng(OsRng);
        let public_key = PublicKey::from(&secret);
        Self { secret, public_key }
    }

    pub fn derive_session_key(self, peer_public_key_bytes: &[u8; 32], info: &[u8]) -> Result<[u8; 32], &'static str> {
        let peer_pub = PublicKey::from(*peer_public_key_bytes);

        let shared_secret = self.secret.diffie_hellman(&peer_pub);

        let hk = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
        let mut session_key = [0u8; 32];
        hk.expand(info, &mut session_key)
            .map_err(|_| "HKDF expand failed")?;

        Ok(session_key)
    }
}