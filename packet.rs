pub struct Packet {
    pub data: Vec<u8>,
}

pub struct EncryptedPacket {
    pub nonce: [u8; 24],
    pub data: Vec<u8>,
}

pub const TYPE_HANDSHAKE: u8 = 0x01;
pub const TYPE_DATA: u8 = 0x02;
pub const EXCHANGE: u8 = 0x03;
pub const INIT_HANDSHAKE: u8 = 0x04;
pub const KEEPALIVE: u8 = 0x05;