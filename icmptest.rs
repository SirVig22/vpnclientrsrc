use std::io::{Read, Write};
use tun::Configuration;

pub fn start() -> Result<(), Box<dyn std::error::Error>> {
    let mut config = Configuration::default();

    config
        .name("tun0")
        .address((10, 0, 0, 42))
        .netmask((255, 255, 255, 0))
        .destination((10, 0, 0, 1))
        .up();

    let mut dev = tun::create(&config)?;

    let mut buf = [0u8; 1500];
    
    loop {
        let amount = dev.read(&mut buf)?;
        let version = buf[0] >> 4;

        if version == 4 {
            let ip_header_len = (buf[0] & 0x0F) as usize * 4;
            let src_ip = &buf[12..16];
            let dst_ip = &buf[16..20];
            let protocol = buf[9];

            if protocol != 1 { continue; }

            let icmp_type = buf[ip_header_len];
            if icmp_type != 8 { continue; }

            let mut reply = buf[..amount].to_vec();
            reply[12..16].copy_from_slice(dst_ip);
            reply[16..20].copy_from_slice(src_ip);
            reply[ip_header_len] = 0;

            reply[ip_header_len + 2] = 0;
            reply[ip_header_len + 3] = 0;
            let checksum = icmp_checksum(&reply[ip_header_len..amount]);
            reply[ip_header_len + 2] = (checksum >> 8) as u8;
            reply[ip_header_len + 3] = (checksum & 0xFF) as u8;

            dev.write_all(&reply)?;

        } else if version == 6 {
            //let header_len: usize = 40;

            //println!("Read {} bytes\n IP version {}\n", header_len, version);
        } else {
            println!("Unknown version")
        }
    }
}

fn icmp_checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut chunks = data.chunks(2);
    for chunk in &mut chunks {
        let val = if chunk.len() == 2 {
            (chunk[0] as u16) << 8 | (chunk[1] as u16)
        } else {
            (chunk[0] as u16) << 8
        };
        sum += val as u32;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}