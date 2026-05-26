use std::net::{UdpSocket, Ipv4Addr, IpAddr, SocketAddr};
use std::sync::Arc;
use std::io::{Read, Write};
use std::{thread, time};
use std::sync::mpsc::channel;
use std::sync::Mutex;
use socket2::{Socket, Domain, Type, Protocol};
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Nonce, Key
};


use crate::packet::{TYPE_HANDSHAKE, TYPE_DATA, EXCHANGE, INIT_HANDSHAKE, KEEPALIVE};
use crate::keyexch::KeyExchange;
use crate::crypto;
use crate::transport;

pub fn udp_handler(server: &str) -> Result<(), Box<dyn std::error::Error>> {
    let bind: SocketAddr = "0.0.0.0:0".parse().unwrap();
    let socket = create_udp(bind)?; // port 0 = OS picks a free port
    let server = server.to_string();
    const MAKE_WORKERS: u8 = 4;

    // --- Handshake first, synchronously ---
    let mut buf = vec![0u8; 65536];
    let mut vpn_ip: Option<Ipv4Addr> = None;
    let mut session_key: Option<[u8; 32]> = None;

    socket.send_to(&[INIT_HANDSHAKE], &server)?;

    loop {
        let (len) = socket.recv(&mut buf)?;
        if len == 0 { continue; }

        match buf[0] {
            TYPE_HANDSHAKE => {
                if len >= 5 {
                    let ip = Ipv4Addr::new(buf[1], buf[2], buf[3], buf[4]);
                    println!("Assigned VPN IP: {}", ip);
                    vpn_ip = Some(ip);
                }
            }
            EXCHANGE => {
                if len >= 33 {
                    let server_pub: [u8; 32] = buf[1..33].try_into()?;
                    let clientk = KeyExchange::new();
                    let mut reply = vec![EXCHANGE];
                    reply.extend_from_slice(&clientk.public_key.to_bytes());
                    socket.send_to(&reply, &server)?;
                    let key = clientk.derive_session_key(&server_pub, b"vpn-session-v1")?;
                    println!("Session key established: {}", hex::encode(key));
                    socket.connect(&server).expect("Cant conn");
                    session_key = Some(key);
                }
            }
            _ => {}
        }

        if vpn_ip.is_some() && session_key.is_some() {
            break;
        }
    }

    let vpn_ip = vpn_ip.unwrap();
    let session_key = session_key.unwrap();

    // --- Now set up TUN with the known VPN IP ---
    let mut config = tun::Configuration::default();
    config
        .name("tun0")
        .address(vpn_ip)
        .netmask((255, 255, 255, 0))
        .mtu(1400)
        .up();
    let dev = tun::create(&config)?;
    let (mut tun_reader, mut tun_writer) = dev.split();

    // --- Set up routes ---
    let server_ip = server.split(':').next().unwrap().to_string();
    std::process::Command::new("ip")
        .args(["route", "replace", &server_ip, "via", "192.168.1.1", "dev", "eth0"])
        .status().ok();
    std::process::Command::new("ip")
        .args(["route", "replace", "default", "via", "10.0.0.1", "dev", "tun0"])
        .status().ok();

    // --- Set up ciphers ---
    let cipher_enc = Arc::new(Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&session_key)));

    let socket = Arc::new(socket);
    let socket_sender = socket.try_clone()?;
    let socket_receiver = socket.try_clone()?;
    let val = server.clone();

    let value = cipher_enc.clone();
    // Outbound: TUN read → encrypt → encapsulate → UDP send
    thread::spawn(move || {
        let mut buf = vec![0u8; 65536];
        let mut out_buf = Vec::with_capacity(65536 + 32);
        loop {
            let n = match tun_reader.read(&mut buf) {
                Ok(n) if n > 0 => n,
                _ => continue,
            };
            //println!("TUN read {} bytes", n);
            let encrypted = crypto::encrypt(&value, &buf[..n], &mut out_buf);
            let encapsulated = transport::encapsulate(&encrypted);
            let _ = socket_sender.send(&encapsulated);
        }
    });


    let tun_writer = Arc::new(Mutex::new(tun_writer));
    let socket_receiver = Arc::new(socket_receiver);

    for _ in 0..MAKE_WORKERS {
        let cipher_dec = Arc::clone(&cipher_enc);
        let tun_writer = Arc::clone(&tun_writer);
        let socket_receiver = Arc::clone(&socket_receiver);
        let value = cipher_enc.clone();
        thread::spawn(move || {
            let cipher_dec = Arc::clone(&value);
            let mut buf = vec![0u8; 65536];
            loop {
                let len = match socket_receiver.recv(&mut buf) {
                    Ok(v) => v,
                    Err(e) => { eprintln!("recv error: {}", e); continue; }
                };
                if len == 0 { continue; }

                match buf[0] {
                    TYPE_DATA => {
                        if let Some(payload) = transport::decapsulate(&buf[..len]) {
                            if let Some(decrypted) = crypto::decrypt(&cipher_dec, payload) {
                                tun_writer.lock().unwrap().write_all(&decrypted).ok();
                                //println!("TUN write {} bytes", decrypted.len());
                            } else {
                                eprintln!("decryption failed");
                            }
                        }
                    }
                    _ => {
                        eprintln!("Unexpected packet type after handshake: {}", buf[0]);
                    }
                }
            }
        });
    };

    //keepalive
    thread::spawn(move || {
        loop {
            thread::sleep(time::Duration::from_millis(15000));
            socket.send(&[TYPE_DATA]).ok();
        }
    });

    

    Ok(())
}

fn create_udp(bind: SocketAddr) -> std::io::Result<UdpSocket> {

    let socket = Socket::new(
        Domain::IPV4,
        Type::DGRAM,
        Some(Protocol::UDP)
    )?;

    socket.set_recv_buffer_size(4 * 1024 * 1024)?;
    socket.set_send_buffer_size(4 * 1024 * 1024)?;

    socket.bind(&bind.into())?;
    Ok(socket.into())
}