use std::thread;

mod crypto;
mod transport;
mod udp;
mod packet;
mod keyexch;

fn main() {
    let server = "77.90.63.74:1286"; //CHANGE LATER

    thread::spawn(move || {
        println!("Listening");
        udp::udp_handler(server).unwrap();
    });
    thread::park();
}

