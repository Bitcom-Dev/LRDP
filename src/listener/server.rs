use crate::utils::{decrypt_data, log};
use std::io::{Read, Write};

fn handle_tcp_connection(address: String, port: u16, _private_key: String, public_key: String) {
    log("REGISTER", &format!("Listening on TCP port {}", port));
    
    std::fs::create_dir_all("devices").unwrap();

    let bind_address = if address == "0.0.0.0" || address == "127.0.0.1" || address == "localhost" {
        format!("[::]:{}", port)
    } else {
        format!("{}:{}", address, port)
    };

    let listener = match std::net::TcpListener::bind(bind_address) {
        Ok(l) => l,
        Err(e) => {
            log("REGISTER", &format!("Failed to bind TCP listener: {}", e));
            return;
        }
    };
    
    for stream in listener.incoming() {
        match stream {
            Ok(mut _s) => {
                let public_key = public_key.clone();
                let private_key = _private_key.clone();
                std::thread::spawn(move || {
                    log("REGISTER", &format!("Accepted new TCP connection from {}", _s.peer_addr().unwrap()));
                    _s.write_all(public_key.as_bytes()).unwrap();

                    let mut encrypted_buf = [0; 512];
                    if let Err(e) = _s.read_exact(&mut encrypted_buf) {
                        log("ERROR", &format!("Failed to read encrypted data from {}: {}", _s.peer_addr().unwrap(), e));
                        return;
                    }

                    let mut public_key_der = Vec::new();
                    if let Err(e) = _s.read_to_end(&mut public_key_der) {
                        log("ERROR", &format!("Failed to read public key from {}: {}", _s.peer_addr().unwrap(), e));
                        return;
                    }
                    
                    log("REGISTER", &format!("Received {} bytes from {}", encrypted_buf.len() + public_key_der.len(), _s.peer_addr().unwrap()));
                    
                    let decrypted_data = decrypt_data(&encrypted_buf, &private_key);
                    log("REGISTER", &format!("Decrypted data: {:?}", decrypted_data));
                    
                    if decrypted_data.len() < 8 {
                        log("ERROR", "Decrypted data is too short.");
                        return;
                    }

                    let mac = &decrypted_data[0..6];
                    let mac = format!("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
                    let device = &decrypted_data[6..];

                    if device.len() != 2 {
                        log("ERROR", "Invalid device data length after decryption.");
                        return;
                    }
                    
                    let device = u16::from_be_bytes([device[0], device[1]]);

                    log("REGISTER", &format!("MAC: {} Device: {:?}", mac, device));

                    let device_folder = format!("devices/{}", device);
                    std::fs::create_dir_all(&device_folder).unwrap();
                    std::fs::write(format!("{}/mac", device_folder), mac).unwrap();
                    std::fs::write(format!("{}/last_seen", device_folder), chrono::Local::now().to_rfc3339()).unwrap();
                    
                    let pem = pem::Pem::new(
                        "PUBLIC KEY",
                        public_key_der,
                    );
                    let pem_string = pem::encode(&pem);
                    std::fs::write(format!("{}/public_key.pem", device_folder), pem_string).unwrap();

                    log("REGISTER", &format!("Device {} registered successfully.", device));
                });
            }
            Err(e) => {
                log("ERROR", &format!("Failed to accept TCP connection: {}", e));
            }
        }
    }
}

fn handle_udp_connection(address: String, port: u16, _private_key: String, public_key: String) {
    log("DUMP", &format!("Listening on UDP port {}", port));

    std::fs::create_dir_all("devices").unwrap();
    let bind_address = if address == "0.0.0.0" || address == "127.0.0.1" || address == "localhost" {
        format!("[::]:{}", port)
    } else {
        format!("{}:{}", address, port)
    };

    let socket = match std::net::UdpSocket::bind(bind_address) {
        Ok(s) => s,
        Err(e) => {
            log("DUMP", &format!("Failed to bind UDP socket: {}", e));
            return;
        }
    };

    let mut buf = [0; 512];
    loop {
        match socket.recv_from(&mut buf) {
            Ok((size, src)) => {
                log("DUMP", &format!("Received {} bytes from {}", size, src));
                // response to src with public key
                if let Err(e) = socket.send_to(public_key.as_bytes(), src) {
                    log("ERROR", &format!("Failed to send public key to {}: {}", src, e));
                    continue;
                }
            }
            Err(e) => {
                log("ERROR", &format!("Failed to receive UDP packet: {}", e));
            }
        }
    }
}


pub fn start(address: String, port: u16, protocol: u8, private_key: String, public_key: String) {
    if port == 0 {
        log("ERROR", "Port number cannot be 0.");
        return;
    }

    match protocol {
        0 => handle_tcp_connection(address, port, private_key, public_key),
        1 => handle_udp_connection(address, port, private_key, public_key),
        _ => {
            log("ERROR", "Invalid protocol specified. Use 0 for TCP or 1 for UDP.");
            return;
        }
    }

}