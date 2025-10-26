mod listener;
mod utils;

use utils::{log, helper};

fn main() {
	let mut mode: u8 = 0;
	let mut address: String = "127.0.0.1".to_string();
	let mut port: u16 = 0;
	let mut protocol: u8 = 0;
	let mut args_iter = std::env::args().skip(1);

	if !std::path::Path::new("keys").exists() {
		std::fs::create_dir("keys").unwrap();
	}
	if !std::path::Path::new("keys/server_private_key.pem").exists() || !std::path::Path::new("keys/server_public_key.pem").exists() {
		let (private_key, public_key) = utils::generate_rsa_keys(4096);
		std::fs::write("keys/server_private_key.pem", private_key).unwrap();
		std::fs::write("keys/server_public_key.pem", public_key).unwrap();
	}

	let private_key = std::fs::read_to_string("keys/server_private_key.pem").unwrap();
	let public_key = std::fs::read_to_string("keys/server_public_key.pem").unwrap();

	while let Some(arg) = args_iter.next() {
		match arg.as_str() {
			"--version" | "-v" => println!("LRDP Server Version: {}", env!("CARGO_PKG_VERSION")),
			"--mode" | "-m" => {
				if let Some(value) = args_iter.next() {
					match value.as_str() {
						"1" => mode = 1,
						"2" => mode = 2,
						_ => {
							println!("Error: Invalid mode specified. Use 0 for devices or 1 for server.");
							helper();
							std::process::exit(-1);	
						}
					}
				} else {
					println!("Error: No mode specified after --mode/-m flag.");
					helper();
					std::process::exit(-1);
				}
			}
			"--protocol" | "-P" => {
				if let Some(value) = args_iter.next() {
					match value.as_str() {
						"0" => protocol = 0,
						"1" => protocol = 1,
						_ => {
							println!("Error: Invalid protocol specified. Use 0 for TCP or 1 for UDP.");
							helper();
							std::process::exit(-1);	
						}
					}
				} else {
					println!("Error: No protocol specified after --protocol/-p flag.");
					helper();
					std::process::exit(-1);
				}
			}
			"--port" | "-p" => {
				if let Some(value) = args_iter.next() {
					match value.parse::<u16>() {
						Ok(p) => port = p,
						Err(_) => {
							println!("Error: Invalid port number specified.");
							helper();
							std::process::exit(-1);	
						}
					}
				} else {
					println!("Error: No port specified after --port/-p flag.");
					helper();
					std::process::exit(-1);
				}
			}
			"--address" | "-a" => {
				if let Some(value) = args_iter.next() {
					address = value;
				} else {
					println!("Error: No address specified after --address/-a flag.");
					helper();
					std::process::exit(-1);
				}
			}
			_ => {
				helper();
				std::process::exit(-1);
			}
		}
	}

	match mode {
		1 => {
			listener::server::start(address, port, protocol, private_key, public_key);
			std::process::exit(0);
		},
		2 => {
			listener::server::start(address, port, protocol, private_key, public_key);
			std::process::exit(0);
		},
		_ => {},
	}

	log("INFO", "LRDP Server starting all subprocesses...");
	
	let mut register_process = std::process::Command::new(std::env::current_exe().unwrap())
		.arg("--mode")
		.arg("1")
		.arg("--port")
		.arg("61234")
		.arg("--protocol")
		.arg("0")
		.spawn()
		.expect("Failed to start register subprocess");
	
	let mut dump_process = std::process::Command::new(std::env::current_exe().unwrap())
		.arg("--mode")
		.arg("1")
		.arg("--port")
		.arg("61234")
		.arg("--protocol")
		.arg("1")
		.spawn()
		.expect("Failed to start dump subprocess");

	register_process.wait().expect("Failed to wait on register subprocess");
	dump_process.wait().expect("Failed to wait on dump subprocess");
	std::process::exit(0);
}
