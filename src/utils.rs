use rsa::{RsaPrivateKey, RsaPublicKey};
use rsa::pkcs1::{EncodeRsaPrivateKey, EncodeRsaPublicKey};
use rsa::pkcs1::LineEnding;
use rsa::{pkcs1::DecodeRsaPrivateKey, pkcs1::DecodeRsaPublicKey};
use rand::rngs::OsRng;

pub fn log(priority: &str, message: &str) {
	println!("[{}] [{}] {}", chrono::Local::now(), priority, message);
}

pub fn helper() {
	println!("Usage: lrdp_server [OPTIONS]\n");
	println!("Options:");
	println!("\t--help, -h\tDisplay this help information");
	println!("\t--version, -v\tDisplay the version information");
	println!("\t--mode, -m\tSet the server mode (0 for listener, 1 for process)");
}

pub fn generate_rsa_keys(bits: usize) -> (String, String) {
    println!("Generating RSA key pair with {} bits...", bits);
    let mut rng = OsRng;
    let private_key = RsaPrivateKey::new(&mut rng, bits ).expect("Failed to generate a key");
    let public_key = RsaPublicKey::from(&private_key);
    let private_key_pem = private_key.to_pkcs1_pem(LineEnding::LF).unwrap();
    let public_key_pem = public_key.to_pkcs1_pem(LineEnding::LF).unwrap();
    println!("RSA key pair generation complete.");
    (private_key_pem.to_string(), public_key_pem.to_string())
}

pub fn encrypted_data(data: &[u8], public_key_pem: &str) -> Vec<u8> {
    let public_key = RsaPublicKey::from_pkcs1_pem(public_key_pem).expect("Failed to parse public key");
    let mut rng = OsRng;
    let encrypted_data = public_key.encrypt(&mut rng, rsa::Pkcs1v15Encrypt, data).expect("Failed to encrypt data");
    encrypted_data
}

pub fn decrypt_data(encrypted_data: &[u8], private_key_pem: &str) -> Vec<u8> {
    let private_key = RsaPrivateKey::from_pkcs1_pem(private_key_pem).expect("Failed to parse private key");
    let decrypted_data = private_key.decrypt(rsa::Pkcs1v15Encrypt, encrypted_data).expect("Failed to decrypt data");
    decrypted_data
}