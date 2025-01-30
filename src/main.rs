use aes_gcm::{Aes256Gcm, KeyInit, Nonce};  // AES-GCM and its required types
use aes_gcm::aead::Aead;  // Traits needed for encryption
use rand::RngCore;
use std::fs;
use std::fs::File;
use std::io::Write;
use base64::engine::general_purpose::STANDARD;
use base64::Engine; // For Engine::encode method

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Retrieve the encryption key from the environment variable
    let secret_key = ""; 

    // Ensure the key length is 32 bytes for AES-256
    if secret_key.len() != 32 {
        return Err("Encryption key must be exactly 32 bytes long for AES-256.".into());
    }

    let key = secret_key.as_bytes();

    // Define file paths
    let input_file_path = ".env";       // Input plaintext .env file
    let output_file_path = ".env.enc"; // Output encrypted .env file

    // Read the plaintext .env file
    let plaintext = fs::read_to_string(input_file_path)
        .expect("Failed to read the .env file");

    // Generate a random nonce (12 bytes for AES-GCM)
    let mut nonce_bytes = [0u8; 12];  // AES-GCM standard nonce size is 12 bytes
    rand::rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Debugging: print the nonce before encryption
    println!("Generated nonce (raw bytes): {:?}", nonce_bytes);

    // Create the AES-GCM cipher using the 256-bit key
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| format!("Failed to create AES cipher: {}", e))?;

    // Encrypt the plaintext using AES-GCM
    let encrypted_data = cipher.encrypt(nonce, plaintext.as_bytes())
        .map_err(|e| format!("Encryption failed: {}", e))?;

    // Debugging: print the encrypted data (raw bytes)
    println!("Encrypted data (raw bytes): {:?}", encrypted_data);

    // Write the result to the .env.enc file in the format: [nonce]:[encrypted_data]
    let mut output_file = File::create(output_file_path)
        .expect("Failed to create the .env.enc file");

    // Write the nonce as a base64 string followed by a ':' separator
    output_file.write_all(STANDARD.encode(&nonce_bytes).as_bytes())?;
    output_file.write_all(b":")?;

    // Write the encrypted data as a base64 string
    output_file.write_all(STANDARD.encode(&encrypted_data).as_bytes())?;

    println!("File encrypted successfully and saved to '{}'", output_file_path);

    Ok(())
}
