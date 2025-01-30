use aes_gcm::{Aes256Gcm, KeyInit, Nonce}; // AES-GCM and its required types
use aes_gcm::aead::Aead;
use base64::engine::general_purpose::STANDARD;
use base64::Engine; // For base64 decoding
use std::env;
use std::fs;
use log::{info, error, debug};
use std::io;

// Decrypt .env.enc file - uses env_logger to report output
pub fn decrypt_config() -> Result<(), Box<dyn std::error::Error>> {
    info!("Starting decryption process");

    // Retrieve the decryption key from the environment variable
    let secret_key = env::var("DECRYPTION_KEY")
        .expect("DECRYPTION_KEY environment variable not set");
    let key = secret_key.as_bytes();

    info!("Decryption key loaded");

    // Define file paths
    let encrypted_file_path = ".env.enc";

    // Read the encrypted file (check if not found or other I/O error)
    let file_content = match fs::read_to_string(encrypted_file_path) {
        Ok(content) => content,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            // Return a custom error if file not found
            return Err(format!("Encrypted file '{}' not found: {}", encrypted_file_path, e).into());
        }
        Err(e) => return Err(e.into()),
    };
    debug!("Encrypted file content loaded");

    // Split the content into nonce and encrypted data parts
    let parts: Vec<&str> = file_content.split(':').collect();
    if parts.len() != 2 {
        return Err("Invalid encrypted file format: expected 'nonce:encrypted_data' format".into());
    }

    let nonce_base64 = parts[0];
    let encrypted_data_base64 = parts[1];

    // Decode the nonce and encrypted data from base64
    let nonce_bytes = STANDARD.decode(nonce_base64)
        .map_err(|e| format!("Failed to decode nonce from base64: {}", e))?;
    let encrypted_data = STANDARD.decode(encrypted_data_base64)
        .map_err(|e| format!("Failed to decode encrypted data from base64: {}", e))?;

    info!("Nonce and encrypted data decoded from base64");

    // Check if nonce length is correct (AES-GCM standard nonce size is 12 bytes)
    if nonce_bytes.len() != 12 {
        error!("Nonce has incorrect length: expected 12 bytes, got {}", nonce_bytes.len());
        return Err("Nonce has incorrect length".into());
    }

    // Create the AES-GCM cipher using the 256-bit key
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| format!("Failed to create AES cipher: {}", e))?;

    // Convert the nonce into a Nonce type
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Decrypt the data using AES-GCM
    let decrypted_data = cipher.decrypt(nonce, encrypted_data.as_ref())
        .map_err(|e| format!("Decryption failed: {}", e))?;

    // Convert decrypted bytes to a string
    let decrypted_string = String::from_utf8(decrypted_data)?;
    info!("Decrypted data successfully converted to string");

    // Parse and set environment variables
    for line in decrypted_string.lines() {
        if !line.is_empty() {
            let mut parts = line.splitn(2, '=');
            let key = parts.next().unwrap().trim();
            let mut value = parts.next().unwrap_or("").trim().to_string();

            // Remove quotes if they exist
            if value.starts_with('"') && value.ends_with('"') {
                value = value[1..value.len() - 1].to_string();
            }

            if !key.is_empty() && !value.is_empty() {
                info!("Setting environment variable: {} = {}", key, value);
                env::set_var(key, value);
            } else {
                error!("Invalid environment variable entry: {} = {}", key, value);
            }
        }
    }

    info!("Decryption and environment variable setting complete");

    Ok(())
}

