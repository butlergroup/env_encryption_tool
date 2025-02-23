use env;
use std::fs;
use std::io::Read;
use log::{info, error};
use argon2::{Argon2, PasswordHasher, Params, password_hash::SaltString};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use aes_gcm::aead::Aead;

// Function to read data with length prefix
fn read_with_length(file: &mut &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut len_buf = [0u8; 4];
    file.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;

    let mut buffer = vec![0u8; len];
    file.read_exact(&mut buffer)?;
    Ok(buffer)
}

// Decrypt .env.enc file
pub fn decrypt_config() -> Result<(), Box<dyn std::error::Error>> {
    info!("Starting decryption process");

    // Step 1: Retrieve the decryption key from the environment variable
    let key = env::var("DECRYPTION_KEY")
        .expect("DECRYPTION_KEY environment variable not set");
    info!("Decryption key loaded");

    // Step 2: Read the encrypted file
    let encrypted_file_path = ".env.enc";
    let file_content = fs::read(encrypted_file_path)?;  // Reading as binary
    let mut cursor = &file_content[..];
    info!("Encrypted file content loaded");

    // Step 3: Extract salt, nonce, and encrypted data
    let salt = read_with_length(&mut cursor)?;
    assert_eq!(salt.len(), 16, "Salt length mismatch");

    let nonce_bytes = read_with_length(&mut cursor)?;
    assert_eq!(nonce_bytes.len(), 12, "Nonce length mismatch");

    let encrypted_data = read_with_length(&mut cursor)?;
    assert!(encrypted_data.len() > 0, "Encrypted data is empty");

    info!("Salt, nonce, and encrypted data decoded");
    info!("Lengths - Salt: {}, Nonce: {}, Encrypted Data: {}", 
        salt.len(), nonce_bytes.len(), encrypted_data.len());

    // Step 4: Derive key using Argon2
    let salt_string = SaltString::encode_b64(&salt)
        .map_err(|e| format!("Invalid salt encoding: {}", e))?;
    let argon2 = Argon2::default();
    let params = Params::new(65536, 3, 1, None)
        .map_err(|e| format!("Invalid Argon2 parameters: {}", e))?;

    let derived_key = argon2
        .hash_password_customized(
            key.as_bytes(),
            None,
            None,
            params,
            &salt_string
        )
        .map_err(|e| format!("Argon2 hashing error: {}", e))?
        .hash
        .ok_or("Missing hash result")?
        .as_bytes()
        .to_vec();

    info!("Derived key generated successfully.");

    // Step 5: Decryption (AES-GCM)
    info!("Starting AES-GCM decryption...");
    let aes_key = Aes256Gcm::new_from_slice(&derived_key).expect("AES key creation failed");
    let nonce = Nonce::from_slice(&nonce_bytes);
    let decrypted_data = aes_key.decrypt(nonce, encrypted_data.as_ref())
        .map_err(|e| format!("AES-GCM decryption failed: {}", e))?;
    let decrypted_string = String::from_utf8(decrypted_data)?;
    info!("Decrypted data successfully converted to string");

    // Step 6: Parse and set environment variables
    info!("Setting environment variables...");
    for line in decrypted_string.lines() {
        if !line.is_empty() {
            let mut parts = line.splitn(2, '=');
            let key = parts.next().unwrap().trim();
            let mut value = parts.next().unwrap_or("").trim().to_string();

            if value.starts_with('"') && value.ends_with('"') {
                value = value[1..value.len() - 1].to_string();
            }

            if !key.is_empty() && !value.is_empty() {
                info!("Setting environment variable: {} = {}", key, value);
                let _ = env::set_var(key, value);
            } else {
                error!("Invalid environment variable entry: {} = {}", key, value);
            }
        }
    }

    info!("Decryption and environment variable setting complete");

    Ok(())
}
