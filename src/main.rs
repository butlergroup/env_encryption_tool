// mod decrypt_config;

use argon2::{Argon2, PasswordHasher, Params, password_hash::SaltString};
use rand_core::{OsRng, TryRngCore};
use std::fs::{self, File};
use std::io::Write;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use aes_gcm::aead::Aead;

// ✅ Generate a random alphanumeric salt using rand_core
fn generate_salt() -> Vec<u8> {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut salt = [0u8; 16]; // 16 bytes for the salt
    let _ = OsRng.try_fill_bytes(&mut salt); // Secure RNG

    // ✅ Collect as u8 instead of char
    salt.iter()
        .map(|&b| CHARSET[(b as usize) % CHARSET.len()])  // Keep as u8
        .collect()
}

// 🔐 Encrypt .env file
fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Step 1: Input encryption key and generate salt
    let salt = generate_salt();
    let key = ""; 
    // ^ Input 32-character encryption key

    // Step 2: Derive new key using Argon2 with salt
    let argon2 = Argon2::default();

    // ✅ Convert raw salt bytes to SaltString
    let salt_string = SaltString::encode_b64(&salt)
        .map_err(|e| format!("Invalid salt encoding: {}", e))?;

    // ✅ Use Params for Argon2 configuration
    let params = Params::new(65536, 3, 1, None)
        .map_err(|e| format!("Invalid Argon2 parameters: {}", e))?;

    let derived_key = argon2
        .hash_password_customized(
            key.as_bytes(),
            None,           // Algorithm (optional)
            None,           // Version (optional)
            params,         // ✅ Directly pass Params (no Some())
            &salt_string    // ✅ Pass SaltString
        )
        .map_err(|e| format!("Argon2 hashing error: {}", e))?
        .hash
        .ok_or("Missing hash result")?
        .as_bytes()
        .to_vec();

    println!("Derived key generated successfully.");

    // Step 3: Encryption (AES-GCM using Argon2-Derived Key)
    let plaintext = fs::read_to_string(".env")?;
    let aes_key = Aes256Gcm::new_from_slice(&derived_key).expect("AES key creation failed");
    let mut nonce_bytes = [0u8; 12];
    let _ = OsRng.try_fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let encrypted_data = aes_key.encrypt(nonce, plaintext.as_bytes())
        .map_err(|e| format!("Encryption process failure: {}", e))?;

    // Step 4: Store Salt, Nonce, and Encrypted Data
    let mut output_file = File::create(".env.enc")?;

    println!("Writing Salt ({} bytes): {:?}", salt.len(), &salt);
    write_with_length(&mut output_file, &salt)?;

    println!("Writing Nonce ({} bytes): {:?}", nonce_bytes.len(), &nonce_bytes);
    write_with_length(&mut output_file, &nonce_bytes)?;

    println!("Writing Encrypted Data ({} bytes)", encrypted_data.len());
    write_with_length(&mut output_file, &encrypted_data)?;

    println!("File encrypted successfully and saved to '.env.enc'");
    Ok(())
}

// Function to write data with length prefix
fn write_with_length(file: &mut File, data: &[u8]) -> std::io::Result<()> {
    let len = (data.len() as u32).to_be_bytes(); // 4 bytes for length
    file.write_all(&len)?;
    file.write_all(data)?;
    Ok(())
}