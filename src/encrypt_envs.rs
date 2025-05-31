use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};
use argon2::{Argon2, Params, PasswordHasher, password_hash::SaltString};
use rand_core::{OsRng, TryRngCore};
use std::error::Error;
use std::fs::{self, File};
use std::io::Write;

/// Generate a random alphanumeric salt
fn generate_salt() -> Vec<u8> {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut salt = [0u8; 16];
    let _ = OsRng.try_fill_bytes(&mut salt);
    salt.iter()
        .map(|&b| CHARSET[(b as usize) % CHARSET.len()])
        .collect()
}

/// Write a binary blob prefixed with its length
fn write_with_length(file: &mut File, data: &[u8]) -> std::io::Result<()> {
    let len = (data.len() as u32).to_be_bytes();
    file.write_all(&len)?;
    file.write_all(data)?;
    Ok(())
}

/// Encrypts `.env` and outputs `env.enc`
pub fn encrypt_env_file() -> Result<(), Box<dyn Error>> {
    let salt = generate_salt();
    let key = std::env::var("DECRYPTION_KEY")
        .map_err(|_| "Missing DECRYPTION_KEY environment variable")?;
    if key.len() != 32 {
        return Err("DECRYPTION_KEY must be exactly 32 characters long".into());
    }
    // Derive key using Argon2
    let argon2 = Argon2::default();
    let salt_string =
        SaltString::encode_b64(&salt).map_err(|e| format!("Invalid salt encoding: {}", e))?;
    // ✅ Use Params for Argon2 configuration
    let params =
        Params::new(65536, 3, 1, None).map_err(|e| format!("Invalid Argon2 parameters: {}", e))?;
    let derived_key = argon2
        .hash_password_customized(key.as_bytes(), None, None, params, &salt_string)
        .map_err(|e| format!("Argon2 hashing error: {}", e))?
        .hash
        .ok_or("Missing hash result")?
        .as_bytes()
        .to_vec();
    let plaintext = fs::read_to_string(".env")?;
    let aes_key = Aes256Gcm::new_from_slice(&derived_key).map_err(|_| "Invalid derived AES key")?;
    let mut nonce_bytes = [0u8; 12];
    let _ = OsRng.try_fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let encrypted_data = aes_key
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|e| format!("Encryption failed: {}", e))?;
    let mut output_file = File::create("env.enc")?;
    write_with_length(&mut output_file, &salt)?;
    write_with_length(&mut output_file, &nonce_bytes)?;
    write_with_length(&mut output_file, &encrypted_data)?;
    println!("Encryption successful. Output written to 'env.enc'");
    Ok(())
}
