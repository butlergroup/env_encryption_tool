use argon2::{Argon2, Params, PasswordHasher, password_hash::SaltString};
use env;
use log::{error, info};
use once_cell::sync::Lazy;
use pqcrypto::kem::mlkem1024::*;
use pqcrypto_traits::kem::{Ciphertext, SecretKey, SharedSecret};
use std::collections::HashMap;
use std::error::Error;
use std::fs;
use std::io::Read;
use std::sync::Mutex;

// Function to read data with length prefix
fn read_with_length(file: &mut &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut len_buf = [0u8; 4];
    file.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut buffer = vec![0u8; len];
    file.read_exact(&mut buffer)?;
    Ok(buffer)
}

// XOR decryption with repeating key
fn xor_decrypt(data: &[u8], key: &[u8]) -> Vec<u8> {
    data.iter()
        .enumerate()
        .map(|(i, b)| b ^ key[i % key.len()])
        .collect()
}

// Instantiate a global HashMap to hold environment variables
pub static ENV_VARS: Lazy<Mutex<HashMap<String, String>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

// Store an environment variable in memory
fn set_env_var(key: &str, value: &str) {
    let mut env_vars = ENV_VARS.lock().unwrap(); // ✅ Lock synchronously
    env_vars.insert(key.to_string(), value.to_string()); // ✅ Insert into HashMap
}

// Retrieve an environment variable from memory
pub fn get_env_var(key: &str) -> Option<String> {
    let env_vars = ENV_VARS.lock().unwrap(); // ✅ Lock synchronously
    env_vars.get(key).cloned() // ✅ Get value from HashMap
}

// 🔓 Decrypts env.enc and loads key-value pairs into memory
pub async fn decrypt_env_vars() -> Result<(), Box<dyn Error>> {
    info!("Starting PQ-safe decryption process");
    let password = env::var("DECRYPTION_KEY").expect("DECRYPTION_KEY environment variable not set");
    if password.len() != 32 {
        return Err("DECRYPTION_KEY must be exactly 32 characters long".into());
    }
    // Read entire env.enc file
    let file_content = fs::read("env.enc")?;
    let mut cursor = &file_content[..];
    // Read fields
    let salt = read_with_length(&mut cursor)?;
    let _pk_bytes = read_with_length(&mut cursor)?;
    let kem_ct_bytes = read_with_length(&mut cursor)?;
    let encrypted_sk = read_with_length(&mut cursor)?;
    let encrypted_env = read_with_length(&mut cursor)?;
    // Derive key using Argon2
    let salt_string =
        SaltString::encode_b64(&salt).map_err(|e| format!("Invalid salt encoding: {}", e))?;
    let argon2 = Argon2::default();
    let params =
        Params::new(65536, 3, 1, None).map_err(|e| format!("Invalid Argon2 parameters: {}", e))?;
    let derived_key = argon2
        .hash_password_customized(password.as_bytes(), None, None, params, &salt_string)
        .map_err(|e| format!("Argon2 hashing error: {}", e))?
        .hash
        .ok_or("Missing hash result")?
        .as_bytes()
        .to_vec();
    // Decrypt private key
    let sk_bytes = xor_decrypt(&encrypted_sk, &derived_key);
    let sk = SecretKey::from_bytes(&sk_bytes)?;
    // Reconstruct ciphertext and public key
    let kem_ct = Ciphertext::from_bytes(&kem_ct_bytes)?;
    let shared_secret = decapsulate(&kem_ct, &sk);
    let decrypted_env = xor_decrypt(&encrypted_env, shared_secret.as_bytes());
    let decrypted_string = String::from_utf8(decrypted_env)?;
    // Parse environment lines and populate in-memory store
    for line in decrypted_string.lines() {
        if !line.is_empty() {
            let mut parts = line.splitn(2, '=');
            let key = parts.next().unwrap_or("").trim();
            let mut value = parts.next().unwrap_or("").trim().to_string();
            if value.starts_with('"') && value.ends_with('"') {
                value = value[1..value.len() - 1].to_string();
            }
            if !key.is_empty() && !value.is_empty() {
                info!("Setting env: {} = {}", key, value);
                set_env_var(key, &value);
            } else {
                error!("Invalid env entry: {} = {}", key, value);
            }
        }
    }
    info!("Decryption complete. Environment variables are in memory.");
    Ok(())
}
