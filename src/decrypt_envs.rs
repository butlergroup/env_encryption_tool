use argon2::{Argon2, Params};
use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{Aead, KeyInit},
};
use env;
use hkdf::Hkdf;
use log::{error, info};
use once_cell::sync::Lazy;
use pqcrypto::kem::mlkem1024::*;
use pqcrypto_traits::kem::{Ciphertext, PublicKey, SecretKey, SharedSecret};
use sha2::Sha256;
use std::collections::HashMap;
use std::error::Error;
use std::fs;
use std::io::Read;
use std::sync::Mutex;
use zeroize::Zeroize;

// Function to read data with length prefix
fn read_with_length(file: &mut &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut len_buf = [0u8; 4];
    file.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut buffer = vec![0u8; len];
    file.read_exact(&mut buffer)?;
    Ok(buffer)
}

// Error handling helper
fn boxed_err<E: std::fmt::Display>(e: E) -> Box<dyn Error> {
    format!("{}", e).into()
}

// Instantiate a global HashMap to hold environment variables
pub static ENV_VARS: Lazy<Mutex<HashMap<String, String>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

// Store an environment variable in memory
pub fn set_env_var(key: &str, value: &str) {
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
    let pk_bytes = read_with_length(&mut cursor)?;
    let kem_ct_bytes = read_with_length(&mut cursor)?;
    let nonce_bytes = read_with_length(&mut cursor)?;
    let wrapped_sk = read_with_length(&mut cursor)?;
    let encrypted_env = read_with_length(&mut cursor)?;
    // ✅ Use Params for Argon2 configuration
    let params = Params::new(524288, 4, 1, Some(32))
        .map_err(|e| format!("Invalid Argon2 parameters: {}", e))?;
    // Derive key using Argon2
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut derived_key = vec![0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), &salt, &mut derived_key)
        .map_err(boxed_err)?;
    // Decrypt private key
    let mut sk_bytes: Vec<u8> = wrapped_sk
        .iter()
        .zip(derived_key.iter().cycle())
        .map(|(a, b)| a ^ b)
        .collect();
    derived_key.zeroize();
    let sk = SecretKey::from_bytes(&sk_bytes).map_err(boxed_err)?;
    sk_bytes.zeroize();
    // ---------- Public Key Verification ----------
    let pk = PublicKey::from_bytes(&pk_bytes).map_err(boxed_err)?;
    // Re-encapsulate test ciphertext using stored public key
    let (test_ss, test_ct) = encapsulate(&pk);
    // Attempt decapsulation using unwrapped secret key
    let verify_ss = decapsulate(&test_ct, &sk);
    // Compare secrets
    if test_ss.as_bytes() != verify_ss.as_bytes() {
        return Err(
            "Public/Private key mismatch — possible tampering or incorrect password".into(),
        );
    }
    // Reconstruct ciphertext and public key
    let kem_ct = Ciphertext::from_bytes(&kem_ct_bytes)?;
    let shared_secret = decapsulate(&kem_ct, &sk);
    // HKDF
    let hk = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
    let mut sym_key = [0u8; 32];
    hk.expand(b"env encryption", &mut sym_key)
        .map_err(boxed_err)?;
    // Derive AEAD key
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&sym_key));
    sym_key.zeroize();
    let nonce = Nonce::from_slice(&nonce_bytes);
    let decrypted_env = cipher
        .decrypt(nonce, encrypted_env.as_ref())
        .map_err(boxed_err)?;
    let mut decrypted_string = String::from_utf8(decrypted_env)?;
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
    decrypted_string.zeroize();
    Ok(())
}
