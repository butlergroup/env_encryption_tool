use argon2::{Argon2, Params, PasswordHasher, password_hash::SaltString};
use pqcrypto::kem::mlkem1024::*;
use pqcrypto_traits::kem::{Ciphertext, PublicKey, SecretKey, SharedSecret};
use rand_core::{OsRng, TryRngCore};
use std::error::Error;
use std::fs::{self, File};
use std::io::Write;

// Generate a random alphanumeric salt
fn generate_salt() -> Vec<u8> {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut salt = [0u8; 16];
    let _ = OsRng.try_fill_bytes(&mut salt);
    salt.iter()
        .map(|&b| CHARSET[(b as usize) % CHARSET.len()])
        .collect()
}

// Write a binary blob prefixed with its length
fn write_with_length(file: &mut File, data: &[u8]) -> std::io::Result<()> {
    let len = (data.len() as u32).to_be_bytes();
    file.write_all(&len)?;
    file.write_all(data)?;
    Ok(())
}

// Simple XOR encryption with a repeating key
fn xor_encrypt(data: &[u8], key: &[u8]) -> Vec<u8> {
    data.iter()
        .enumerate()
        .map(|(i, b)| b ^ key[i % key.len()])
        .collect()
}

// Encrypts `.env` and outputs `env.enc`
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
    // Kyber KEM keypair and encapsulation
    let (pk, sk) = keypair();
    let (shared_secret, kem_ct) = encapsulate(&pk);
    // Encrypt .env contents using shared secret
    let plaintext = fs::read_to_string(".env")?;
    let encrypted_env = xor_encrypt(plaintext.as_bytes(), shared_secret.as_bytes());
    // Encrypt the Kyber private key with Argon2-derived password key
    let encrypted_sk = xor_encrypt(sk.as_bytes(), &derived_key);
    // Write everything to the output file in a structured format
    let mut output_file = File::create("env.enc")?;
    write_with_length(&mut output_file, &salt)?;
    write_with_length(&mut output_file, pk.as_bytes())?;
    write_with_length(&mut output_file, kem_ct.as_bytes())?;
    write_with_length(&mut output_file, &encrypted_sk)?;
    write_with_length(&mut output_file, &encrypted_env)?;
    println!("PQ-safe encryption complete. Output written to 'env.enc'");
    Ok(())
}
