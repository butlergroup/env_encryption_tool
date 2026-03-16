use argon2::{Argon2, Params};
use chacha20poly1305::{
    AeadCore, ChaCha20Poly1305, Key,
    aead::{Aead, KeyInit, OsRng as ChaChaOsRng},
};
use hkdf::Hkdf;
use pqcrypto::kem::mlkem1024::*;
use pqcrypto_traits::kem::{Ciphertext, PublicKey, SecretKey, SharedSecret};
use rand::{TryRng, rngs::SysRng};
use sha2::Sha256;
use std::error::Error;
use std::fs::{self, File};
use std::io::Write;
use zeroize::Zeroize;

// Generate a random alphanumeric salt
fn generate_salt() -> Vec<u8> {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut salt = [0u8; 16];
    let _ = SysRng.try_fill_bytes(&mut salt);
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

// Error handling helper
fn boxed_err<E: std::fmt::Display>(e: E) -> Box<dyn Error> {
    format!("{}", e).into()
}

// Encrypts `.env` and outputs `env.enc`
pub fn encrypt_env_file() -> Result<(), Box<dyn Error>> {
    let mut salt = generate_salt();
    let key = env::var("DECRYPTION_KEY")
        .map_err(|_| "Missing DECRYPTION_KEY environment variable")?;
    if key.len() != 32 {
        return Err("DECRYPTION_KEY must be exactly 32 characters long".into());
    }
    // ✅ Use Params for Argon2 configuration
    let params = Params::new(524288, 4, 1, Some(32))
        .map_err(|e| format!("Invalid Argon2 parameters: {}", e))?;
    // Derive key using Argon2
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut derived_key = vec![0u8; 32];
    argon2
        .hash_password_into(key.as_bytes(), &salt, &mut derived_key)
        .map_err(boxed_err)?;
    // Kyber KEM keypair and encapsulation
    let (pk, sk) = keypair();
    let (shared_secret, kem_ct) = encapsulate(&pk);
    let mut wrapped_sk: Vec<u8> = sk
        .as_bytes()
        .iter()
        .zip(derived_key.iter().cycle())
        .map(|(a, b)| a ^ b)
        .collect();
    derived_key.zeroize();
    // Derive AEAD key
    let hk = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
    let mut sym_key = [0u8; 32];
    hk.expand(b"env encryption", &mut sym_key)
        .map_err(boxed_err)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&sym_key));
    sym_key.zeroize();
    // Generate nonce
    let mut nonce = ChaCha20Poly1305::generate_nonce(&mut ChaChaOsRng);
    // Encrypt .env contents using shared secret
    let plaintext = fs::read_to_string(".env")?;
    let mut encrypted_env = cipher
        .encrypt(&nonce, plaintext.as_bytes())
        .map_err(boxed_err)?;
    // Write everything to the output file in a structured format
    let mut output_file = File::create("env.enc")?;
    write_with_length(&mut output_file, &salt)?;
    write_with_length(&mut output_file, pk.as_bytes())?;
    write_with_length(&mut output_file, kem_ct.as_bytes())?;
    write_with_length(&mut output_file, nonce.as_slice())?;
    write_with_length(&mut output_file, &wrapped_sk)?;
    write_with_length(&mut output_file, &encrypted_env)?;
    println!("PQ-safe encryption complete. Output written to 'env.enc'");
    salt.zeroize();
    nonce.zeroize();
    wrapped_sk.zeroize();
    encrypted_env.zeroize();
    Ok(())
}
