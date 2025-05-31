fn main() {
    if let Err(e) = env_encryption_tool::encrypt_envs::encrypt_env_file() {
        eprintln!("Encryption failed: {}", e);
    }
}