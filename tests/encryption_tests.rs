use env;
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

// Use decrypt logic from your main code
use env_encryption_tool::decrypt_envs::{decrypt_env_vars, get_env_var};

// Global setup
static EXPECTED_VARS: Lazy<Mutex<HashMap<&str, &str>>> = Lazy::new(|| {
    let mut map = HashMap::new();
    map.insert("TEST_KEY", "test_value");
    map.insert("ANOTHER_KEY", "1234");
    Mutex::new(map)
});

fn project_root() -> PathBuf {
    // Move from /tests/encryption_tests.rs to root by going one level up
    let mut dir = env::current_dir().expect("Failed to get current directory");
    if dir.ends_with("tests") {
        dir.pop(); // go up to root
    }
    dir
}

fn write_sample_env() {
    let mut env_path = project_root();
    env_path.push(".env");
    let mut file = File::create(env_path).expect("Failed to create .env in root");
    writeln!(file, "TEST_KEY=test_value").unwrap();
    writeln!(file, "ANOTHER_KEY=1234").unwrap();
}

fn cleanup_env_files() {
    let mut env_path = project_root();
    env_path.push(".env");
    if env_path.exists() {
        let _ = std::fs::remove_file(&env_path);
    }
    let mut enc_path = project_root();
    enc_path.push("env.enc");
    if enc_path.exists() {
        let _ = std::fs::remove_file(&enc_path);
    }
}

#[test]
fn test_encrypt_and_decrypt_env_file() {
    // Ensure consistent key
    let key = "12345678901234567890123456789012"; // 32 chars
    let _ = env::set_var("DECRYPTION_KEY", key);
    // Create .env file in root dir
    write_sample_env();
    // Encrypt .env
    let encrypt_result = env_encryption_tool::encrypt_envs::encrypt_env_file();
    assert!(
        encrypt_result.is_ok(),
        "Encryption failed: {:?}",
        encrypt_result.err()
    );
    // Decrypt .env.enc
    let rt = tokio::runtime::Runtime::new().unwrap();
    let result = rt.block_on(decrypt_env_vars());
    assert!(result.is_ok(), "Decryption failed: {:?}", result.err());
    // Verify environment values
    let expected = EXPECTED_VARS.lock().unwrap();
    for (&key, &val) in expected.iter() {
        let actual = get_env_var(key).unwrap_or_else(|| "MISSING".to_string());
        assert_eq!(actual, val, "Mismatch for key '{}'", key);
    }
    // ✅ Clean up .env and env.enc after test
    cleanup_env_files();
}
