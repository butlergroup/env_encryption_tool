## Version 0.9.21 

#### New Features


#### Improvements


#### Fixes


---

## Version 0.9.20 (04-08-2026)

#### New Features


#### Improvements
- bump tokio from 1.51.0 to 1.51.1

#### Fixes


---

## Version 0.9.19 (04-03-2026)

#### New Features


#### Improvements
- bump tokio from 1.50.0 to 1.51.0

#### Fixes


---

## Version 0.9.18 (03-30-2026)

#### New Features


#### Improvements
- bump hkdf from 0.12.4 to 0.13.0
- bump sha2 from 0.10.9 to 0.11.0

#### Fixes


---

## Version 0.9.17 (03-15-2026)

updated dependency versions
corrected usage of std::env::var to env::var in encrypt_envs.rs
added repository info to publish crate to crates.io
added/optimized workflows and added badges to README.md

---

## Version 0.9.16 (03-10-2026)

updated dependency versions
slight code modifications to correct build errors with new rand crate version
modified workflow/actions settings to address concurrent runs and appropriate scheduling

---

## Version 0.9.15 (02-03-2026)

Fixed an issue with env variables being processed correctly
Revised code/logic for greater cryptographic strength

---

## Version 0.9.14 (02-03-2026)

Updated dependency/crate versions
Added patch settings to Cargo.toml to resolve CVE-2026-25541 as well as dependency conflicts
Switched from the rand_core crate to the rand crate to maintain existing project code

---

## Version 0.9.13 (Oct 22, 2025)

Further refinements to the testing code for compatibility with Miri

---

## Version 0.9.12 (Oct 20, 2025)

Modified test code for compatibility with Miri; forked the paste crate to resolve RUSTSEC-2024-0436

---

## Version 0.9.11 (Oct 16, 2025)

Updated package versions in Cargo.toml

---

## Version 0.9.10 (Jun 29, 2025)

Replaced aes-gcm crate/algorithm with pqcrypto crate/algorithms to achieve Post-Quantum cryptography safety. Unit tests and production tests pass.

---

## Version 0.9.9 (May 31, 2025)

Reordered project code for unit testing. Manual and automated tests are passing.

---

## Version 0.9.8 (May 30, 2025)

Github-related changes (housekeeping) only - no code changes

---

## Version 0.9.7 (May 27, 2025)

Cleaned up comments; modified decrypt_config function to decrypt_env_vars

---

## Version 0.9.6 (May 23, 2025)

Modified output filename for compatibility with Windows copy/robocopy tools

---

## Version 0.9.5 (Apr 7, 2025)

Updated package versions

---

## Version 0.9.4 (Feb 23, 2025)

Added "once_cell" crate for static value handling
Modified environment variable handling to use a HashMap instead of the built-in env::set_var function
Added helper functions in decrypt_config.rs that can be imported into .rs files to retrieve environment variable values

---

## Version 0.9.3 (Feb 23, 2025)

Upgraded Rust edition from 2021 to 2024
Updated versions of several dependent crates
Added "env" crate to call "set_var" safely

---

## Version 0.9.2 (Feb 10, 2025)

Reverted encryption key character length modification as it produced an error

---

## Version 0.9.1 (Feb 9, 2025)

Added salt function
Added key hashing with Argon2
Reconfigured code to support keys of any length and AES-GCM to accept only the first 32 characters of the key