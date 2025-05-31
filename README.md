## env_encryption_tool :copyright: Project Goals & Info

**Purpose**: the goal for this project is to encrypt .env files for a given Rust application and store them in an encrypted state, then decrypt them at runtime using an OS-based environment variable and pass them to the application. This requires any potential/illicit attacker to breach the operating system's security and access its environment variables before any application-level environment variables can be compromised. 

*Disclaimer:* this project is stable and can be used in production environments, but SLA-based support won't be offered until we're at v1.0 and/or sponsored. :bowtie:

## Installation Instructions

1. [Install Rust](https://rustup.rs/) :earth_americas:
2. Clone/fork the env_encryption_tool repo :zap:
3. Modify the encryption key in main.rs to your desired content :lock:
4. Run "cargo build --release" - this outputs a binary in the target/release folder :sparkles:
5. Run the binary in the same folder as your .env file - this outputs a env.enc file :confetti_ball:
6. Integrate the included decrypt_config.rs file and its crates into your Rust project :star:
7. Set an OS-level environment variable named "DECRYPTION_KEY" ( :earth_americas: [for Linux](https://stackoverflow.com/questions/45502996/how-to-set-environment-variable-in-linux-permanently), :earth_africa: [for Windows](https://phoenixnap.com/kb/windows-set-environment-variable), :earth_asia: [for MacOS](https://stackoverflow.com/questions/65597552/how-exactly-to-set-up-and-use-environment-variables-on-a-mac)) to the same value you placed in main.rs. 
8. Copy the env.enc file to the same folder your Rust binary runs in and voila! You have encrypted environment variables provided to your application at runtime. :tada:

## Contributing

We welcome contributions from the community! A simple guide to get started:

1. Fork the repository to your Github account (a.k.a create a branch). 
2. Clone your forked repo/branch to your favorite IDE (VS Code is our editor of choice) and make changes (or use the command-line: git checkout -b feature/your-feature).
3. **Thoroughly test and debug your changes**, then commit and push them to your forked repo/branch.
4. Open a pull request to have your changes reviewed and reintegrated into the main branch.

Contributors are strongly encouraged to read our [CONTRIBUTING.md](https://github.com/butlergroup/env_encryption_tool/blob/main/CONTRIBUTING.md) file before opening a pull request. 

## License

env_encryption_tool is licensed under the AGPL-3.0 license, making it free to use, modify, and distribute as long as the source code remains open-source. **Using a modified version of this software without disclosing its source code is not in compliance with the AGPL-3.0 license.**

## Acknowledgments

Special thanks to contributors, open-source enthusiasts, and supporters of env_encryption_tool's vision.

## Terms of Service

Please read our [Terms of Service](https://github.com/butlergroup/env_encryption_tool/blob/main/terms-of-service.md) before using our software. Violators of these Terms are not supported by the community or contributors.

## Privacy Policy

Please also read our [Privacy Policy](https://github.com/butlergroup/env_encryption_tool/blob/main/privacy-policy.md) to understand how we handle your personal information. 

## Contact

Have questions or suggestions? Reach out to us at welcome@butlergroup.net. Thank you and happy coding! :)
