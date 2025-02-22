# <h1 align="center"> Silent Time-lock Encryption Blueprint 🔐 </h1>

A decentralized threshold encryption service built on Tangle Network that enables secure time-locked data encryption and decryption. It uses the silent threshold ecnryption research paper [Silent Threshold Encryption ePrint:2024/263](https://eprint.iacr.org/2024/263) by Sanjam Garg, Dimitris Kolonelos, and Mingyuan Wang.

The innovative aspect of Silent Threshold Encryption is that it allows for threshold decryption services without any interactive setup. The scheme can be used to create timelock encryption as well, which is useful for a variety of use cases such as random number generation, verifiable delay functions, and more.

## 🎯 Overview

This Blueprint implements a threshold encryption service where:

- Multiple operators collectively manage encrypted data
- Users can encrypt data that requires a threshold of operators to decrypt
- Decryption requests are processed through secure multi-party computation
- Built using BN254 elliptic curve cryptography and silent threshold encryption

## 🚀 Features

- **Threshold Decryption**: Requires `t-of-n` operators to collaborate for decryption
- **Secure Key Management**: Each operator maintains their own secret key
- **On-chain Coordination**: Decryption requests and operator registration handled via smart contracts
- **Asynchronous Protocol**: Uses Tokio for efficient async communication between operators
- **Robust Error Handling**: Comprehensive error management for cryptographic operations

## 📋 Prerequisites

- [Rust](https://www.rust-lang.org/tools/install)
- [Forge](https://getfoundry.sh)
- [Tangle](https://github.com/tangle-network/tangle)
- [cargo-tangle](https://crates.io/crates/cargo-tangle)

## 🛠️ Setup

1. Install the Tangle CLI:

```bash
cargo install cargo-tangle --git https://github.com/tangle-network/gadget.git --force
```

2. Create a new project:

```bash
cargo tangle blueprint create --name silent-timelock
```

## 🔒 Security

- Uses BN254 elliptic curve for efficient pairing-based cryptography
- Implements secure multi-party computation for threshold decryption

## 📚 Documentation

For detailed documentation on the cryptographic protocols and service architecture, please visit:
[Tangle Documentation](https://docs.tangle.tools/developers/blueprints)

## 📄 License

Licensed under either:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

## 🤝 Contributing

Contributions welcome! Please feel free to submit a Pull Request.
