# SecureVault 🔐 - Enterprise PKI Edition

**SecureVault** is an enterprise-grade, zero-trust local file and directory encryption utility. Built with Python, it utilizes authenticated AES-256-GCM cryptography and a robust streaming architecture to secure anything from small text files to massive 8+ GB media archives without exhausting system memory.

This upgraded PKI Edition introduces **Hybrid RSA-4096 Asymmetric Sharing**, allowing users to securely exchange encrypted packages across untrusted networks using public/private key pairs.

---

## ✨ Key Features

* **Asymmetric Sharing (Hybrid RSA + AES):** Securely share files with other users. The system generates a throwaway AES key to quickly lock massive files, then wraps that key in an unbreakable RSA-4096 envelope using the recipient's Public Key.
* **Authenticated Encryption (AES-256-GCM):** Provides both strict confidentiality and cryptographic integrity. If an encrypted file is tampered with by even a single bit, the GCM authentication tag verification will fail, aborting decryption to protect against malicious modifications.
* **Infinite File Streaming:** Bypasses standard memory limitations by piping data in discrete 64 KB memory chunks. Easily handles multi-gigabyte files (like 8 GB movies) with a flat ~10 MB RAM footprint.
* **The "Dead Man's Switch":** Actively defends against offline brute-force attacks. If a user enters an incorrect password **5 consecutive times**, the system automatically triggers a secure shredding sequence, permanently destroying the locked file.
* **Directory Archiving:** Automatically bundles entire nested folder structures into temporary `.zip` archives before encryption to mask individual filenames, folder hierarchies, and file sizes from metadata analysis.
* **Anti-Forensics Secure Shredder:** Features an optional multi-pass cryptographic wipe (`os.urandom`) that overwrites original unencrypted files at the physical disk-sector level before deletion, preventing data recovery via forensic tools.
* **Dynamic GUI (PyQt6):** A multi-threaded, asynchronous desktop interface that never freezes. Automatically adapts to the host operating system's native Light/Dark theme registry settings.

---

## 🏗️ Technical Architecture

### 1. Symmetric Cryptography (Local Engine)

* **Key Derivation (KDF):** Passwords are never stored. The system derives a 256-bit key using **PBKDF2HMAC** (SHA-256) over 480,000 iterations, salted with 16 bytes of cryptographically secure random data.
* **Storage Layout:** `[16B Salt] + [12B Nonce] + [N-Bytes Ciphertext Stream] + [16B GCM Authentication Tag]`

### 2. Asymmetric Cryptography (Sharing Engine)

* **Key Generation:** 4096-bit RSA Keypairs.
* **Padding Algorithm:** OAEP (Optimal Asymmetric Encryption Padding) using MGF1 and SHA-256.
* **Storage Layout:** `[4B RSA Key Length] + [RSA-Encrypted AES Key] + [12B Nonce] + [N-Bytes Ciphertext Stream] + [16B GCM Authentication Tag]`

---

## 🚀 Getting Started

### Prerequisites

Ensure you have Python 3.10+ installed.

1. Clone the repository:

   ```bash
   git clone https://github.com/AKM7622/SecureVault.git
   cd SecureVault
   ```

2. Create a virtual environment and install the required dependencies:

   ```bash
   python -m venv .venv
   .venv\Scripts\activate  # On Windows
   source .venv/bin/activate # On Linux/macOS
   pip install -r requirements.txt
   ```

### Running the Application

To launch the graphical interface from the source code:

```bash
python gui.py
```

---

## 📖 Usage Guide

### Local Encryption & Decryption

1. **To Lock:** Navigate to the **Local Encrypt** tab, select your target file/folder, enter a Master Password, and click **LOCAL LOCK**. Use the shredder option to permanently destroy the original file.
2. **To Unlock:** Navigate to the **Local Decrypt** tab, select the `.enc` archive, and enter your password. *(Warning: 5 incorrect attempts triggers the Dead Man's Switch!)*

### Asymmetric Sharing (RSA)

The **Asymmetric Sharing** tab allows you to securely send and receive files without ever sharing a password.

1. **Generate Keys:** Click **Generate New RSA-4096 Keypair**. This creates a Public Key (safe to share) and a Private Key (keep this completely secret).
2. **Package for Sharing:** Select a target file and the **recipient's Public Key**. The system will lock the file so that *only* the recipient can open it. Send them the resulting `.rsa.enc` file.
3. **Unlock Received Package:** If someone sends you an `.rsa.enc` file, select it alongside your **Private Key** to unlock the contents.

---

## ⚠️ Disclaimer

*This tool was developed as an advanced academic project for educational purposes. While it utilizes industry-standard cryptographic primitives, it has not undergone an independent third-party security audit. The developers are not responsible for any permanent data loss resulting from forgotten passwords, lost Private Keys, or triggered Dead Man's Switches. Use at your own risk.*

---
**Developed by:** Preeti  
**License:** MIT License
