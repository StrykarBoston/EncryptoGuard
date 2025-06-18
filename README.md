# EncryptoGuard: Secure Message and File Encryption/Decryption Tool

![Python](https://img.shields.io/badge/Python-3.x-blue.svg)
![Tkinter](https://img.shields.io/badge/GUI-Tkinter-green.svg)
![Cryptography](https://img.shields.io/badge/Security-Cryptography-red.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)

EncryptoGuard is a robust and user-friendly desktop application built with Python and Tkinter, designed for secure encryption and decryption of both messages and files. Leveraging the powerful `cryptography` library, it implements AES-256-GCM (Authenticated Encryption with Associated Data) to ensure not only confidentiality but also integrity and authenticity of your data.

## ✨ Features

- **Message Encryption/Decryption:**
    - Securely encrypt and decrypt text messages.
    - Utilizes AES-256-GCM for strong cryptographic protection.
    - Incorporates PBKDF2HMAC with SHA256 and high iteration counts for robust key derivation from passwords.
    - Password visibility toggle for convenience.
    - Copy result to clipboard functionality.
- **File Encryption/Decryption:**
    - Encrypt and decrypt entire files with AES-256-GCM.
    - Protects against tampering using Message Authentication Code (MAC) for integrity verification.
    - Includes robust input validation for file paths to prevent directory traversal and symlink attacks.
    - Enforces file size limits to prevent Denial of Service (DoS) attacks (currently 100MB).
    - Encrypted files are saved in a dedicated `encrypted_files` directory for better organization and security.
- **Enhanced Security Measures:**
    - **Strong Password Policy:** Enforces minimum length (12 characters) and requires a mix of uppercase, lowercase, numbers, and special characters.
    - **Secure Key Derivation:** Uses PBKDF2HMAC with a high number of iterations for password-based key generation.
    - **Random Salts and IVs:** Generates unique salts and Initialization Vectors (IVs) for each encryption operation to enhance security.
    - **Secure Memory Handling:** Attempts to clear sensitive data (keys, passwords, plaintexts) from memory immediately after use.
    - **Comprehensive Error Handling:** Provides user-friendly error messages while logging detailed technical errors for debugging.
    - **Secure Logging:** Implements logging to a file (`encryption_tool.log`) to record application events and potential security warnings.
- **User-Friendly Interface:**
    - Intuitive Tkinter-based GUI.
    - Clear separation of message and file operations.
    - "Reset All Fields" button with confirmation for quick cleanup.
    - Dynamic radio button styling for better visual feedback.

## 🚀 Installation

To run EncryptoGuard, you need Python 3.x installed on your system.

1.  **Clone the Repository:**
    ```bash
    git clone https://github.com/StrykarBoston/EncryptoGuard.git
    cd EncryptoGuard
    ```

2.  **Install Dependencies:**
    EncryptoGuard relies on the `cryptography` library. You can install it using pip:
    ```bash
    pip install cryptography
    ```

## 🛠️ Usage

1.  **Run the Application:**
    ```bash
    python EncryptoGuard.py
    ```

![Task-1](https://github.com/user-attachments/assets/b2e95195-4b79-4dc4-8af8-32920ffeab83)


2.  **Using the Message Encryptor/Decryptor:**
    * Enter your message in the "Message:" text area.
    * Input a strong password in the "Password:" field. You can toggle its visibility using the "Show/Hide" button.
    * Select "Encrypt" or "Decrypt" using the radio buttons.
    * Click "Process Message".
    * A new window will display the encrypted/decrypted result, which you can copy to your clipboard.

3.  **Using the File Encryptor/Decryptor:**
    * Click "Browse" to select the file you wish to encrypt or decrypt.
    * Enter a strong password in the "Password:" field for file operations.
    * Select "Encrypt" or "Decrypt".
    * Click "Process File".
    * Encrypted files will be saved in a new directory named `encrypted_files/` in the same location as the script, with a `.enc` extension.
    * Decrypted files will have their `.enc` extension removed, or a `.dec` extension added if the original file didn't have `.enc`.

4.  **Resetting Fields:**
    * Click the "Reset All Fields" button to clear all input fields (message, password, file path) and sensitive data from memory.

## ⚠️ Security Considerations

While EncryptoGuard employs strong cryptographic practices and security measures, it's crucial to understand:

* **Password Strength:** The security of your encrypted data relies heavily on the strength and uniqueness of your chosen password. Always use long, complex, and unique passwords.
* **Password Management:** Never share your passwords. If you forget your password, your encrypted data cannot be recovered.
* **Physical Security:** Ensure the security of your system where the tool and encrypted files are stored.
* **Logging:** Be aware that the tool generates a `EncryptoGuard.log` file for operational logging. While sensitive content is not logged, general operational information is.

## 🤝 Contributing

Contributions are welcome! If you have suggestions for improvements, bug reports, or new features, please open an issue or submit a pull request.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
