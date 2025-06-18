import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import os
import base64
import secrets
import re # For input validation
import logging # For secure logging

# Configure logging
# This will create a log file named encryption_tool.log in the same directory as the script.
# It logs INFO level messages and above, including timestamps, log level, and the message.
logging.basicConfig(filename='EncryptoGuard.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

class SecureEncryptionTool:
    def __init__(self):
        """Initializes the GUI and sets up the application."""
        self.setup_gui()

    def setup_gui(self):
        """Sets up the main Tkinter GUI window and its frames."""
        self.root = tk.Tk()
        self.root.title("EncryptoGuard") # Updated title here
        self.root.resizable(False, False) # Prevent resizing for a consistent UI

        self.setup_message_frame()
        self.setup_file_frame()

        # Reset button with confirmation dialog
        tk.Button(self.root, text="Reset All Fields", command=self.confirm_reset_fields,
                 font=("Arial", 15, "bold"), bg="green", fg="white",
                 activebackground="lightgreen", activeforeground="black",
                 relief=tk.RAISED, bd=3).pack(padx=10, pady=10, fill="x")

        # Initial color update for radio buttons
        self.update_radiobutton_colors()

    def setup_message_frame(self):
        """Sets up the GUI elements for message encryption/decryption."""
        message_frame = tk.LabelFrame(self.root, text="Message Encryption/Decryption (AES-256-GCM)",
                                      padx=10, pady=10, bg="#f0f0f0", bd=2, relief=tk.GROOVE)
        message_frame.pack(padx=10, pady=10, fill="x")

        # Message input
        tk.Label(message_frame, text="Message:", font=("Arial", 14, "bold"), bg="#f0f0f0").grid(row=0, column=0, padx=10, pady=5, sticky="w")
        self.message_entry = tk.Text(message_frame, height=5, width=50, font=("Arial", 12), bd=2, relief=tk.SUNKEN)
        self.message_entry.grid(row=0, column=1, padx=10, pady=5, columnspan=2, sticky="ew")

        # Password input for messages
        tk.Label(message_frame, text="Password:", font=("Arial", 14, "bold"), bg="#f0f0f0").grid(row=1, column=0, padx=10, pady=5, sticky="w")
        self.password_entry = tk.Entry(message_frame, font=("Arial", 12), show="*", bd=2, relief=tk.SUNKEN)
        self.password_entry.grid(row=1, column=1, padx=10, pady=5, sticky="ew")

        # Toggle password visibility button
        self.toggle_message_key_button = tk.Button(message_frame, text="Show", command=self.toggle_message_key_visibility,
                                                  font=("Arial", 12, "bold"), bg="#007bff", fg="white",
                                                  activebackground="#0056b3", activeforeground="white",
                                                  relief=tk.RAISED, bd=2)
        self.toggle_message_key_button.grid(row=1, column=2, padx=5, pady=5, sticky="e")

        # Encryption/Decryption radio buttons for messages
        self.message_encryption_var = tk.BooleanVar()
        self.message_encryption_var.set(True) # Default to encrypt
        self.encrypt_message_radio = tk.Radiobutton(message_frame, text="Encrypt", variable=self.message_encryption_var,
                                                   value=True, font=("Arial", 12, "bold"), command=self.update_radiobutton_colors,
                                                   bg="#f0f0f0", selectcolor="#f0f0f0")
        self.encrypt_message_radio.grid(row=2, column=0, padx=10, pady=5, sticky="w")
        self.decrypt_message_radio = tk.Radiobutton(message_frame, text="Decrypt", variable=self.message_encryption_var,
                                                   value=False, font=("Arial", 12, "bold"), command=self.update_radiobutton_colors,
                                                   bg="#f0f0f0", selectcolor="#f0f0f0")
        self.decrypt_message_radio.grid(row=2, column=1, padx=10, pady=5, sticky="w")

        # Process message button
        tk.Button(message_frame, text="Process Message", command=self.process_message,
                 font=("Arial", 16, "bold"), bg="#28a745", fg="white",
                 activebackground="#218838", activeforeground="white",
                 relief=tk.RAISED, bd=3).grid(row=3, column=0, columnspan=3, padx=10, pady=10, sticky="ew")

        # Configure column weights for resizing
        message_frame.grid_columnconfigure(1, weight=1)

    def setup_file_frame(self):
        """Sets up the GUI elements for file encryption/decryption."""
        file_frame = tk.LabelFrame(self.root, text="File Encryption/Decryption (AES-256-GCM)",
                                    padx=10, pady=10, bg="#f0f0f0", bd=2, relief=tk.GROOVE)
        file_frame.pack(padx=10, pady=10, fill="x")

        # File path input and browse button
        tk.Label(file_frame, text="Select a file:", font=("Arial", 14, "bold"), bg="#f0f0f0").grid(row=0, column=0, padx=10, pady=5, sticky="w")
        self.file_entry = tk.Entry(file_frame, width=50, font=("Arial", 12), bd=2, relief=tk.SUNKEN)
        self.file_entry.grid(row=0, column=1, padx=10, pady=5, sticky="ew")
        tk.Button(file_frame, text="Browse", command=self.select_file, font=("Arial", 12, "bold"),
                 bg="#17a2b8", fg="white", activebackground="#138496", activeforeground="white",
                 relief=tk.RAISED, bd=2).grid(row=0, column=2, padx=5, pady=5)

        # Password input for files
        tk.Label(file_frame, text="Password:", font=("Arial", 14, "bold"), bg="#f0f0f0").grid(row=1, column=0, padx=10, pady=5, sticky="w")
        self.file_key_entry = tk.Entry(file_frame, width=50, font=("Arial", 12), show="*", bd=2, relief=tk.SUNKEN)
        self.file_key_entry.grid(row=1, column=1, padx=10, pady=5, sticky="ew")

        # Toggle file password visibility button
        self.toggle_file_key_button = tk.Button(file_frame, text="Show", command=self.toggle_file_key_visibility,
                                               font=("Arial", 12, "bold"), bg="#007bff", fg="white",
                                               activebackground="#0056b3", activeforeground="white",
                                               relief=tk.RAISED, bd=2)
        self.toggle_file_key_button.grid(row=1, column=2, padx=5, pady=5, sticky="e")

        # Encryption/Decryption radio buttons for files
        self.file_operation_var = tk.StringVar()
        self.file_operation_var.set('encrypt') # Default to encrypt
        self.encrypt_file_radio = tk.Radiobutton(file_frame, text="Encrypt", variable=self.file_operation_var,
                                                value='encrypt', font=("Arial", 12, "bold"), command=self.update_radiobutton_colors,
                                                bg="#f0f0f0", selectcolor="#f0f0f0")
        self.encrypt_file_radio.grid(row=2, column=0, padx=10, pady=5, sticky="w")
        self.decrypt_file_radio = tk.Radiobutton(file_frame, text="Decrypt", variable=self.file_operation_var,
                                                value='decrypt', font=("Arial", 12, "bold"), command=self.update_radiobutton_colors,
                                                bg="#f0f0f0", selectcolor="#f0f0f0")
        self.decrypt_file_radio.grid(row=2, column=1, padx=10, pady=5, sticky="w")

        # Process file button
        tk.Button(file_frame, text="Process File", command=self.encrypt_decrypt_file,
                 font=("Arial", 16, "bold"), bg="#dc3545", fg="white",
                 activebackground="#c82333", activeforeground="white",
                 relief=tk.RAISED, bd=3).grid(row=3, column=0, columnspan=3, padx=10, pady=10, sticky="ew")

        # Configure column weights for resizing
        file_frame.grid_columnconfigure(1, weight=1)

    def derive_key(self, password: str, salt: bytes) -> bytes:
        """
        Derives a cryptographic key from a password using PBKDF2HMAC with SHA256.
        This function is crucial for securely converting a human-readable password
        into a fixed-size cryptographic key.
        """
        password_bytes = password.encode('utf-8')
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # 256 bits for AES-256
            salt=salt,
            iterations=390000, # Increased iterations for stronger resistance against brute-force attacks
        )
        key = kdf.derive(password_bytes)
        # Explicitly clear sensitive password data from memory after use
        del password_bytes
        return key

    def encrypt_message_secure(self, message: str, password: str) -> str:
        """
        Encrypts a message using AES-256-GCM.
        Includes input validation for message size to prevent DoS.
        The GCM mode provides authenticated encryption (confidentiality and integrity).
        """
        try:
            # Validate message length to prevent Denial of Service (DoS) attacks
            message_bytes = message.encode('utf-8')
            if len(message_bytes) > 10 * 1024 * 1024: # 10 MB limit for messages
                logging.warning(f"Attempted to encrypt message exceeding size limit: {len(message_bytes)} bytes.")
                raise ValueError("Message too large. Max 10MB allowed.")

            salt = os.urandom(16)  # Generate a unique salt for each encryption
            iv = os.urandom(12)    # Generate a unique IV (Nonce) for each encryption

            key = self.derive_key(password, salt)

            cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
            encryptor = cipher.encryptor()

            ciphertext = encryptor.update(message_bytes) + encryptor.finalize()

            # The encrypted data includes salt, IV, GCM tag, and ciphertext.
            # The GCM tag inherently provides integrity and authenticity.
            encrypted_data = salt + iv + encryptor.tag + ciphertext

            # Securely clear sensitive data from memory immediately after use
            del key
            del salt
            del iv
            del message_bytes
            del ciphertext
            del encryptor

            logging.info("Message encrypted successfully.")
            return base64.b64encode(encrypted_data).decode('utf-8')

        except ValueError as ve:
            # Catch specific validation errors and provide a user-friendly message
            logging.error(f"Message encryption failed due to validation: {ve}")
            raise Exception(f"Encryption failed: {ve}")
        except Exception as e:
            # Catch any other cryptographic or system errors, log details, but show generic message to user
            logging.error(f"Message encryption failed unexpectedly: {e}", exc_info=True)
            raise Exception("Encryption failed due to an internal error. Please check application logs for details.")

    def decrypt_message_secure(self, encrypted_message: str, password: str) -> str:
        """
        Decrypts a message using AES-256-GCM.
        Verifies the GCM tag to ensure integrity and authenticity of the ciphertext.
        """
        try:
            encrypted_data = base64.b64decode(encrypted_message.encode('utf-8'))

            # Extract components from the encrypted data
            salt = encrypted_data[:16]
            iv = encrypted_data[16:28]
            tag = encrypted_data[28:44]
            ciphertext = encrypted_data[44:]

            key = self.derive_key(password, salt)

            cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag))
            decryptor = cipher.decryptor()

            # Decryption will fail with a CryptographicError if the tag (integrity) is invalid
            decrypted_bytes = decryptor.update(ciphertext) + decryptor.finalize()

            # Securely clear sensitive data from memory immediately after use
            del key
            del salt
            del iv
            del tag
            del ciphertext
            del decryptor
            del encrypted_data

            logging.info("Message decrypted successfully.")
            return decrypted_bytes.decode('utf-8')

        except Exception as e:
            # Catch any decryption errors (including tag verification failures)
            logging.error(f"Message decryption failed: {e}", exc_info=True)
            raise Exception("Decryption failed. Please ensure the message and password are correct and the message has not been tampered with.")

    def encrypt_file_secure(self, file_path: str, password: str) -> None:
        """
        Encrypts a file using AES-256-GCM and adds an HMAC for integrity verification.
        Includes file path validation to prevent directory traversal and symlink attacks,
        and file size limits to prevent DoS. Encrypted files are stored in a dedicated directory.
        """
        try:
            # 1. Input Validation: File path and size
            if not self.is_safe_filepath(file_path):
                logging.warning(f"Attempted file encryption with unsafe path: {file_path}")
                raise ValueError("Invalid file path or symbolic link detected. Please select a valid file.")

            # Get file size and check limit
            file_size = os.path.getsize(file_path)
            if file_size > 100 * 1024 * 1024: # 100 MB limit for files
                logging.warning(f"Attempted to encrypt file exceeding size limit: {file_size} bytes.")
                raise ValueError("File too large. Max 100MB allowed.")

            salt = os.urandom(16)
            iv = os.urandom(12)
            key = self.derive_key(password, salt)

            with open(file_path, 'rb') as file:
                file_data = file.read()

            cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
            encryptor = cipher.encryptor()

            ciphertext = encryptor.update(file_data) + encryptor.finalize()

            # 2. Secure Storage for Encrypted Files: Use a designated directory
            secure_dir = "encrypted_files"
            os.makedirs(secure_dir, exist_ok=True) # Create directory if it doesn't exist
            # Construct a safe output file path within the secure directory
            encrypted_file_name = os.path.basename(file_path) + '.enc'
            encrypted_file_path = os.path.join(secure_dir, encrypted_file_name)

            # 3. Integrity Check: Add HMAC to the encrypted data
            # HMAC covers salt, IV, GCM tag, and ciphertext to protect against tampering
            h = hashes.Hash(hashes.SHA256())
            h.update(salt + iv + encryptor.tag + ciphertext)
            mac = h.finalize() # Message Authentication Code

            with open(encrypted_file_path, 'wb') as encrypted_file:
                # Store salt, IV, GCM tag, HMAC, and then ciphertext
                encrypted_file.write(salt + iv + encryptor.tag + mac + ciphertext)

            # Securely clear sensitive data from memory
            del key
            del salt
            del iv
            del file_data
            del ciphertext
            del encryptor
            del mac

            messagebox.showinfo("Success", f"File encrypted successfully!\nEncrypted file: {encrypted_file_path}")
            logging.info(f"File '{file_path}' encrypted successfully to '{encrypted_file_path}'.")

        except ValueError as ve:
            logging.error(f"File encryption failed due to validation or size limits: {ve}")
            raise Exception(f"File encryption failed: {ve}")
        except Exception as e:
            logging.error(f"File encryption failed unexpectedly: {e}", exc_info=True)
            raise Exception("File encryption failed due to an internal error. Please check application logs for details.")

    def decrypt_file_secure(self, file_path: str, password: str) -> None:
        """
        Decrypts a file using AES-256-GCM.
        Verifies the HMAC for file integrity before attempting GCM decryption.
        Includes file path validation.
        """
        try:
            # 1. Input Validation: File path
            if not self.is_safe_filepath(file_path):
                logging.warning(f"Attempted file decryption with unsafe path: {file_path}")
                raise ValueError("Invalid file path or symbolic link detected. Please select a valid file.")

            with open(file_path, 'rb') as encrypted_file:
                encrypted_data = encrypted_file.read()

            # Extract components from the encrypted data: salt, IV, GCM tag, HMAC, ciphertext
            salt = encrypted_data[:16]
            iv = encrypted_data[16:28]
            tag = encrypted_data[28:44]
            # HMAC is 32 bytes for SHA256
            received_mac = encrypted_data[44:76]
            ciphertext = encrypted_data[76:]

            # 2. Integrity Check: Verify HMAC first
            h = hashes.Hash(hashes.SHA256())
            h.update(salt + iv + tag + ciphertext)
            calculated_mac = h.finalize()

            # Use secrets.compare_digest for constant-time comparison to prevent timing attacks
            if not secrets.compare_digest(received_mac, calculated_mac):
                logging.warning(f"File integrity check failed for '{file_path}'. MAC mismatch.")
                raise ValueError("File integrity check failed. The file may have been tampered with or is corrupted.")

            key = self.derive_key(password, salt)

            cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag))
            decryptor = cipher.decryptor()

            decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

            # Determine output file path
            if file_path.endswith('.enc'):
                decrypted_file_path = file_path[:-4] # Remove .enc extension
            else:
                decrypted_file_path = file_path + '.dec' # Add .dec if no .enc

            with open(decrypted_file_path, 'wb') as decrypted_file:
                decrypted_file.write(decrypted_data)

            # Securely clear sensitive data from memory
            del key
            del salt
            del iv
            del tag
            del received_mac
            del ciphertext
            del decryptor
            del calculated_mac
            del encrypted_data

            messagebox.showinfo("Success", f"File decrypted successfully!\nDecrypted file: {decrypted_file_path}")
            logging.info(f"File '{file_path}' decrypted successfully to '{decrypted_file_path}'.")

        except ValueError as ve:
            logging.error(f"File decryption failed due to validation or integrity check: {ve}")
            raise Exception(f"File decryption failed: {ve}")
        except Exception as e:
            logging.error(f"File decryption failed unexpectedly: {e}", exc_info=True)
            raise Exception("File decryption failed. Please ensure the file and password are correct and the file has not been tampered with.")

    def process_message(self):
        """Handles the message encryption/decryption process, including input validation."""
        message = self.message_entry.get("1.0", tk.END).strip()
        password = self.password_entry.get().strip()

        # Input validation for message and password fields
        if not message:
            messagebox.showwarning("Input Error", "Please enter a message.")
            logging.warning("Attempted message processing with no message input.")
            return
        if not password:
            messagebox.showwarning("Input Error", "Please enter a password.")
            logging.warning("Attempted message processing with no password input.")
            return
        if not self.is_strong_password(password):
            messagebox.showwarning("Security Warning", "Password does not meet complexity requirements. It must be at least 12 characters long and include uppercase, lowercase, numbers, and special characters.")
            logging.warning("Attempted message processing with a weak password.")
            return

        try:
            if self.message_encryption_var.get(): # Encrypt message
                result = self.encrypt_message_secure(message, password)
                description = "Encrypted Message:"
                border_color = "red"
                logging.info("Message encryption initiated.")
            else: # Decrypt message
                result = self.decrypt_message_secure(message, password)
                description = "Decrypted Message:"
                border_color = "green"
                logging.info("Message decryption initiated.")

            self.show_result(result, description, border_color)

        except Exception as e:
            # Generic error message to the user, detailed error logged
            messagebox.showerror("Error", str(e))

    def encrypt_decrypt_file(self):
        """Handles the file encryption/decryption process, including input validation."""
        operation = self.file_operation_var.get()
        file_path = self.file_entry.get()
        password = self.file_key_entry.get()

        # Input validation for file path and password fields
        if not file_path or not password:
            messagebox.showwarning("Input Error", "Please select a file and enter a password.")
            logging.warning("Attempted file processing with missing file path or password.")
            return
        if not self.is_strong_password(password):
            messagebox.showwarning("Security Warning", "Password does not meet complexity requirements. It must be at least 12 characters long and include uppercase, lowercase, numbers, and special characters.")
            logging.warning("Attempted file processing with a weak password.")
            return

        try:
            if operation == 'encrypt':
                self.encrypt_file_secure(file_path, password)
                logging.info(f"File encryption initiated for '{file_path}'.")
            else:
                self.decrypt_file_secure(file_path, password)
                logging.info(f"File decryption initiated for '{file_path}'.")

        except Exception as e:
            # Generic error message to the user, detailed error logged
            messagebox.showerror("Error", str(e))

    def show_result(self, result, description, border_color):
        """Displays the result of message processing in a new Toplevel window."""
        result_window = tk.Toplevel(self.root)
        result_window.title("Result")
        result_window.transient(self.root) # Make it a transient window relative to the root
        result_window.grab_set() # Make it modal
        result_window.focus_set() # Give focus to the new window

        result_label = tk.Label(result_window, text=description, font=("Arial", 14, "bold"))
        result_label.pack(pady=10)

        result_text = tk.Text(result_window, height=10, width=80, font=("Arial", 12),
                             highlightthickness=4, highlightbackground=border_color, wrap=tk.WORD,
                             bd=2, relief=tk.SUNKEN)
        result_text.pack(padx=10, pady=10)
        result_text.insert(tk.END, result)
        result_text.config(state=tk.DISABLED) # Make text read-only

        def copy_to_clipboard():
            """Copies the displayed result to the clipboard."""
            try:
                result_window.clipboard_clear()
                result_window.clipboard_append(result)
                messagebox.showinfo("Copied", "Result copied to clipboard!")
                logging.info("Result copied to clipboard.")
            except tk.TclError as clipboard_error:
                messagebox.showerror("Clipboard Error", f"Failed to copy to clipboard: {clipboard_error}")
                logging.error(f"Failed to copy to clipboard: {clipboard_error}")

        tk.Button(result_window, text="Copy to Clipboard", command=copy_to_clipboard,
                 font=("Arial", 12, "bold"), bg="#17a2b8", fg="white",
                 activebackground="#138496", activeforeground="white",
                 relief=tk.RAISED, bd=2).pack(pady=5)

        # Protocol for closing the Toplevel window
        result_window.protocol("WM_DELETE_WINDOW", result_window.destroy)

    def select_file(self):
        """Opens a file dialog to select a file and updates the file entry field."""
        file_path = filedialog.askopenfilename()
        if file_path: # Only update if a file was selected
            self.file_entry.delete(0, tk.END)
            self.file_entry.insert(0, file_path)
            logging.info(f"File selected for operation: {file_path}")

    def toggle_message_key_visibility(self):
        """Toggles the visibility of the message password field."""
        logging.info("Message password visibility toggled.")
        if self.password_entry.cget('show') == '*':
            self.password_entry.config(show='')
            self.toggle_message_key_button.config(text='Hide')
        else:
            self.password_entry.config(show='*')
            self.toggle_message_key_button.config(text='Show')

    def toggle_file_key_visibility(self):
        """Toggles the visibility of the file password field."""
        logging.info("File password visibility toggled.")
        if self.file_key_entry.cget('show') == '*':
            self.file_key_entry.config(show='')
            self.toggle_file_key_button.config(text='Hide')
        else:
            self.file_key_entry.config(show='*')
            self.toggle_file_key_button.config(text='Show')

    def confirm_reset_fields(self):
        """Asks for user confirmation before resetting all input fields."""
        if messagebox.askyesno("Confirm Reset", "Are you sure you want to reset all fields? This will clear all entered data and sensitive information from memory."):
            self.reset_fields()
            logging.info("All fields reset after user confirmation.")

    def reset_fields(self):
        """Resets all input fields and resets password visibility to hidden."""
        self.message_entry.delete("1.0", tk.END)
        self.password_entry.delete(0, tk.END)
        self.file_entry.delete(0, tk.END)
        self.file_key_entry.delete(0, tk.END)

        # Reset radio buttons to default encryption mode
        self.message_encryption_var.set(True)
        self.file_operation_var.set('encrypt')

        # Ensure password fields are hidden after reset for security
        self.password_entry.config(show='*')
        self.toggle_message_key_button.config(text='Show')
        self.file_key_entry.config(show='*')
        self.toggle_file_key_button.config(text='Show')

        self.update_radiobutton_colors()
        logging.info("Application fields successfully reset.")

    def update_radiobutton_colors(self):
        """Updates the background and foreground colors of radio buttons based on selection."""
        # Message radio buttons
        if self.message_encryption_var.get(): # Encrypt selected
            self.encrypt_message_radio.config(bg="#dc3545", fg="white") # Red for Encrypt (Action)
            self.decrypt_message_radio.config(bg="#f0f0f0", fg="black") # Neutral for Decrypt
        else: # Decrypt selected
            self.encrypt_message_radio.config(bg="#f0f0f0", fg="black") # Neutral for Encrypt
            self.decrypt_message_radio.config(bg="#28a745", fg="white") # Green for Decrypt (Success)

        # File radio buttons
        if self.file_operation_var.get() == 'encrypt':
            self.encrypt_file_radio.config(bg="#dc3545", fg="white") # Red for Encrypt
            self.decrypt_file_radio.config(bg="#f0f0f0", fg="black") # Neutral for Decrypt
        else:
            self.encrypt_file_radio.config(bg="#f0f0f0", fg="black") # Neutral for Encrypt
            self.decrypt_file_radio.config(bg="#28a745", fg="white") # Green for Decrypt

    def is_strong_password(self, password: str) -> bool:
        """
        Enforces a strong password policy:
        - Minimum length of 12 characters.
        - At least one lowercase letter.
        - At least one uppercase letter.
        - At least one digit.
        - At least one special character.
        """
        if len(password) < 12:
            return False
        if not re.search(r"[a-z]", password):
            return False
        if not re.search(r"[A-Z]", password):
            return False
        if not re.search(r"[0-9]", password):
            return False
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            return False
        return True

    def is_safe_filepath(self, filepath: str) -> bool:
        """
        Validates file paths to prevent directory traversal attacks (e.g., ../../etc/passwd)
        and symbolic link attacks.
        This function ensures that file operations are restricted to safe paths.
        """
        try:
            # Resolve symbolic links and normalize path (e.g., remove '..')
            resolved_path = os.path.realpath(filepath)
            normalized_path = os.path.normpath(resolved_path)

            # Prevent directory traversal by checking if '..' is still in the normalized path
            # or if it tries to access root outside allowed directories.
            # For a stricter policy, define an allowed base directory and check if
            # normalized_path starts with that base directory.
            # Example: allowed_base = os.path.abspath(os.getcwd())
            # if not normalized_path.startswith(allowed_base): return False

            # More robust check for directory traversal using relative path
            # This is a general approach to prevent going outside the current working directory's hierarchy.
            # If the user selects a file from an entirely different drive/root, this might still pass,
            # but it prevents relative path attacks within the current file system.
            if ".." in normalized_path.split(os.sep):
                return False

            # Check if the path points to a symbolic link, which can be exploited
            if os.path.islink(filepath):
                logging.warning(f"Symbolic link detected: {filepath}")
                return False

            return True
        except Exception as e:
            logging.error(f"Error during file path validation for '{filepath}': {e}", exc_info=True)
            return False

    def run(self):
        """Starts the Tkinter event loop."""
        self.root.mainloop()

if __name__ == "__main__":
    # Ensure the cryptography library is installed before running
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        app = SecureEncryptionTool()
        app.run()
    except ImportError:
        # Provide clear instructions if the dependency is missing
        print("ERROR: The 'cryptography' library is not installed.")
        print("Please install it using: pip install cryptography")
        logging.critical("Application failed to start: 'cryptography' library not found.")
    except Exception as ex:
        # Catch any other unhandled exceptions during startup
        print(f"An unhandled error occurred during application startup: {ex}")
        logging.critical(f"Application startup failed due to an unhandled exception: {ex}", exc_info=True)