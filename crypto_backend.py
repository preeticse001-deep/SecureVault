import os
import shutil
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization

class FileEncryptor:
    def __init__(self):
        self.iterations = 480_000 
        self.chunk_size = 64 * 1024 

    def _derive_key(self, password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=self.iterations,
        )
        return kdf.derive(password.encode('utf-8'))

    def encrypt_file(self, input_path: str, password: str, output_path: str = None) -> str:
        salt = os.urandom(16)
        nonce = os.urandom(12)
        
        key = self._derive_key(password, salt)
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
        encryptor = cipher.encryptor()
        
        # Override output if custom path is provided
        if not output_path:
            output_path = f"{input_path}.enc"

        with open(input_path, 'rb') as f_in, open(output_path, 'wb') as f_out:
            f_out.write(salt + nonce)
            while chunk := f_in.read(self.chunk_size):
                f_out.write(encryptor.update(chunk))
            encryptor.finalize()
            f_out.write(encryptor.tag)

        return output_path

    def decrypt_file(self, input_path: str, password: str, output_path: str = None, overwrite_callback=None) -> str:
        file_size = os.path.getsize(input_path)
        if file_size < 44:
            raise ValueError("Target structure payload is too short or corrupted.")

        if not output_path:
            output_path = input_path[:-4] if input_path.endswith('.enc') else f"{input_path}.dec"

        tmp_output_path = f"{output_path}.tmp"

        with open(input_path, 'rb') as f_in:
            salt = f_in.read(16)
            nonce = f_in.read(12)
            
            f_in.seek(file_size - 16)
            tag = f_in.read(16)
            
            ciphertext_len = file_size - 16 - 28
            key = self._derive_key(password, salt)
            cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag))
            decryptor = cipher.decryptor()

            f_in.seek(28)
            bytes_processed = 0

            with open(tmp_output_path, 'wb') as f_out:
                while bytes_processed < ciphertext_len:
                    to_read = min(self.chunk_size, ciphertext_len - bytes_processed)
                    chunk = f_in.read(to_read)
                    if not chunk:
                        break
                    f_out.write(decryptor.update(chunk))
                    bytes_processed += len(chunk)

                try:
                    f_out.write(decryptor.finalize())
                except InvalidTag:
                    f_out.close()
                    if os.path.exists(tmp_output_path):
                        os.remove(tmp_output_path)
                    raise ValueError("Decryption signature verification failed. Bad token or payload tampered.")

        if os.path.exists(output_path) and overwrite_callback:
            if not overwrite_callback(output_path):
                os.remove(tmp_output_path)
                raise InterruptedError("Operation aborted to protect existing file.")

        if os.path.exists(output_path):
            os.remove(output_path)
        os.rename(tmp_output_path, output_path)

        return output_path

    def encrypt_directory(self, dir_path: str, password: str, output_path: str = None) -> str:
        if not os.path.isdir(dir_path):
            raise ValueError("Target path resolution is not a valid directory.")
            
        archive_path = shutil.make_archive(base_name=dir_path, format='zip', root_dir=dir_path)
        archive_path_with_ext = f"{dir_path}.zip"
        
        # Passes the custom output_path down the chain
        encrypted_path = self.encrypt_file(archive_path_with_ext, password, output_path)
        os.remove(archive_path_with_ext)
        return encrypted_path

    def decrypt_directory(self, input_path: str, password: str, output_path: str = None, overwrite_callback=None) -> str:
        # 1. Decrypt to a temporary zip file (Bypasses UI override check for this temp file)
        temp_zip_out = f"{input_path}.tmp.zip"
        decrypted_zip_path = self.decrypt_file(input_path, password, output_path=temp_zip_out)

        if not decrypted_zip_path.endswith('.zip'):
            raise ValueError("Target element structure does not validate as a directory archive.")

        # 2. Assign final custom extraction folder path
        extract_path = output_path if output_path else decrypted_zip_path.replace('.tmp.zip', '_decrypted')

        # 3. NOW check if the target folder exists and ping the UI safely
        if os.path.exists(extract_path) and overwrite_callback:
            if not overwrite_callback(extract_path):
                os.remove(decrypted_zip_path) 
                raise InterruptedError("Operation aborted to protect existing folder.")

        # 4. Extract into the custom destination
        shutil.unpack_archive(filename=decrypted_zip_path, extract_dir=extract_path)
        os.remove(decrypted_zip_path)
        return extract_path

    def secure_delete(self, path: str, passes: int = 3):
        if os.path.isfile(path):
            self._shred_file(path, passes)
        elif os.path.isdir(path):
            for root, dirs, files in os.walk(path, topdown=False):
                for name in files:
                    self._shred_file(os.path.join(root, name), passes)
            shutil.rmtree(path)

    def _shred_file(self, file_path: str, passes: int):
        try:
            length = os.path.getsize(file_path)
            with open(file_path, "ba+") as f:
                for _ in range(passes):
                    f.seek(0)
                    f.write(os.urandom(length))
            os.remove(file_path)
        except Exception as e:
            raise Exception(f"Anti-forensics execution failed on {file_path}: {e}")
        
    def generate_rsa_keypair(self, private_out_path: str, public_out_path: str):
        """Generates a secure 4096-bit RSA keypair and saves them as PEM files."""
        # 1. Generate the Private Key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
        )
        
        # Save Private Key (Keep this completely secret!)
        with open(private_out_path, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption() # Can be password protected later
            ))
            
        # 2. Extract and Save the Public Key (Share this with anyone)
        public_key = private_key.public_key()
        with open(public_out_path, "wb") as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

    def rsa_encrypt_file(self, input_path: str, public_key_path: str, output_path: str = None) -> str:
        """Encrypts a file using a random AES key, then locks that AES key with a recipient's RSA Public Key."""
        # Load the recipient's public key
        with open(public_key_path, "rb") as key_file:
            public_key = serialization.load_pem_public_key(key_file.read())

        # Generate a throwaway AES key and nonce for the heavy lifting
        aes_key = os.urandom(32)
        nonce = os.urandom(12)

        # Encrypt the temporary AES key using RSA OAEP padding
        enc_aes_key = public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce))
        encryptor = cipher.encryptor()

        if not output_path:
            output_path = f"{input_path}.rsa.enc"

        with open(input_path, 'rb') as f_in, open(output_path, 'wb') as f_out:
            # Header Layout: [Size of RSA Key (4 Bytes)] + [Encrypted AES Key] + [Nonce]
            enc_key_len = len(enc_aes_key).to_bytes(4, byteorder='big')
            f_out.write(enc_key_len + enc_aes_key + nonce)

            # Stream the large file using the fast AES cipher
            while chunk := f_in.read(self.chunk_size):
                f_out.write(encryptor.update(chunk))

            encryptor.finalize()
            f_out.write(encryptor.tag) # Append GCM Auth Tag

        return output_path

    def rsa_decrypt_file(self, input_path: str, private_key_path: str, output_path: str = None, overwrite_callback=None) -> str:
        """Unlocks the RSA envelope using a Private Key, extracts the AES key, and decrypts the file stream."""
        file_size = os.path.getsize(input_path)

        # Load your personal private key
        with open(private_key_path, "rb") as key_file:
            private_key = serialization.load_pem_private_key(key_file.read(), password=None)

        if not output_path:
            output_path = input_path.replace('.rsa.enc', '.dec')

        tmp_output_path = f"{output_path}.tmp"

        with open(input_path, 'rb') as f_in:
            # Read the hybrid headers
            enc_key_len = int.from_bytes(f_in.read(4), byteorder='big')
            enc_aes_key = f_in.read(enc_key_len)
            nonce = f_in.read(12)

            # Use RSA to unlock the AES key
            try:
                aes_key = private_key.decrypt(
                    enc_aes_key,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
            except Exception:
                raise ValueError("RSA Decryption Failed: The private key does not match this payload.")

            # Grab the GCM Tag from the end of the file
            f_in.seek(file_size - 16)
            tag = f_in.read(16)
            
            # Calculate stream boundaries
            ciphertext_len = file_size - 16 - 4 - enc_key_len - 12
            cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce, tag))
            decryptor = cipher.decryptor()

            # Return cursor to the start of the actual encrypted data block
            f_in.seek(4 + enc_key_len + 12)
            bytes_processed = 0

            with open(tmp_output_path, 'wb') as f_out:
                while bytes_processed < ciphertext_len:
                    to_read = min(self.chunk_size, ciphertext_len - bytes_processed)
                    chunk = f_in.read(to_read)
                    if not chunk:
                        break
                    f_out.write(decryptor.update(chunk))
                    bytes_processed += len(chunk)

                try:
                    f_out.write(decryptor.finalize())
                except InvalidTag:
                    f_out.close()
                    if os.path.exists(tmp_output_path):
                        os.remove(tmp_output_path)
                    raise ValueError("Integrity check failed. Payload tampered during transit.")

        # Handle UI overwrite conflicts safely
        if os.path.exists(output_path) and overwrite_callback:
            if not overwrite_callback(output_path):
                os.remove(tmp_output_path)
                raise InterruptedError("Operation aborted to protect existing file.")

        if os.path.exists(output_path):
            os.remove(output_path)
        os.rename(tmp_output_path, output_path)

        return output_path
