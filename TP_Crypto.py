import os
import math
import random
import hashlib
import tkinter as tk
from tkinter import filedialog, messagebox

class RSA:
    def __init__(self):
        self.e = 65537  # Common public exponent

    def generate_keypair(self, bits=2048):
        """Generate an RSA key pair with specified bit length"""
        # Generate two large prime numbers
        p = self._generate_large_prime(bits // 2)
        q = self._generate_large_prime(bits // 2)
        
        # Calculate n = p * q
        n = p * q
        
        # Calculate Euler's totient function φ(n) = (p-1)(q-1)
        phi = (p - 1) * (q - 1)
        
        # Public key is (e, n)
        e = self.e
        
        # Compute private key d (modular multiplicative inverse of e modulo phi)
        d = self._mod_inverse(e, phi)
        
        # Return public and private key pairs
        public_key = {'e': e, 'n': n}
        private_key = {'d': d, 'n': n, 'p': p, 'q': q}  # Include p, q for CRT optimization
        
        return public_key, private_key

    def _is_prime(self, n, k=40):
        """Miller-Rabin primality test"""
        if n == 2 or n == 3:
            return True
        if n <= 1 or n % 2 == 0:
            return False
            
        # Write n-1 as 2^r * d
        r, d = 0, n - 1
        while d % 2 == 0:
            r += 1
            d //= 2
            
        # Witness loop
        for _ in range(k):
            a = random.randint(2, n - 2)
            x = pow(a, d, n)
            if x == 1 or x == n - 1:
                continue
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        return True
        
    def _generate_large_prime(self, bits):
        """Generate a prime number with specified bit length"""
        while True:
            # Generate a random odd number with specified bit length
            p = random.getrandbits(bits) | (1 << bits - 1) | 1
            if self._is_prime(p):
                return p

    def _extended_gcd(self, a, b):
        """Extended Euclidean Algorithm to compute gcd and Bézout coefficients"""
        if a == 0:
            return b, 0, 1
        else:
            gcd, x1, y1 = self._extended_gcd(b % a, a)
            x = y1 - (b // a) * x1
            y = x1
            return gcd, x, y

    def _mod_inverse(self, a, m):
        """Calculate modular multiplicative inverse of a mod m"""
        gcd, x, y = self._extended_gcd(a, m)
        if gcd != 1:
            raise Exception("Modular inverse does not exist")
        else:
            return x % m
            
    def encrypt(self, message, public_key):
        """Encrypt message using RSA public key"""
        e, n = public_key['e'], public_key['n']
        c = pow(message, e, n)
        return c
        
    def decrypt(self, ciphertext, private_key):
        """Decrypt ciphertext using RSA private key with Chinese Remainder Theorem optimization"""
        d, n = private_key['d'], private_key['n']
        p, q = private_key['p'], private_key['q']
        
        # CRT optimization
        dp = d % (p - 1)
        dq = d % (q - 1)
        qinv = self._mod_inverse(q, p)
        
        # Compute message modulo p
        m1 = pow(ciphertext % p, dp, p)
        # Compute message modulo q
        m2 = pow(ciphertext % q, dq, q)
        
        # Combine using CRT
        h = (qinv * (m1 - m2)) % p
        m = m2 + h * q
        
        return m


class OAEP:
    def __init__(self, hash_function=hashlib.sha256, hash_len=32):
        self.hash_function = hash_function
        self.hash_len = hash_len  # SHA-256 output length in bytes
    
    def mgf1(self, seed, length):
        """Mask Generation Function based on hash function"""
        result = b''
        counter = 0
        
        while len(result) < length:
            C = counter.to_bytes(4, byteorder='big')
            result += self.hash_function(seed + C).digest()
            counter += 1
            
        return result[:length]
        
    def pad(self, message, key_length_bytes):
        """
        OAEP padding for message
        key_length_bytes: Length of RSA modulus in bytes
        """
        # Calculate maximum message length that can be encoded
        k = key_length_bytes
        mlen = len(message)
        hlen = self.hash_len
        
        # Check if message is too long
        if mlen > k - 2 * hlen - 2:
            raise ValueError("Message too long for OAEP padding")
            
        # Generate a random seed
        seed = os.urandom(hlen)
        
        # Generate padding string PS
        ps_len = k - mlen - 2 * hlen - 2
        ps = b'\x00' * ps_len
        
        # Concatenate to form data block
        db = self.hash_function(b'').digest() + ps + b'\x01' + message
        
        # Calculate masked db
        db_mask = self.mgf1(seed, k - hlen - 1)
        masked_db = bytes(a ^ b for a, b in zip(db, db_mask))
        
        # Calculate masked seed
        seed_mask = self.mgf1(masked_db, hlen)
        masked_seed = bytes(a ^ b for a, b in zip(seed, seed_mask))
        
        # Concatenate to form padded message
        padded_message = b'\x00' + masked_seed + masked_db
        
        return padded_message
        
    def unpad(self, padded_message, key_length_bytes):
        """
        OAEP unpadding for decrypted message
        key_length_bytes: Length of RSA modulus in bytes
        """
        k = key_length_bytes
        hlen = self.hash_len
        
        # Check input length
        if len(padded_message) != k:
            raise ValueError("Decrypted message length incorrect")
            
        # Check if first byte is zero
        if padded_message[0] != 0:
            raise ValueError("Decryption error: first byte not zero")
            
        # Split components
        masked_seed = padded_message[1:hlen+1]
        masked_db = padded_message[hlen+1:]
        
        # Recover seed
        seed_mask = self.mgf1(masked_db, hlen)
        seed = bytes(a ^ b for a, b in zip(masked_seed, seed_mask))
        
        # Recover data block
        db_mask = self.mgf1(seed, k - hlen - 1)
        db = bytes(a ^ b for a, b in zip(masked_db, db_mask))
        
        # Extract message
        expected_hash = self.hash_function(b'').digest()
        
        if db[:hlen] != expected_hash:
            raise ValueError("Decryption error: invalid padding")
            
        # Find the first occurrence of 0x01 byte after the hash
        separator_idx = hlen
        while separator_idx < len(db):
            if db[separator_idx] == 0x01:
                break
            elif db[separator_idx] != 0x00:
                raise ValueError("Decryption error: invalid padding format")
            separator_idx += 1
            
        if separator_idx == len(db):
            raise ValueError("Decryption error: no message separator found")
            
        # Extract the message
        message = db[separator_idx + 1:]
        
        return message


class RSA_OAEP:
    def __init__(self):
        self.rsa = RSA()
        self.oaep = OAEP()
        
    def generate_keypair(self, bits=2048):
        """Generate RSA key pair"""
        return self.rsa.generate_keypair(bits)
        
    def save_key_to_file(self, key, filename):
        """Save key to a hex-formatted text file"""
        with open(filename, 'w') as f:
            # Convert dictionary to hex strings
            for k, v in key.items():
                f.write(f"{k}:{hex(v)[2:]}\n")
    
    def load_key_from_file(self, filename):
        """Load key from a hex-formatted text file"""
        key = {}
        with open(filename, 'r') as f:
            for line in f:
                k, v = line.strip().split(':', 1)
                key[k] = int(v, 16)
        return key
        
    def encrypt_file(self, input_file, output_file, public_key_file):
        """Encrypt a file using RSA-OAEP"""
        # Load public key
        public_key = self.load_key_from_file(public_key_file)
        
        # Read input file
        with open(input_file, 'rb') as f:
            plaintext = f.read()
            
        # Calculate RSA modulus byte length
        modulus_bytes_len = (public_key['n'].bit_length() + 7) // 8
        
        # Maximum size of data that can be encrypted in one block
        max_chunk_size = modulus_bytes_len - 2 * self.oaep.hash_len - 2
        
        # Process file in chunks
        encrypted_chunks = []
        
        for i in range(0, len(plaintext), max_chunk_size):
            chunk = plaintext[i:i + max_chunk_size]
            
            # Pad using OAEP
            padded_chunk = self.oaep.pad(chunk, modulus_bytes_len)
            
            # Convert to integer
            padded_int = int.from_bytes(padded_chunk, byteorder='big')
            
            # RSA encrypt
            encrypted_int = self.rsa.encrypt(padded_int, public_key)
            
            # Convert to bytes of fixed length
            encrypted_bytes = encrypted_int.to_bytes(modulus_bytes_len, byteorder='big')
            encrypted_chunks.append(encrypted_bytes)
            
        # Write encrypted data to output file
        with open(output_file, 'wb') as f:
            for chunk in encrypted_chunks:
                f.write(chunk)
                
    def decrypt_file(self, input_file, output_file, private_key_file):
        """Decrypt a file using RSA-OAEP"""
        # Load private key
        private_key = self.load_key_from_file(private_key_file)
        
        # Calculate RSA modulus byte length
        modulus_bytes_len = (private_key['n'].bit_length() + 7) // 8
        
        # Read encrypted file
        with open(input_file, 'rb') as f:
            ciphertext = f.read()
            
        # Process file in chunks
        decrypted_chunks = []
        
        for i in range(0, len(ciphertext), modulus_bytes_len):
            chunk = ciphertext[i:i + modulus_bytes_len]
            
            if len(chunk) != modulus_bytes_len:
                # Skip incomplete block at the end if any
                break
                
            # Convert to integer
            chunk_int = int.from_bytes(chunk, byteorder='big')
            
            # RSA decrypt
            decrypted_int = self.rsa.decrypt(chunk_int, private_key)
            
            # Convert to bytes of fixed length
            decrypted_bytes = decrypted_int.to_bytes(modulus_bytes_len, byteorder='big')
            
            # Remove OAEP padding
            try:
                unpadded = self.oaep.unpad(decrypted_bytes, modulus_bytes_len)
                decrypted_chunks.append(unpadded)
            except ValueError as e:
                print(f"Decryption error in chunk {i // modulus_bytes_len}: {str(e)}")
                return False
            
        # Write decrypted data to output file
        with open(output_file, 'wb') as f:
            for chunk in decrypted_chunks:
                f.write(chunk)
                
        return True


# Simple GUI
class RSA_OAEP_GUI:
    def __init__(self, root):
        self.root = root
        self.root.title("RSA-OAEP Encryption/Decryption")
        self.root.geometry("500x300")
        self.crypto = RSA_OAEP()
        
        # Create frames
        self.key_frame = tk.Frame(root)
        self.key_frame.pack(pady=10)
        
        self.encrypt_frame = tk.Frame(root)
        self.encrypt_frame.pack(pady=10)
        
        self.decrypt_frame = tk.Frame(root)
        self.decrypt_frame.pack(pady=10)
        
        # Key generation
        self.key_button = tk.Button(self.key_frame, text="Generate Key Pair (2048-bit)", command=self.generate_keys)
        self.key_button.pack()
        
        # Encryption
        tk.Label(self.encrypt_frame, text="Encryption").pack()
        self.encrypt_file_button = tk.Button(self.encrypt_frame, text="Select File to Encrypt", command=self.select_encrypt_file)
        self.encrypt_file_button.pack(side=tk.LEFT, padx=5)
        
        self.public_key_button = tk.Button(self.encrypt_frame, text="Select Public Key", command=self.select_public_key)
        self.public_key_button.pack(side=tk.LEFT, padx=5)
        
        self.encrypt_button = tk.Button(self.encrypt_frame, text="Encrypt", command=self.encrypt_file)
        self.encrypt_button.pack(side=tk.LEFT, padx=5)
        
        # Decryption
        tk.Label(self.decrypt_frame, text="Decryption").pack()
        self.decrypt_file_button = tk.Button(self.decrypt_frame, text="Select File to Decrypt", command=self.select_decrypt_file)
        self.decrypt_file_button.pack(side=tk.LEFT, padx=5)
        
        self.private_key_button = tk.Button(self.decrypt_frame, text="Select Private Key", command=self.select_private_key)
        self.private_key_button.pack(side=tk.LEFT, padx=5)
        
        self.decrypt_button = tk.Button(self.decrypt_frame, text="Decrypt", command=self.decrypt_file)
        self.decrypt_button.pack(side=tk.LEFT, padx=5)
        
        # File paths
        self.encrypt_file_path = None
        self.decrypt_file_path = None
        self.public_key_path = None
        self.private_key_path = None
        
    def generate_keys(self):
        """Generate and save RSA key pair"""
        try:
            public_key, private_key = self.crypto.generate_keypair(2048)
            
            # Save public key
            public_key_file = filedialog.asksaveasfilename(
                title="Save Public Key",
                defaultextension=".txt",
                filetypes=[("Text files", "*.txt")]
            )
            if not public_key_file:
                return
                
            self.crypto.save_key_to_file(public_key, public_key_file)
            
            # Save private key
            private_key_file = filedialog.asksaveasfilename(
                title="Save Private Key",
                defaultextension=".txt",
                filetypes=[("Text files", "*.txt")]
            )
            if not private_key_file:
                return
                
            self.crypto.save_key_to_file(private_key, private_key_file)
            
            messagebox.showinfo("Success", "Key pair generated and saved successfully!")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate keys: {str(e)}")
    
    def select_encrypt_file(self):
        """Select file to encrypt"""
        self.encrypt_file_path = filedialog.askopenfilename(title="Select File to Encrypt")
    
    def select_public_key(self):
        """Select public key file"""
        self.public_key_path = filedialog.askopenfilename(
            title="Select Public Key",
            filetypes=[("Text files", "*.txt")]
        )
    
    def encrypt_file(self):
        """Encrypt selected file"""
        if not self.encrypt_file_path:
            messagebox.showerror("Error", "No file selected for encryption!")
            return
            
        if not self.public_key_path:
            messagebox.showerror("Error", "No public key selected!")
            return
            
        output_file = filedialog.asksaveasfilename(
            title="Save Encrypted File",
            defaultextension=".enc"
        )
        if not output_file:
            return
            
        try:
            self.crypto.encrypt_file(self.encrypt_file_path, output_file, self.public_key_path)
            messagebox.showinfo("Success", "File encrypted successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {str(e)}")
    
    def select_decrypt_file(self):
        """Select file to decrypt"""
        self.decrypt_file_path = filedialog.askopenfilename(title="Select File to Decrypt")
    
    def select_private_key(self):
        """Select private key file"""
        self.private_key_path = filedialog.askopenfilename(
            title="Select Private Key",
            filetypes=[("Text files", "*.txt")]
        )
    
    def decrypt_file(self):
        """Decrypt selected file"""
        if not self.decrypt_file_path:
            messagebox.showerror("Error", "No file selected for decryption!")
            return
            
        if not self.private_key_path:
            messagebox.showerror("Error", "No private key selected!")
            return
            
        output_file = filedialog.asksaveasfilename(
            title="Save Decrypted File"
        )
        if not output_file:
            return
            
        try:
            success = self.crypto.decrypt_file(self.decrypt_file_path, output_file, self.private_key_path)
            if success:
                messagebox.showinfo("Success", "File decrypted successfully!")
            else:
                messagebox.showerror("Error", "Decryption failed: Invalid ciphertext or key")
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {str(e)}")


# Main entry point
if __name__ == "__main__":
    root = tk.Tk()
    app = RSA_OAEP_GUI(root)
    root.mainloop()
