import hashlib
import os


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