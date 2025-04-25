
import random


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