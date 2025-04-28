import random


class RSA:
    def __init__(self):
        self.e = 65537  # Common public exponent, safe number for RSA encryption, see README for details

    # Generate an RSA key pair with specified bit length
    def generate_keypair(self, bits=2048):
        # 1. Generate two large prime numbers 
        p = self.generate_large_prime(bits // 2)
        q = self.generate_large_prime(bits // 2)
        
        # 2. Calculate n = p * q 
        n = p * q
        
        # 3. Calculate Euler's totient function φ(n) = (p-1)(q-1)
        phi = (p - 1) * (q - 1)
        
        # Public key is (e, n)
        e = self.e
        
        # 4. Compute private key d (modular multiplicative inverse of e modulo phi)
        d = self.mod_inverse(e, phi)
        
        # 5. Pre-compute CRT components
        dp = d % (p - 1)
        dq = d % (q - 1)
        qinv = self.mod_inverse(q, p)
        
        # Return public and private key pairs
        public_key = {'e': e, 'n': n}
        private_key = {
            'd': d, 
            'n': n, 
            'p': p, 
            'q': q,
            'dp': dp,
            'dq': dq,
            'qinv': qinv
        }

        """NOTE: dp and dq along the with qinverse are precomputed at the key generation step to speed up decryption."""
        
        return public_key, private_key

    # Miller-Rabin primality test
    def is_prime(self, n, k=40):
        # Handle base cases for n < 3 and if n is even, return false.
        if n == 2 or n == 3:
            return True
        if n <= 1 or n % 2 == 0:
            return False
            
        # n-1 = 2^r * d
        # Find an odd number d such that n-1 can be written as d*2r. 
        # Note that since n is odd, (n-1) must be even and r must be greater than 0.
        r, d = 0, n - 1
        while d % 2 == 0:
            r += 1
            d //= 2
            
        # Witness loop k times
        for _ in range(k):
            a = random.randint(2, n - 2)
            x = pow(a, d, n)
            if x == 1 or x == n - 1:
                continue
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            # If n is composite
            else:
                return False
        return True
        
    # Helper Function: Generate a prime number with specified bit length
    def generate_large_prime(self, bits):
        while True:
            p = random.getrandbits(bits) | (1 << bits - 1) | 1
            if self.is_prime(p):
                return p

    # Helper Function: Extended Euclidean Algorithm to compute gcd and Bézout coefficients
    def extended_gcd(self, a, b):
        if a == 0:
            return b, 0, 1
        else:
            gcd, x1, y1 = self.extended_gcd(b % a, a)
            x = y1 - (b // a) * x1
            y = x1
            return gcd, x, y
        
    # Helper Function: Calculate modular multiplicative inverse of a mod m
    def mod_inverse(self, a, m):
        gcd, x, y = self.extended_gcd(a, m)
        if gcd != 1:
            raise Exception("Modular inverse does not exist")
        else:
            return x % m

    # ENCRYPT Function     
    # Encrypt message using RSA public key   
    def encrypt(self, message, public_key):
        e, n = public_key['e'], public_key['n']

        # Ciphertext= Plain(Message)^e mod n
        c = pow(message, e, n)
        return c

    # DECRYPT Function    
    # Decrypt ciphertext using RSA private key with Chinese Remainder Theorem optimization
    def decrypt(self, ciphertext, private_key):
        # 1. Extract pre-computed CRT components
        p = private_key['p']
        q = private_key['q']
        dp = private_key['dp']
        dq = private_key['dq']
        qinv = private_key['qinv']
        
        # 2. Compute message modulo p
        m1 = pow(ciphertext % p, dp, p)
        # 3. Compute message modulo q
        m2 = pow(ciphertext % q, dq, q)
        
        # 4. Combine using CRT
        h = (qinv * (m1 - m2)) % p
        m = m2 + h * q
        
        return m