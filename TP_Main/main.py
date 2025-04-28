import os
import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk
from PIL import Image, ImageTk
from itertools import count, cycle

from OAEP import OAEP
from RSA import RSA

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
        
    def encrypt_file(self, input_file, output_file, public_key_file, progress_callback=None):
        """Encrypt a file using RSA-OAEP"""
        # Load public key
        public_key = self.load_key_from_file(public_key_file)
        
        # Read input file
        with open(input_file, 'rb') as f:
            plaintext = f.read()
            
        bytes_processed = 0
        
                # Get original file extension
        original_extension = os.path.splitext(input_file)[1].encode()  # contoh: b'.mp4'
        if not original_extension:
            original_extension = b'.bin'  # kalau tidak ada ekstensi

        # Prepare header: length(1 byte) + extension (max 255 bytes)
        if len(original_extension) > 255:
            raise ValueError("File extension too long!")
        header = len(original_extension).to_bytes(1, 'big') + original_extension

        # Insert header at the beginning
        plaintext = header + plaintext

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
            
            bytes_processed += len(chunk)
            if progress_callback:
                progress_callback(bytes_processed)
            
        # Write encrypted data to output file
        with open(output_file, 'wb') as f:
            for chunk in encrypted_chunks:
                f.write(chunk)
                
    def decrypt_file(self, input_file, output_file, private_key_file, progress_callback=None):
        # Load private key
        private_key = self.load_key_from_file(private_key_file)

        bytes_processed = 0

        modulus_bytes_len = (private_key['n'].bit_length() + 7) // 8

        with open(input_file, 'rb') as f:
            ciphertext = f.read()

        decrypted_chunks = []

        for i in range(0, len(ciphertext), modulus_bytes_len):
            chunk = ciphertext[i:i + modulus_bytes_len]

            if len(chunk) != modulus_bytes_len:
                break

            chunk_int = int.from_bytes(chunk, byteorder='big')
            decrypted_int = self.rsa.decrypt(chunk_int, private_key)
            decrypted_bytes = decrypted_int.to_bytes(modulus_bytes_len, byteorder='big')

            try:
                unpadded = self.oaep.unpad(decrypted_bytes, modulus_bytes_len)
                decrypted_chunks.append(unpadded)
            except ValueError as e:
                print(f"Decryption error in chunk {i // modulus_bytes_len}: {str(e)}")
                return False

            bytes_processed += len(chunk)
            if progress_callback:
                progress_callback(bytes_processed)

        # Gabungkan semua potongan
        full_plaintext = b''.join(decrypted_chunks)

        # --- Baca header ---
        ext_len = full_plaintext[0]
        original_extension = full_plaintext[1:1+ext_len].decode()
        real_plaintext = full_plaintext[1+ext_len:]

        # --- Sesuaikan output file ---
        base_output = output_file
        if base_output.endswith('.enc'):
            base_output = base_output[:-4]

        output_file_with_ext = base_output + original_extension

        with open(output_file_with_ext, 'wb') as f:
            f.write(real_plaintext)

        return True


class AnimatedGIF(tk.Label):
    def __init__(self, master, path):
        tk.Label.__init__(self, master)
        self.frames = None
        self.load(path)

    def load(self, path):
        im = Image.open(path)
        frames = []
        try:
            for i in count(1):
                frames.append(ImageTk.PhotoImage(im.copy()))
                im.seek(i)
        except EOFError:
            pass
        self.frames = cycle(frames)
        self.frame_count = len(frames)
        
        try:
            self.delay = im.info['duration']
        except:
            self.delay = 100

        if len(frames) == 1:
            self.config(image=next(self.frames))
        else:
            self.next_frame()

    def next_frame(self):
        if self.frames:
            self.config(image=next(self.frames))
            self.after(self.delay, self.next_frame)

    def stop(self):
        self.frames = None
        self.config(image='')



class RSA_OAEP_GUI:
    def __init__(self, root):
        self.root = root
        self.root.title("RSA-OAEP Encryption/Decryption")
        self.root.geometry("800x400") 
        self.crypto = RSA_OAEP()
        
        self.main_container = tk.Frame(root)
        self.main_container.pack(side=tk.LEFT, padx=20, pady=10, fill=tk.BOTH)
        
        tk.Label(self.main_container, text="RSA-OAEP Encryption/Decryption", font=('Helvetica', 12, 'bold')).pack(anchor=tk.W)
        
        # Key Generation Section
        self.key_frame = tk.LabelFrame(self.main_container, text="Key Generation", padx=5, pady=5)
        self.key_frame.pack(fill=tk.X, pady=(10,5))
        
        self.key_button = tk.Button(self.key_frame, text="Generate Key Pair (2048-bit)", command=self.generate_keys)
        self.key_button.pack(anchor=tk.W)
        
        # Encryption Section
        self.encrypt_frame = tk.LabelFrame(self.main_container, text="Encryption", padx=5, pady=5)
        self.encrypt_frame.pack(fill=tk.X, pady=5)
        
        # File selection row
        file_row = tk.Frame(self.encrypt_frame)
        file_row.pack(fill=tk.X, pady=2)
        self.encrypt_file_button = tk.Button(file_row, text="Select File", width=12, command=self.select_encrypt_file)
        self.encrypt_file_button.pack(side=tk.LEFT)
        self.encrypt_path_label = tk.Label(file_row, text="No file selected", padx=5)
        self.encrypt_path_label.pack(side=tk.LEFT, fill=tk.X)
        
        # Key selection row
        key_row = tk.Frame(self.encrypt_frame)
        key_row.pack(fill=tk.X, pady=2)
        self.public_key_button = tk.Button(key_row, text="Select Key", width=12, command=self.select_public_key)
        self.public_key_button.pack(side=tk.LEFT)
        self.public_key_label = tk.Label(key_row, text="No public key selected", padx=5)
        self.public_key_label.pack(side=tk.LEFT, fill=tk.X)
        
        # Encrypt button
        self.encrypt_button = tk.Button(self.encrypt_frame, text="Encrypt File", width=12, command=self.encrypt_file)
        self.encrypt_button.pack(anchor=tk.W, pady=(5,0))
        
        # Decryption Section
        self.decrypt_frame = tk.LabelFrame(self.main_container, text="Decryption", padx=5, pady=5)
        self.decrypt_frame.pack(fill=tk.X, pady=5)
        
        # File selection row
        dec_file_row = tk.Frame(self.decrypt_frame)
        dec_file_row.pack(fill=tk.X, pady=2)
        self.decrypt_file_button = tk.Button(dec_file_row, text="Select File", width=12, command=self.select_decrypt_file)
        self.decrypt_file_button.pack(side=tk.LEFT)
        self.decrypt_path_label = tk.Label(dec_file_row, text="No file selected", padx=5)
        self.decrypt_path_label.pack(side=tk.LEFT, fill=tk.X)
        
        # Key selection row
        dec_key_row = tk.Frame(self.decrypt_frame)
        dec_key_row.pack(fill=tk.X, pady=2)
        self.private_key_button = tk.Button(dec_key_row, text="Select Key", width=12, command=self.select_private_key)
        self.private_key_button.pack(side=tk.LEFT)
        self.private_key_label = tk.Label(dec_key_row, text="No private key selected", padx=5)
        self.private_key_label.pack(side=tk.LEFT, fill=tk.X)
        
        # Decrypt button
        self.decrypt_button = tk.Button(self.decrypt_frame, text="Decrypt File", width=12, command=self.decrypt_file)
        self.decrypt_button.pack(anchor=tk.W, pady=(5,0))
        
        # Progress Section
        self.progress_frame = tk.LabelFrame(self.main_container, text="Progress", padx=5, pady=5)
        self.progress_frame.pack(fill=tk.X, pady=5)
        
        # Progress elements frame
        self.progress_elements = tk.Frame(self.progress_frame)
        self.progress_elements.pack(fill=tk.X)
        
        # Left side: Loading GIF
        self.loading_label = None  # Will hold the AnimatedGIF instance
        
        # Right side: Progress information
        self.progress_info = tk.Frame(self.progress_elements)
        self.progress_info.pack(side=tk.RIGHT, fill=tk.X, expand=True)
        
        self.progress_label = tk.Label(self.progress_info, text="")
        self.progress_label.pack(anchor=tk.W)
        
        self.progress_bar = ttk.Progressbar(
            self.progress_info,
            orient='horizontal',
            length=400,
            mode='determinate'
        )
        self.progress_bar.pack(fill=tk.X, pady=(5,0))
        
        # Initialize file paths
        self.encrypt_file_path = None
        self.decrypt_file_path = None
        self.public_key_path = None
        self.private_key_path = None

    # Update the label update methods
    def select_encrypt_file(self):
        self.encrypt_file_path = filedialog.askopenfilename(title="Select File to Encrypt")
        if self.encrypt_file_path:
            filename = os.path.basename(self.encrypt_file_path)
            self.encrypt_path_label.config(text=filename)
    
    def select_public_key(self):
        self.public_key_path = filedialog.askopenfilename(
            title="Select Public Key",
            filetypes=[("Text files", "*.txt")]
        )
        if self.public_key_path:
            filename = os.path.basename(self.public_key_path)
            self.public_key_label.config(text=filename)
    
    def select_decrypt_file(self):
        self.decrypt_file_path = filedialog.askopenfilename(title="Select File to Decrypt")
        if self.decrypt_file_path:
            filename = os.path.basename(self.decrypt_file_path)
            self.decrypt_path_label.config(text=filename)
    
    def select_private_key(self):
        self.private_key_path = filedialog.askopenfilename(
            title="Select Private Key",
            filetypes=[("Text files", "*.txt")]
        )
        if self.private_key_path:
            filename = os.path.basename(self.private_key_path)
            self.private_key_label.config(text=filename)

    def show_progress(self, process_name):
        """Show progress bar and loading animation"""
        if self.loading_label is None:
            # Create and add the loading animation
            self.loading_label = AnimatedGIF(self.progress_elements, "loading.gif")
            self.loading_label.pack(side=tk.LEFT, padx=5)
        
        self.progress_label.config(text=f"{process_name} in progress...")
        self.progress_bar["value"] = 0
        self.progress_bar.pack()
        self.root.update()
        
    def update_progress(self, value):
        """Update progress bar value"""
        self.progress_bar["value"] = value
        self.root.update()
        
    def hide_progress(self):
        """Hide progress bar and stop loading animation"""
        if self.loading_label:
            self.loading_label.stop()
            self.loading_label.destroy()
            self.loading_label = None
            
        self.progress_label.config(text="")
        self.progress_bar["value"] = 0
        self.root.update()
        
    def generate_keys(self):
        """Generate and save RSA key pair"""
        try:
            self.show_progress("Key Generation")
            
            # Generate keys
            self.update_progress(20)
            public_key, private_key = self.crypto.generate_keypair(2048)
            
            self.update_progress(40)
            
            # Save public key
            public_key_file = filedialog.asksaveasfilename(
                title="Save Public Key",
                defaultextension=".txt",
                filetypes=[("Text files", "*.txt")]
            )
            if not public_key_file:
                self.hide_progress()
                return
                
            self.update_progress(60)    
            self.crypto.save_key_to_file(public_key, public_key_file)
            
            # Save private key
            self.update_progress(80)
            private_key_file = filedialog.asksaveasfilename(
                title="Save Private Key",
                defaultextension=".txt",
                filetypes=[("Text files", "*.txt")]
            )
            if not private_key_file:
                self.hide_progress()
                return
                
            self.crypto.save_key_to_file(private_key, private_key_file)
            
            self.update_progress(100)
            self.hide_progress()
            messagebox.showinfo("Success", "Key pair generated and saved successfully!")
            
        except Exception as e:
            self.hide_progress()
            messagebox.showerror("Error", f"Failed to generate keys: {str(e)}")
    
    def encrypt_file(self):
        """Encrypt selected file"""
        if not self.encrypt_file_path:
            messagebox.showerror("Error", "No file selected for encryption!")
            return
            
        if not self.public_key_path:
            messagebox.showerror("Error", "No public key selected!")
            return
            
        output_file = filedialog.asksaveasfilename(
            title="Save Encrypted File"
        )
        if not output_file:
            return
            
        # Force add .enc extension
        if not output_file.endswith('.enc'):
            output_file = output_file + '.enc'
            
        try:
            self.show_progress("Encryption")
            
            # Get file size for progress calculation
            file_size = os.path.getsize(self.encrypt_file_path)
            
            def progress_callback(bytes_processed):
                progress = (bytes_processed / file_size) * 100
                self.update_progress(progress)
    
            self.crypto.encrypt_file(
                self.encrypt_file_path, 
                output_file,
                self.public_key_path,
                progress_callback
            )
            
            self.hide_progress()
            messagebox.showinfo("Success", "File encrypted successfully!")
            
        except Exception as e:
            self.hide_progress()
            messagebox.showerror("Error", f"Encryption failed: {str(e)}")
    
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

        # Remove .enc from output file if input had it
        if self.decrypt_file_path.endswith('.enc') and output_file.endswith('.enc'):
            output_file = output_file[:-4]
            
        try:
            self.show_progress("Decryption")
            
            # Get file size for progress calculation  
            file_size = os.path.getsize(self.decrypt_file_path)
            
            def progress_callback(bytes_processed):
                progress = (bytes_processed / file_size) * 100
                self.update_progress(progress)
    
            success = self.crypto.decrypt_file(
                self.decrypt_file_path,
                output_file,
                self.private_key_path, 
                progress_callback
            )
            
            self.hide_progress()
            if success:
                messagebox.showinfo("Success", "File decrypted successfully!")
            else:
                messagebox.showerror("Error", "Decryption failed: Invalid ciphertext or key")
                
        except Exception as e:
            self.hide_progress()
            messagebox.showerror("Error", f"Decryption failed: {str(e)}")


# Main entry point
if __name__ == "__main__":
    root = tk.Tk()
    app = RSA_OAEP_GUI(root)
    root.mainloop()