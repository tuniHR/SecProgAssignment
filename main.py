import hashlib
import secrets
import string
from tkinter import filedialog
from tkinter import messagebox
from tkinter import simpledialog
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA512
import gui as ui

FILE = None
KEY = None

def open_file(root, frame):
    global FILE
    file_path = filedialog.askopenfilename(title="Select Password File")
    if file_path:
        password = ui.ask_password()
        if password:
            try:
                 with open(file_path, 'r') as file:
                    # Read the stored hash and salt from the file
                    stored_hash, stored_salt = file.readline().strip().split(',')
                    # Hash the provided password with the stored salt
                    hash_attempt = hashlib.sha256(password.encode('utf-8') + bytes.fromhex(stored_salt)).hexdigest()
                    if(stored_hash == hash_attempt):
                        FILE = file_path
                        generate_key(password, bytes.fromhex(stored_salt))
                        ui.populate_frame(root, frame)
                        
                    else:
                        messagebox.showinfo("Failure", "Incorrect password!")
            except Exception as e:
                messagebox.showerror("Error", f"Error occurred while reading the file: {e}")
        else:
            messagebox.showwarning("Warning", "No password entered.")


def generate_key(password, salt):
    global KEY
    key = PBKDF2(password, salt, 32, count=1000000, hmac_hash_module=SHA512)
    KEY = key

def generate_new_password(length=16):
    alphabet = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(secrets.choice(alphabet) for i in range(length))
    return password

    
def init_new_file(frame):
    global FILE
    file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
    if(file_path):
        try:
            ui.clear_password_frame(frame)
            password = ui.new_password()
            if password:
                salt = secrets.token_bytes(32)
                hashed_password = hashlib.sha256(password.encode('utf-8') + salt).hexdigest()
                with open(file_path, 'w') as file:
                    file.write(f"{hashed_password}, {salt.hex()}")
                    FILE = file_path
                    generate_key(password, salt)
                
        except Exception as e:
            messagebox.showerror("Error", f"Error occurred while creating the file: {e}")



def add_entry(root, service, username, password, frame):
    if isFileOpen():
        entry = service+","+username+","+password
        cipher = AES.new(KEY, AES.MODE_EAX)
        nonce = cipher.nonce
        ciphertext, tag = cipher.encrypt_and_digest(entry.encode('utf-8'))
        line = ciphertext.hex()+ "," + nonce.hex() + "," + tag.hex()

        try:
            with open(FILE, "a") as file:
                file.write("\n")
                file.write(line)
            
            ui.populate_frame(root, frame)
        except Exception as e:
            messagebox.showinfo("Error", f"Error while writing {e}")
    else:
        messagebox.showinfo("Error", "There must be open file to add password")

def read_and_decrypt_content():
    plaintextArray = []
    with open(FILE, 'r') as file: 
        next(file)  # Skip the first line
        for line in file:
            encrypted_array = line.strip().split(",")
            if len(encrypted_array) == 3:
                cipher = AES.new(KEY, AES.MODE_EAX, nonce=bytes.fromhex(encrypted_array[1]))
                plaintext = cipher.decrypt(bytes.fromhex(encrypted_array[0]))
                try:
                    plaintext = plaintext.decode("utf-8").strip().split(",")
                    cipher.verify(bytes.fromhex(encrypted_array[2]))
                    plaintextArray.append(plaintext)
                except ValueError:
                    messagebox.showinfo("Error", "Content corrupted")
                    return []

    return plaintextArray
    

def copy_to_clipboard(root, entry):
    clear_clipboard(root)

    # Get text from the Entry widget
    text = entry.get()
    
    # Append the text to the clipboard
    root.clipboard_append(text)

def clear_clipboard(root):
    # Clear the clipboard
    root.clipboard_clear()

def delete_card(frame, index):
    try:
        with open(FILE, 'r') as file:
            lines = file.readlines()

        # Check if the index is valid
        if index < 0 or index >= len(lines):
            return
        
        frame.destroy()

        # Remove the line at the specified index
        del lines[index]

        # Write the modified content back to the file
        with open(FILE, 'w') as file:
            file.writelines(lines)
    except Exception as e:
         messagebox.showerror("Error", f"Error occurred: {e}")
    

def save_changes(service_entry, username_entry, password_entry, edit_button, save_button, index):

    with open(FILE, 'r') as file:
        lines = file.readlines()

    # Check if the index is valid
    if index < 0 or index >= len(lines):
        return

    # Get the new values from the entries
    new_service = service_entry.get()
    new_username = username_entry.get()
    new_password = password_entry.get()

    entry = new_service+","+new_username+","+new_password
    cipher = AES.new(KEY, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(entry.encode('utf-8'))
    line = ciphertext.hex()+ "," + nonce.hex() + "," + tag.hex()

    lines[index] = line +'\n'
    

    with open(FILE, 'w') as file:
        file.writelines(lines)

    edit_button.config(state="normal")
    ui.toggle_edit_mode(service_entry, username_entry, password_entry, edit_button, save_button)


def change_password():
    if isFileOpen():
        try:
            password = ui.new_password()
            salt = secrets.token_bytes(32)
            hashed_password = hashlib.sha256(password.encode('utf-8') + salt).hexdigest()
            passwordsArray = read_and_decrypt_content()
            with open(FILE, 'w') as file: 
                file.write(f"{hashed_password}, {salt.hex()}")
                generate_key(password, salt)
                
                for passwordEntry in passwordsArray:
                    if len(passwordEntry) == 3:
                        entry = passwordEntry[0]+","+passwordEntry[1]+","+passwordEntry[2]
                        
                        cipher = AES.new(KEY, AES.MODE_EAX)
                        nonce = cipher.nonce
                        ciphertext, tag = cipher.encrypt_and_digest(entry.encode('utf-8'))
                        line = ciphertext.hex()+ "," + nonce.hex() + "," + tag.hex()
                        file.write("\n")
                        file.write(line)


        except Exception as e:
            messagebox.showinfo("Error", f"Error while writing {e}")
    else:
        messagebox.showinfo("Error","There must be open file to change password")

def clear_passwords(frame):
    global FILE
    global KEY
    ui.clear_password_frame(frame)
    FILE = None
    KEY = None

def isFileOpen():
    if FILE != None:
        return True
    else:
        return False

def main():
    ui.mainWindow()


if __name__ == "__main__":
    main()