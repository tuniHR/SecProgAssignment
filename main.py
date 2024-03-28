import tkinter as tk
import hashlib
import secrets
from tkinter import filedialog
from tkinter import messagebox
from tkinter import simpledialog

def open_file():
    file_path = filedialog.askopenfilename(title="Select Password File")
    if file_path:
        password = ask_password()
        if password:
            try:
                 with open(file_path, 'r') as file:
                    # Read the stored hash and salt from the file
                    stored_hash, stored_salt = file.readline().strip().split(',')
                    # Hash the provided password with the stored salt
                    hash_attempt = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), bytes.fromhex(stored_salt), 100000)
                    if(stored_hash == hash_attempt.hex()):
                        messagebox.showinfo("Success", "File decrypted successfully!")
                    else:
                        messagebox.showinfo("Failure", "Incorrect password!")
            except Exception as e:
                messagebox.showerror("Error", f"Error occurred while reading the file: {e}")
        else:
            messagebox.showwarning("Warning", "No password entered.")

def ask_password():
    password = simpledialog.askstring("Password", "Enter password:", show='*')
    return password

def init_new_file():
    file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
    if(file_path):
        try:
            password = ask_password()
            salt = secrets.token_bytes(32)
            hashed_password = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
            with open(file_path, 'w') as file:
                file.write(f"{hashed_password.hex()}, {salt.hex()}")
                
                
        except Exception as e:
            messagebox.showerror("Error", f"Error occurred while creating the file: {e}")
    

def main():
    # Your main program logic goes here
    root = tk.Tk()
    root.title("Password Manager")

    # Create a menu bar
    menubar = tk.Menu(root)
    root.config(menu=menubar)

    # Create menubar
    menubar = tk.Menu(root)
    root.config(menu=menubar)

    menubar.add_command(label="Open File", command=open_file)
    menubar.add_command(label="New Passwords File", command=init_new_file)

    # Run the application
    root.mainloop()


if __name__ == "__main__":
    main()