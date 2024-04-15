import tkinter as tk
import hashlib
import secrets
import base64
from tkinter import filedialog
from tkinter import messagebox
from tkinter import simpledialog
from tkinter import ttk
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


FILE = None
KEY = None

def open_file(frame):
    global FILE
    file_path = filedialog.askopenfilename(title="Select Password File")
    if file_path:
        password = ask_password()
        if password:
            try:
                 with open(file_path, 'r') as file:
                    # Read the stored hash and salt from the file
                    stored_hash, stored_salt = file.readline().strip().split(',')
                    # Hash the provided password with the stored salt
                    hash_attempt = hashlib.sha256(password.encode('utf-8') + bytes.fromhex(stored_salt)).hexdigest()
                    if(stored_hash == hash_attempt):
                        #messagebox.showinfo("Success", "File decrypted successfully!")
                        FILE = file_path
                        generate_key(password, bytes.fromhex(stored_salt))
                        populate_frame(frame)
                        
                    else:
                        messagebox.showinfo("Failure", "Incorrect password!")
            except Exception as e:
                messagebox.showerror("Error", f"Error occurred while reading the file: {e}")
        else:
            messagebox.showwarning("Warning", "No password entered.")

def ask_password():
    password = simpledialog.askstring("Password", "Enter password:", show='*')
    return password

def generate_key(password, salt):
    global KEY
    kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=480000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))
    KEY = Fernet(key)
    
    
def init_new_file():
    global FILE
    file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
    if(file_path):
        try:
            password = ask_password()
            salt = secrets.token_bytes(32)
            hashed_password = hashlib.sha256(password.encode('utf-8') + salt).hexdigest()
            with open(file_path, 'w') as file:
                file.write(f"{hashed_password}, {salt.hex()}")
                FILE = file_path
                generate_key(password, salt)
                
        except Exception as e:
            messagebox.showerror("Error", f"Error occurred while creating the file: {e}")


def add_password_entry(frame):
    if FILE != None:
        # Create a dialog window
        dialog = tk.Toplevel()
        dialog.title("Add Password Entry")

        # Service entry field
        service_label = tk.Label(dialog, text="Service:")
        service_label.grid(row=0, column=0, padx=5, pady=5)
        service_entry = tk.Entry(dialog)
        service_entry.grid(row=0, column=1, padx=5, pady=5)

        # Username entry field
        username_label = tk.Label(dialog, text="Username:")
        username_label.grid(row=1, column=0, padx=5, pady=5)
        username_entry = tk.Entry(dialog)
        username_entry.grid(row=1, column=1, padx=5, pady=5)

        # Password entry field
        password_label = tk.Label(dialog, text="Password:")
        password_label.grid(row=2, column=0, padx=5, pady=5)
        password_entry = tk.Entry(dialog)
        password_entry.grid(row=2, column=1, padx=5, pady=5)

        # Function to handle button click
        def save_entry():
            service = service_entry.get()
            username = username_entry.get()
            password = password_entry.get()
            if service and password:
                add_entry(service, username, password, frame)
                #messagebox.showinfo("Success", "Password entry added successfully!")
                dialog.destroy()
            else:
                messagebox.showwarning("Warning", "Service and Password are required fields.")

        # Save button
        save_button = tk.Button(dialog, text="Save", command=save_entry)
        save_button.grid(row=3, column=0, columnspan=2, padx=5, pady=5)

def add_entry(service, username, password, frame):
    entry = service+","+username+","+password
    token = KEY.encrypt(entry.encode("utf-8"))
    try:
        with open(FILE, "a") as file:
            file.write("\n")
            file.write(token.hex())
        
        populate_frame(frame)
    except Exception as e:
        messagebox.showinfo("Error", f"Error while writing {e}")


def populate_frame(frame):
    try:
        for widget in frame.winfo_children():
            widget.destroy()
    
        with open(FILE, 'r') as file:
            
            i = 0
            next(file)  # Skip the first line
            for line in file:
                decrypted = KEY.decrypt(bytes.fromhex(line))
                plaintext = decrypted.decode("utf-8").strip().split(",")
                
                if len(plaintext) == 3:
                    card_frame = tk.Frame(frame, relief=tk.RIDGE, borderwidth=2)
                    card_frame.grid(row=i, column=1, padx=5, pady=5, sticky="ew")

                    service_label = tk.Label(card_frame, text="Service:")
                    service_label.grid(row=0, column=0, sticky="w")

                    service_entry = tk.Entry(card_frame, state="normal")
                    service_entry.insert(0, plaintext[0])
                    service_entry.config(state="readonly")
                    service_entry.grid(row=0, column=1, sticky="w")

                    username_label = tk.Label(card_frame, text="Username:")
                    username_label.grid(row=1, column=0, sticky="w")

                    username_entry = tk.Entry(card_frame, state="normal")
                    username_entry.insert(0, plaintext[1])
                    username_entry.config(state="readonly")
                    username_entry.grid(row=1, column=1, sticky="w")

                    password_label = tk.Label(card_frame, text="Password:")
                    password_label.grid(row=2, column=0, sticky="w")

                    password_entry = tk.Entry(card_frame, state="normal")
                    password_entry.insert(0, plaintext[2])
                    password_entry.config(state="readonly")
                    password_entry.grid(row=2, column=1, sticky="w")

                    i += 1

    except Exception as e:
        messagebox.showerror("Error", f"Error occurred while reading the file: {e}")

def main():
    root = tk.Tk()
    root.title("Password Manager")
    root.geometry("600x600")

    # Create a frame for the left section (buttons)
    left_frame = tk.Frame(root)
    left_frame.grid(row=0, column=0, padx=5, pady=5, sticky="n")

    # Add "Add Password Entry" button to the left section
    add_password_button = tk.Button(left_frame, text="Add Password Entry", command=lambda: add_password_entry(inner_frame))
    add_password_button.pack(fill=tk.X, padx=5, pady=5)

    # Create File menu
    file_menu = tk.Menu(root)
    file_menu.add_command(label="Open File", command=lambda: open_file(inner_frame))
    file_menu.add_command(label="New Passwords File", command=init_new_file)

    # Create menubar buttons and add them to the left section
    open_file_button = tk.Button(left_frame, text="Open File", command=lambda: open_file(inner_frame))
    open_file_button.pack(fill=tk.X, padx=5, pady=5)
    new_file_button = tk.Button(left_frame, text="New Passwords File", command=init_new_file)
    new_file_button.pack(fill=tk.X, padx=5, pady=5)

    # Create a frame for the right section (content)
    right_frame = tk.Frame(root)
    right_frame.grid(row=0, column=1, padx=5, pady=5, sticky="nsew")  # Changed sticky from "n" to "nsew"

    # Create a canvas
    canvas = tk.Canvas(right_frame)
    canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

    # Add a scrollbar
    scrollbar = tk.Scrollbar(right_frame, orient=tk.VERTICAL, command=canvas.yview)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    # Create a frame inside the canvas
    inner_frame = tk.Frame(canvas)
    inner_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
    canvas.create_window((0, 0), window=inner_frame, anchor="nw")

    # Configure scrollbar to always be visible
    canvas.configure(yscrollcommand=scrollbar.set)
    

    # Configure grid weights to make right frame expandable
    root.grid_rowconfigure(0, weight=1)
    root.grid_columnconfigure(1, weight=1)

    # Run the application
    root.mainloop()


if __name__ == "__main__":
    main()