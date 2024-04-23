import tkinter as tk
import hashlib
import secrets
from tkinter import filedialog
from tkinter import messagebox
from tkinter import simpledialog
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA512

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
    key = PBKDF2(password, salt, 32, count=1000000, hmac_hash_module=SHA512)
    KEY = key
    
    
def init_new_file(frame):
    global FILE
    file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
    if(file_path):
        try:
            clear_password_frame(frame)
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
        password_entry = tk.Entry(dialog, show="*")
        password_entry.grid(row=2, column=1, padx=5, pady=5)

        password_visibility_button = tk.Button(dialog, text="Show Password" )
        password_visibility_button.config(command=lambda pe=password_entry, pvb = password_visibility_button:  toggle_password_visibility(pe, pvb))
        password_visibility_button.grid(row=2, column=2, padx=5, pady=5)

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
    if FILE != None:
        entry = service+","+username+","+password
        cipher = AES.new(KEY, AES.MODE_EAX)
        nonce = cipher.nonce
        ciphertext, tag = cipher.encrypt_and_digest(entry.encode('utf-8'))
        line = ciphertext.hex()+ "," + nonce.hex() + "," + tag.hex()

        try:
            with open(FILE, "a") as file:
                file.write("\n")
                file.write(line)
            
            populate_frame(frame)
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
    
def clear_password_frame(frame):
    for widget in frame.winfo_children():
        widget.destroy()

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
    

def toggle_password_visibility(password_entry, pvb):
    current_state = password_entry.cget("show")
    if current_state == "*":
        password_entry.config(show="")
        pvb.config(text="Hide Password")
    else:
        password_entry.config(show="*")
        pvb.config(text="Show Password")

def toggle_edit_mode(service_entry, username_entry, password_entry, edit_button, save_button):
    if service_entry["state"] == "readonly":
        # Switch to edit mode
        service_entry.config(state="normal")
        username_entry.config(state="normal")
        password_entry.config(state="normal")
        edit_button.config(state="disabled")
        save_button.config(state="normal")
    else:
        # Switch back to readonly mode
        service_entry.config(state="readonly")
        username_entry.config(state="readonly")
        password_entry.config(state="readonly")
        save_button.config(state="disabled")

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
    toggle_edit_mode(service_entry, username_entry, password_entry, edit_button, save_button)

def populate_frame(frame):
    try:
        
        clear_password_frame(frame)
        i = 0
        passwordsArray = read_and_decrypt_content()
        for passwordEntry in passwordsArray:
             if len(passwordEntry) == 3:
                    card_frame = tk.Frame(frame, relief=tk.RIDGE, borderwidth=2)
                    card_frame.grid(row=i, column=1, padx=5, pady=5, sticky="ew")

                    service_label = tk.Label(card_frame, text="Service:")
                    service_label.grid(row=0, column=0, sticky="w")

                    service_entry = tk.Entry(card_frame, state="normal", width=50, justify="left")
                    service_entry.insert(0, passwordEntry[0])
                    service_entry.config(state="readonly")
                    service_entry.grid(row=0, column=1, sticky="w")

                    username_label = tk.Label(card_frame, text="Username:")
                    username_label.grid(row=1, column=0, sticky="w")

                    username_entry = tk.Entry(card_frame, state="normal", width=50, justify="left")
                    username_entry.insert(0, passwordEntry[1])
                    username_entry.config(state="readonly")
                    username_entry.grid(row=1, column=1, sticky="w")

                    password_label = tk.Label(card_frame, text="Password:")
                    password_label.grid(row=2, column=0, sticky="w")

                    password_entry = tk.Entry(card_frame, state="normal", width=50, justify="left", show="*")
                    password_entry.insert(0, passwordEntry[2])
                    password_entry.config(state="readonly")
                    password_entry.grid(row=2, column=1, sticky="w")

                    save_button = tk.Button(card_frame, text="Save", state="disabled")

                    edit_button = tk.Button(card_frame, text="Edit")

                    edit_button.config(command=lambda se=service_entry, ue=username_entry, pe=password_entry, eb=edit_button, sb=save_button: toggle_edit_mode(se, ue, pe, eb, sb))
                    edit_button.grid(row=3, column=0, pady=5)
                    save_button.config(command=lambda se=service_entry, ue=username_entry, pe=password_entry, eb=edit_button, sb=save_button, index=i+1: save_changes(se, ue, pe, eb, sb, index))
                    save_button.grid(row=3, column=1, pady=5)

                
                    delete_button = tk.Button(card_frame, text="Delete", command=lambda frame=card_frame, index=i+1: delete_card(frame, index))
                    delete_button.grid(row=3, column=2, pady=5)

                    password_visibility_button = tk.Button(card_frame, text="Show Password" )
                    password_visibility_button.config(command=lambda pe=password_entry, pvb = password_visibility_button:  toggle_password_visibility(pe, pvb))
                    password_visibility_button.grid(row=2, column=2, sticky="w", padx=(10, 0))

                    i += 1        

    except Exception as e:
        messagebox.showerror("Error", f"Error occurred: {e}")

def change_password():
    if FILE is not None:
        try:
            password = ask_password()
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
    clear_password_frame(frame)
    FILE = None
    KEY = None

def main():
    root = tk.Tk()
    root.title("Password Manager")
    root.geometry("600x600")

    # Create a frame for the left section (buttons)
    left_frame = tk.Frame(root)
    left_frame.grid(row=0, column=0, padx=5, pady=5, sticky="n")

    # Add "Add Password Entry" button to the left section
    
    

    # Create menubar buttons and add them to the left section
    open_file_button = tk.Button(left_frame, text="Open File", command=lambda: open_file(inner_frame))
    open_file_button.pack(fill=tk.X, padx=5, pady=5)
    new_file_button = tk.Button(left_frame, text="New Passwords File", command=lambda:init_new_file(inner_frame))
    new_file_button.pack(fill=tk.X, padx=5, pady=5)
    add_password_button = tk.Button(left_frame, text="Add Password Entry", command=lambda: add_password_entry(inner_frame))
    add_password_button.pack(fill=tk.X, padx=5, pady=5)
    change_password_button = tk.Button(left_frame, text="Change Password", command=change_password)
    change_password_button.pack(fill=tk.X, padx=5, pady=5)
    clear_button = tk.Button(left_frame, text="Clear all", command=lambda:clear_passwords(inner_frame))
    clear_button.pack(fill=tk.X, padx=5, pady=5)

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