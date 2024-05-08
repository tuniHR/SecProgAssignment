# Password Manager

This is simple password manager done as programming work for the secure programming course. The program allows for easy storing passwords as encrypted text in a file using AES256-EAX encryption. This is locally run application with no account or addtional setup needed. Passwords are stored in file individually with each line representing a password entry with username and assosiated service as encrypted text. First line of the file always contains the hash of master password alongside with the salt. Encrypted password files are safe to share or synchronize through service but it is recommended take care that only the owner should have access to this file. Each file always has its own master password as there is no account system implemented.


## Installation and running the software

1. Install python, tested and developed with 3.10.4 but should work with 3.x
2. Clone the code from GitHub
3. Install required libraries with:  pip install -r requirements.txt
4. Now you can run the software with command:  python main.py

## How to use

To start saving passwords in encrypted form, first new password file must be created or existing password file opened. When creating a new password file the user will be asked to type the master password for that specific file. This password should be made as secure as possible as it is responsible for securing the other passwords. If there are saved passwords on opened file, the manager will show them with username and service that that password is assosiated with. The password is hidden by default, but can be shown as plaintext if desired. New entries added with click of a button and filling the information required fields (service and password). 

## License

This project is licensed under the [MIT License](LICENSE).