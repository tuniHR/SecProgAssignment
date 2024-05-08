# Password Manager

This is simple password manager done as programming work for the secure programming course. The program allows storing passwords as encrypted text in a file using AES256-EAX encryption. Passwords are stored in file individually with each line representing a password entry with username and assosiated service as encrypted text. First line of the file always contains the hash of master password alongside with the salt. 


## Installation and running the software

1. Install python, tested and developed with 3.10.4 but should work with 3.x
2. Clone the code from GitHub
3. Install required libraries with:  pip install -r requirements.txt
4. Now you can run the software with command:  python main.py

## How to use

To start saving passwords in encrypted form, first new password file must be created or existing password file opened. If there are saved passwords on the file, the manager will show them with username and service that that password is assosiated with. The password is hidden by default, but can be shown as plaintext if desired. New entries added with click of a button and filling the information required fields (service and password). 

## License

This project is licensed under the [MIT License](LICENSE).