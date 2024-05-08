# Password Manager, Secure programming project work

This is simple password manager done as programming work for the secure programming course. The program allows storing passwords as encrypted text in a file using AES256-EAX encryption. Passwords are stored in file individually with each line representing a password entry with username and assosiated service as encrypted text. First line of the file always contains the hash of master password alongside with the salt. Hashing is done using SHA256 algorithm. 


## Installation and Running the software

1. Install python (3.x) and pip
2. Clone the code from GitHub
3. Install required libraries with, pip install -r requirements.txt
4. Now you can run the software with command:  python main.py

## License

This project is licensed under the [MIT License](LICENSE).