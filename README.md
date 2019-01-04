# Password-Vault
Secure Password Manager

**Please see Vault-Security-Writeup.pdf for a detailed description of the cryptographic features of the application.

Password-Vault was made with Pycryptodome and Tkinter to create a GUI that guides the user through the process of safely storing and retrieving passwords linked with their accounts.

The app relies on a strong master password chosen by the user. Error messages help guide the user through creating and retrieving passwords, and adding accounts. The app will lock after 3 login attempts.
 
# Setup screen

The user must choose a “master” password for the application that has at least 12 characters, special
characters, and numbers.

![Alt text](./screenshots/screen-1.png?raw=true "Setup Screen")

# Adding an account

Users can add their own existing password for an account, or have a strong one generated with random bytes (within the accepted ascii range).

![Alt text](./screenshots/screen-2.png?raw=true "Add Account")

# Retrieving a password

To retrieve a stored password, a user just has to search the user name and URL associated with that account. The password will be copied to the clipboard — never showing the plaintext of the password.

![Alt text](./screenshots/screen-3.png?raw=true "Retrieve Password")

# Secure storage

Passwords are stored in a single encrypted binary file with no “formatting” that leaks information as to where one password starts and one ends. When a user wants to retrieve a password, only the specific block containing that password is decrypted, rather than the entire file. Below is an example of what an encrypted password file looks like.

![Alt text](./screenshots/screen-4.png?raw=true "Password File")
