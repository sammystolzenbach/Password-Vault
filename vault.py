#Vault program stub
from tkinter import *
import os
import sys, getopt
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util import Counter
from Crypto.Util import Padding
import re

class Vault(Frame):

    #if program is already set up
    def start_screen(self):
        self.parse_file("passwords.hex")
        self.line_count = 0
        self.attempts = 0

        # start_screen GUI #
        self.frame = Frame(self.master, bg="#282828")
        self.headLbl = Label(self.frame, text="Vault Password Manager", 
                             bg="black", fg="white", font=("Courier New", 20))
        self.headLbl.pack(side=TOP, fill=X)
        self.pswd_frame = Frame(self.frame, bg="#282828")
        self.pswd_label = Label(self.pswd_frame, height=2, bg="#282828",
                                text="Please enter your password", fg="white",
                                font=("Courier New", 18))
        self.pswd_label.pack(side=TOP, fill=X)
        self.password_input = StringVar()
        self.password_box = Entry(self.pswd_frame, textvariable=self.password_input,
                                  show='*')
        self.password_box.bind('<Return>', self.login)
        self.password_box.pack(side=TOP)
        self.validated = StringVar()
        self.repeat_label = Label(self.pswd_frame, height=2, bg="#282828",
                                  textvariable=self.validated, fg="white", 
                                  font=("Courier New", 18))
        self.repeat_label.pack(side=TOP)
        self.pswd_frame.pack(expand=YES, fill=BOTH, pady=100)
        self.frame.pack(expand=YES, fill=BOTH)

    def setup_screen(self):
        self.frame = Frame(self.master, bg="#282828")
        self.headLbl = Label(self.frame, bg="black", fg="white",
                             text="Vault Password Manager Setup", 
                             font=("Courier New", 20))
        self.headLbl.pack(side=TOP, fill=X)
        self.pswd_frame = Frame(self.frame, bg="#282828")
        self.pswd_label = Label(self.pswd_frame, height=2, bg="#282828",
                                text="Please enter a password", fg="white", 
                                font=("Courier New", 18))
        self.pswd_label.pack(side=TOP, fill=X)
        self.password_one = StringVar()
        self.password1_box = Entry(self.pswd_frame,
                                   textvariable=self.password_one, show='*')
        self.password1_box.pack(side=TOP)
        self.repeat_label = Label(self.pswd_frame, height=2, bg="#282828",
                                  text="Enter password again", fg="white", 
                                  font=("Courier New", 18))
        self.repeat_label.pack(side=TOP)
        self.password_two = StringVar()
        self.password2_box = Entry(self.pswd_frame, 
                                   textvariable=self.password_two, show='*')
        self.password2_box.bind('<Return>', self.password_setup)
        self.password2_box.pack(side=TOP)
        self.pswd_frame.pack(expand=YES, fill=BOTH, pady=100)
        self.frame.pack(expand=YES, fill=BOTH)

    def main_screen(self):
        self.frame = Frame(self.master, bg="#282828")
        self.headLbl = Label(self.frame, bg="black", fg="white",
                             text="Vault - Home", 
                             font=("Courier New", 20))

    def add_account_screen(self):
        self.frame = Frame(self.master, bg="#282828")
        self.headLbl = Label(self.frame, bg="black", fg="white",
                             text="Vault - Add account", 
                             font=("Courier New", 20))

    def search_screen(self):
        self.frame = Frame(self.master, bg="#282828")
        self.headLbl = Label(self.frame, bg="black", fg="white",
                             text="Vault - Home", 
                             font=("Courier New", 20))

    def strength_validated(self, password):
        if re.match(r'!@#%&*()_~?><{}[]^\w+$', password):
            if len(password) > 11 and len(password < 33):
                if re.match(r'1234567890'):
                    print('Success')
                else:
                    print('Password must have at least 1 number')
            else:
                print('Password must be between 12 and 32 characters')
        else:
            print('Password must have at least 1 special character')


    def password_setup(self, event):
        pass_1 = self.password_one.get()
        pass_2 = self.password_two.get()

        # add a label for error message and for password strength
        if (pass_1 != pass_2):
            print("passwords don't match")
        else:
            print("passwords match!")
            self.create_derived_key(pass_2, "passwords.hex")
            self.frame.destroy()
            self.start_screen()

    def login(self, event):
        success = False
        self.password_attempt = self.password_input.get()
        print("attempts: ", self.attempts)

        if (self.attempts >= 3):
            self.validated.set("3 attempts exceeded. Account locked.")
        else:
            success = self.validate_login(self.password_attempt)
            if (not success):
                self.validated.set("Invalid password.")
                self.attempts = self.attempts + 1
            else:
                self.validated.set("Success")


    def create_derived_key(self, master_pass, password_file):
        master_pass = master_pass.encode('utf-8')   #MAY NEED DIFFERENT ENCODING .hex()
        padded_master_pass = Padding.pad(master_pass, AES.block_size)
        salt = Random.get_random_bytes(8)    #Create random salt
        master_iv = Random.get_random_bytes(AES.block_size)    
        derived_key = PBKDF2(master_pass, salt, count=1000)  #use PBKDFS with salt to make master password to derived key
        cipher = AES.new(derived_key, AES.MODE_CBC, master_iv)
        enc_padded_master_pass = cipher.encrypt(padded_master_pass)   #Encrypt master password with AES.CTR
        iv_cipher = AES.new(derived_key, AES.MODE_ECB)
        enc_master_iv = iv_cipher.encrypt(master_iv)
        ofile = open(password_file, 'wb')
        length_enc_padded_master_pass = len(enc_padded_master_pass).to_bytes(2, 'big')

        print("length of encrypted master pass", len(enc_padded_master_pass))
        print(length_enc_padded_master_pass)
        ofile.write(salt + enc_master_iv + length_enc_padded_master_pass + enc_padded_master_pass)     #write out to file
        ofile.write(b'\n')
        ofile.close()
    #** Make sure plaintext of master password not in memory for
    #too long!! **

    def parse_file(self, password_file):
        ifile = open(password_file, 'rb')
        file_content = ifile.read()
        self.salt = file_content[:8]
        self.enc_iv = file_content[8:24]
        # update this basedon len(enc padded master pass)
        length_enc_padded_master_pass = int.from_bytes(file_content[24:26], byteorder='big')
        print("in parse file", length_enc_padded_master_pass)
        self.enc_master_pass = file_content[26:(26+length_enc_padded_master_pass)]

    def validate_login(self, password_input):
        self.derived_key = PBKDF2(password_input, self.salt, count=1000)
        iv_cipher = AES.new(self.derived_key, AES.MODE_ECB)
        self.master_iv = iv_cipher.decrypt(self.enc_iv)
        cipher = AES.new(self.derived_key, AES.MODE_CBC, self.master_iv)
        padded_master_pass = cipher.decrypt(self.enc_master_pass)

        try:
            master_pass = Padding.unpad(padded_master_pass, AES.block_size)
        except ValueError:
            return False
        else:
            master_pass = master_pass.decode('ascii')
            if(master_pass == password_input):
                master_pass = "" # to reduce time master password is in memory
                return True
            else:
                return False
    def copy_pass_to_clipboard(self, password): 
        r = Tk()
        r.withdraw()
        r.clipboard_clear()
        r.clipboard_append(password)
        r.update() # now it stays on the clipboard after the window is closed
        r.destroy()  
          
    def enc_and_add_password(self, new_password, password_file, derived_key):
        padded_new_password = Padding.pad(new_password, AES.block_size)     
        iv = Random.get_random_bytes(AES.block_size)
        cipher = AES.new(derived_key, AES.MODE_CBC, iv)
        enc_padded_new_password = cipher.encrypt(padded_new_password)
        with open(password_file, "a") as myfile:        
            myfile.write(iv+enc_padded_new_password)    # Append clear iv and encrypted password to file
            myfile.write(b'\n') 
     
    def add_username_url_password(self, url, username, password, password_file, account_file): 
    self.line_count += 1
    self.enc_and_add_password(password, password_file, self.derived_key)
    with open(account_file, "a") as myfile:
        myfile.write(self.line_count+" USERNAME:"+username+" | URL:"+url)
            
    def __init__(self, master):
        Frame.__init__(self, master)               
        self.master = master
        self.pack()

        #check if setup is needed
        if (os.path.isfile("./passwords.hex")):
            self.start_screen()
        else:
            self.setup_screen()
 
root = Tk()
app = Vault(root)
root.title("Password Manager")
root.minsize(width=500, height=500)
root.maxsize(width=500, height=500)
root.mainloop()


'''    Program setup:
        - Detect if theres a current encrypted password file, if so, move on
        Function: 
            Takes in the user's new master password with restrictions
            Read and validate
        Function:
            Create random salt
            Make a random IV
            use PBKDFS with salt to make master password to derived key
            Encrypt master password and IV with ECB
            write out to file
            ** Make sure plaintext of master password not in memory for
                too long!! **

        Function:
            reads in and parses encrypted file so that we have
            the salt, the iv, and the stored ENC master password

    Program start:
        Function:
            Takes in password
            Uses salt to generate derived key P
            Uses derived password P to decrypt IV with AES_ECB
            Uses IV and P to decrypt master password with AES_CBC
            Sees if password = master password
        Repeat if wrong, if rejected 3 times, send email?

        Function:
            Opens the program window for searching/adding new things

    Program options:
        Create new account (enter username, url, password)
        Create new password for account
        Search for account password
            - copy to clipboard '''
