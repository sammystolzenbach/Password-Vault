#Vault program stub
from tkinter import *
#from PIL import ImageTk, Image
import os

class Vault(Frame):

    #if program is already set up
    def start_screen(self):
        #master frame for start screen
        self.frame = Frame(self.master, bg="dark grey")

        self.headLbl = Label(self.frame, text="Vault Password Manager", 
                             bg="black", fg="white", font=("Comic Sans MS", 20))
        self.headLbl.pack(side=TOP, fill=X)
        self.pswd_frame = Frame(self.frame, bg="dark grey")
        self.pswd_label = Label(self.pswd_frame, text="Please enter your password", 
                                height=2, bg="dark grey", fg="white", 
                                font=("Comic Sans MS", 15))
        self.pswd_label.pack(side=TOP, fill=X)
        
        self.password_box = Entry(self.pswd_frame, show='*')
        self.password_box.bind('<Return>', self.login)
        self.password_box.pack(side=TOP)

        self.pswd_frame.pack(expand=YES, fill=BOTH)
        self.frame.pack(expand=YES, fill=BOTH)

    def login(self, event):
        print("test")

 
    def __init__(self, master):
        Frame.__init__(self, master)               
        self.master = master
        self.pack()
        #check if setup is needed
        self.start_screen()
 






root = Tk()
app = Vault(root)
root.title("Password Manager")
root.minsize(width=500, height=500)
root.maxsize(width=500, height=500)
root.mainloop()

import sys, getopt
from Crypto.Cipher import AES
from Crypto.Hash import SHA256, HMAC
from Crypto import Random
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util import Counter

'''    Program setup:
        - Detect if theres a current encrypted password file, if so, move on
        Function: 
            Takes in the user's new master password with restrictions
            Read and validate
'''
def create_derived_key(master_pass,password_file):
    master_pass = master_pass.encode('utf-8')   #MAY NEED DIFFERENT ENCODING .hex()
    salt = Random.get_random_bytes(8)    #Create random salt
    nonce = Random.get_random_bytes(8)    #Make a random nonce
    derived_key = PBKDF2(master_pass, salt, count=1000)  #use PBKDFS with salt to make master password to derived key
    ctr = Counter.new(64, prefix=nonce, initial_value=0)
    cipher = AES.new(derived_key, AES.MODE_CTR, counter=ctr)
    enc_master_pass = cipher.encrypt(master_pass)   #Encrypt master password with AES.CTR
    ofile = open(password_file, 'wb')
    ofile.write(salt + nonce + enc_master_pass)     #write out to file
    ofile.close()
    #** Make sure plaintext of master password not in memory for
    #too long!! **
'''
        Function:
            reads in and parses encrypted file so that we have
            the salt, the iv, and the stored ENC master password

    Program start:
        Function:
            Takes in password
            Uses salt to generate derived password P
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