#Vault program stub
from Tkinter import *


class Application(Frame):

        def setup_screen(self):
                #check for encrypted file
                #if there is none, ask for password twice
                #if there is, ask for password

        def start_screen(self):
                self.password_label = Label(self, text="Password:", fg="light green", 
                                          width=60, height=2, font=("Ariel", 20))

                master_password = ''
                raw_input("Enter your password:", master_password)

                if master_password != "dog":
                        invalid_password(self)

                


        def __init__(self, master=None):
                Frame.__init__(self, master)
                self.pack()
                self.start_screen()



root = Tk()
app = Application(master=root)
root.title("Vault Password Manager")
root.minsize(width=600, height=600)
root.maxsize(width=600, height=600)
app.mainloop()