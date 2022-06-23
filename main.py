from hashlib import *
from tkinter import *
from tkinter import messagebox
import os
import tkinter as tk
from tkinter import filedialog as f_d
from Crypto.Cipher import AES
import rsa
from Crypto import Random
from Crypto.Util.Padding import *
from base64 import *

global signature1
AES_key = Random.new().read(16)
AES_key = pad(AES_key, AES.block_size)


# AES Encryption File
def Encrypt(file_name, AES_key):
    # Read from file
    print('--------------------------------------------------')
    print("Encryption file Processe.....")
    with open(file_name, 'rb') as entry:
        plain_text = entry.read()
        plain_text = pad(plain_text, AES.block_size)

        # Encrypt msg & generate iv
        Encryptmethod = AES.new(AES_key, AES.MODE_CFB)
        cipher_text = Encryptmethod.encrypt(plain_text)
        iv = b64encode(Encryptmethod.iv).decode('UTF-8')
        cipher_text = b64encode(cipher_text).decode('UTF-8')
        to_write = iv + cipher_text
        entry.close()

        # Write Encrypted msg in new file
        with open("Encrypted_" + namer, 'w') as Encryptedpaintext:
            Encryptedpaintext.write(to_write)
            Encryptedpaintext.close()
        print("Encrypted file")
        print(to_write)
        print('--------------------------------------------------')


# authntiction the file

def Decrypt(Encrypted_file):
    print('--------------------------------------------------')
    print("Decryption AES_Key Processe.....")
    with open(Encrypted_file, 'rb') as entry:
        # Read from file
        iv_cipher_text = entry.read()

        # Seprate iv and cipher_text from each other
        length_cipher_text = len(iv_cipher_text)
        iv = iv_cipher_text[:24]
        iv = b64decode(iv)
        cipher_text = iv_cipher_text[24:length_cipher_text]
        cipher_text = b64decode(cipher_text)
        # Decrypt AES_Key Using RSA

        E_AES_Keyi = open(rf"{'sec_recever_publkey' + V_username}", "rb").read()

        O_AES_Key = D_RSA(E_AES_Keyi, PrivKey)
        print("Done Decryption AES_Key!")
        print(O_AES_Key)
        file1 = open('sender', "r")
        p = file1.read()
        s_PubKey = load_keys_pu(p)

    file99 = open('sender_signature1', "rb")
    s = file99.read()
    if verify(O_AES_Key, s, s_PubKey):
        print('verified signature')
    else:
        print('could not be verified')

    # Decrypt file using CFB mode
    decryptmethod = AES.new(O_AES_Key, AES.MODE_CFB, iv)
    org_plain_text = decryptmethod.decrypt(cipher_text)
    org_plain_text = unpad(org_plain_text, AES.block_size)

    # Write Orginal msg (Decrypted) in new file
    new_file = 'decrypted_' + V_username
    with open(new_file, 'wb') as Orginal:
        Orginal.write(org_plain_text)
        Orginal.close()
    prsent_text(new_file)


def prsent_text(new_file):
    print('--------------------------------------------------')
    print("Done Decryption file!")
    global file_screen
    file_screen = Toplevel(root)
    file_screen.title("File")
    file_screen.geometry("300x300")
    file99 = open('sender', "r")
    sender = file99.read()
    Label(file_screen, text="To: " + V_username, fg="maroon").place(x=10, y=70)
    Label(file_screen, text="from: " + sender, fg="navy").place(x=100, y=70)
    file_data = open(rf"{new_file}", "rb").read()
    Label(file_screen, text=file_data, bd=4, relief='solid', font='Times 8', padx=10).place(x=10, y=140)
    Button(file_screen, text="Exit", fg="maroon", command=quit).place(x=100, y=200)


def quit():
    if os.path.exists("Encrypted_" + V_username) & os.path.exists('decrypted_' + V_username):
        os.remove("Encrypted_" + V_username)
        os.remove('decrypted_' + V_username)
        os.remove('sender_signature1')
        os.remove('sec_recever_publkey' + V_username)
    else:
        print(".")
    exit()


def check_receive_file():
    global receipt_screen
    receipt_screen = Toplevel(root)
    receipt_screen.title("Inbox")
    receipt_screen.geometry("300x300")
    Label(receipt_screen, text="Dear " + V_username, font=("calibri", 14), fg="maroon").pack()
    tk.Label(receipt_screen, text="Click to check whether there are new files ? ").pack()
    tk.Button(receipt_screen, text="click", command=changetext).pack()


def changetext():
    global new_file
    new_file = "Encrypted_" + V_username
    list_of_files = os.listdir()
    if new_file in list_of_files:
        Label(receipt_screen, text='you have a new file ', fg='green').pack()
        Button(receipt_screen, text="open", command=open_File).pack()
    else:
        Label(receipt_screen, text='you do not have a new file ', fg='red').pack()


def open_File():
    Decrypt(new_file)


def generate_key(N_username):
    PubKeys_Name = N_username + '_PubKeys.pem'
    PrivKeys_Name = N_username + '_PrivKeys.pem'
    (pubKey, privKey) = rsa.newkeys(1024)
    with open(PrivKeys_Name, 'wb') as f:
        f.write(privKey.save_pkcs1('PEM'))

    with open(PubKeys_Name, 'wb') as f:
        f.write(pubKey.save_pkcs1('PEM'))


def load_keys_pu(N_username):
    PubKeys_Name = N_username + '_PubKeys.pem'

    with open(PubKeys_Name, 'rb') as f:
        pubKey = rsa.PublicKey.load_pkcs1(f.read())
    return pubKey


def load_keys_pr(N_username):
    PrivKeys_Name = N_username + '_PrivKeys.pem'
    with open(PrivKeys_Name, 'rb') as f:
        privKey = rsa.PrivateKey.load_pkcs1(f.read())

    return privKey


def E_RSA(key, public_key):
    return rsa.encrypt(key, public_key)


def D_RSA(ciphertext, key):
    try:
        return rsa.decrypt(ciphertext, key)

    # It means that the key was not able to decrypt the message
    except:
        return False


def sign(msg, key):
    return rsa.sign(msg, key, 'SHA-1')


def verify(msg, signo, key):
    try:
        return rsa.verify(msg, signo, key) == 'SHA-1'
    except:
        return False


def chosefile():
    global E_AES_Key
    file = f_d.askopenfile(title="chose file")
    file_name = file.name
    Encrypt(file_name, AES_key)
    signature1 = sign(AES_key, PrivKey)
    # print(signature1)
    file3 = open('sender_signature1', "wb")
    file3.write(signature1)
    file3.close()
    recever_publkey = load_keys_pu(namer)
    print("Encryption AES_Key Processe.....")
    E_AES_Key = E_RSA(AES_key, recever_publkey)
    with open('sec_recever_publkey' + namer, 'wb') as f:
        f.write(E_AES_Key)
        f.close()
    print("Encrypted AES Key")
    print(E_AES_Key)
    print('--------------------------------------------------')


def create_file():
    global recever_publkey
    global namer
    namer = entry3.get()
    list_of_files = os.listdir()
    if namer in list_of_files:
        recever_publkey = load_keys_pu(namer)
        print('Friend: ' + namer)
        print(recever_publkey)
        Label(Send_screen, text='found user', fg='green').place(x=90, y=120)
    else:
        Label(Send_screen, text='user not found', fg='red').place(x=90, y=120)


def send():
    global entry3
    global entry4
    global Send_screen
    global new_file_name
    entry3 = StringVar()
    global Send_screen

    Send_screen = Toplevel(root)
    Send_screen.title("Send file")
    Send_screen.geometry("300x300")
    Label(Send_screen, text="Dear " + V_username + ": Enter details below", font=("calibri", 14),
          fg="maroon").place(
        x=10, y=40)
    file11 = open('sender', "w")
    file11.write(V_username)
    file11.close()
    Label(Send_screen, text="To:", fg="navy").place(x=10, y=100)
    entry4 = Entry(Send_screen, textvariable=entry3)
    entry4.place(x=30, y=100)
    Button(Send_screen, text="Enter", command=create_file).place(x=180, y=100)
    Button(Send_screen, text="Browse Files", command=chosefile).place(x=100, y=170)
    Label(Send_screen, text="Chose File :", fg="navy").place(x=30, y=170)
    Button(Send_screen, text="Exit", fg="maroon", command=exit).place(x=100, y=200)


def menu_fun():
    global login_screen
    login_screen = Toplevel(root)
    login_screen.title("Login")
    login_screen.geometry("300x300")
    global pubKey
    list_of_files = os.listdir()
    if V_username in list_of_files:
        file1 = open(V_username, "r")
        p = file1.read().splitlines()
    pubKey = p[3]
    Label(login_screen, text="Welcom : " + V_username, font=("calibri", 13), fg="maroon").pack()
    Label(login_screen, text="Your Public Key : ").pack()
    Label(login_screen, text="").pack()
    Label(login_screen, text=str(pubKey)).place(x=40, y=60)
    Label(login_screen, text="").pack()
    Label(login_screen, text="if you want to send a text file", bg="gray").pack()
    Label(login_screen, text="").pack()
    Button(login_screen, text="Send file", fg="maroon", height=2, width=10, command=send).pack()
    Label(login_screen, text="").pack()
    Label(login_screen, text=" or check if you have a new message", bg="gray").pack()
    Label(login_screen, text="").pack()
    Button(login_screen, text="Inbox", fg="maroon", height=2, width=10, command=check_receive_file).pack()


def caesarEnPaswod(plainText, shift):
    cipherText = ""
    for ch in plainText:
        if ch.isalpha():
            stayInAlphabet = ord(ch) + shift
        if stayInAlphabet > ord('z'):
            stayInAlphabet -= 26
        finalLetter = chr(stayInAlphabet)
        cipherText += finalLetter

    return cipherText


def register_user():
    global PrivKey, PubKey
    print("working...")
    # decler pu,pr key
    # get username and password
    New_username = username.get()
    New_password = password.get()
    # Open file in write mode
    file = open(New_username, "w")
    file.write("\n")
    # write username and password information into file
    file.write(New_username + "\n")
    file.write(caesarEnPaswod(New_password, 5) + "\n")
    # user generates their pair of private and public key
    generate_key(New_username)
    PrivKey = load_keys_pr(New_username)
    PubKey = load_keys_pu(New_username)
    file.write(str(PubKey) + "\n")
    file.close()
    # file.close()

    username_entry.delete(0, END)
    password_entry.delete(0, END)

    Label(register_screen, text="Registration Success", fg="green", font=("calibri", 11)).pack()


def register():
    # The Toplevel widget work pretty much like Frame,
    # but it is displayed in a separate, top-level window.
    # Such windows usually have title bars, borders, and other “window decorations”.
    # And in argument we have to pass global screen variable
    global username
    global password
    global username_entry
    global password_entry
    global register_screen
    register_screen = Toplevel(root)
    register_screen.title("Register")
    register_screen.geometry("300x250")

    # Set text variables
    username = StringVar()
    password = StringVar()

    # Set label for user's instruction
    Label(register_screen, text="Please enter details below").pack()
    Label(register_screen, text="").pack()

    # Set username label
    username_lable = Label(register_screen, text="Username * ")
    username_lable.pack()

    # Set username entry
    # The Entry widget is a standard Tkinter widget used to enter or display a single line of text.

    username_entry = Entry(register_screen, textvariable=username)
    username_entry.pack()

    # Set password label
    password_lable = Label(register_screen, text="Password * ")
    password_lable.pack()

    # Set password entry
    password_entry = Entry(register_screen, textvariable=password)
    password_entry.pack()

    Label(register_screen, text="").pack()

    # Set register button

    Button(register_screen, text="Register", width=10, height=1, command=register_user).pack()

    register_screen.mainloop()


def varlogin():
    list_of_files = os.listdir()
    global V_username
    global PrivKey
    global PubKey
    V_username = username1.get()
    V_password = password2.get()
    username_input1.delete(0, END)
    password_input2.delete(0, END)

    encpasswod = caesarEnPaswod(V_password, 5)

    if (V_username == "" and V_password == ""):
        messagebox.showinfo("", "Blank Not allowed")


    elif V_username in list_of_files:
        PrivKey = load_keys_pr(V_username)
        PubKey = load_keys_pu(V_username)
        file1 = open(V_username, "r")  # open the file in read mode
        file1_Data = file1.read().splitlines()
        if encpasswod in file1_Data:
            Label(root, text="login successfully", fg="green").place(x=90, y=250)
            menu_fun()

        else:
            messagebox.showinfo("", "Incorrent Username and Password")

    else:
        messagebox.showinfo("", "User not found")



# main scren

# main scren

root = Tk()
root.title("XSecure System")
root.geometry("300x300")
global username1
global password2
username1 = StringVar()
password2 = StringVar()
global username_input1
global password_input2
Label(root, text="Username").place(x=10, y=70)
Label(root, text="Password").place(x=10, y=100)

username_input1 = Entry(root, textvariable=username1)
username_input1.place(x=140, y=70)

password_input2 = Entry(root, textvariable=password2, show='*')
password_input2.place(x=140, y=100)
# password_input2.config(show="*")

Label(root, text="XSecure application", fg="maroon", font=("calibri", 13)).place(x=90, y=10)
Label(root, text="You do not have an Account Register Now!", fg="navy").place(x=30, y=140)
Button(root, text="Register", height=2, width=10, command=register, fg="navy").place(x=150, y=180)
Button(root, text="Login", height=2, width=10, command=varlogin).place(x=50, y=180)

root.mainloop()
