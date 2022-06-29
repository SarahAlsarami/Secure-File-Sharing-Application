# Secure-File-Sharing-Application
In this project we design a secure file sharing application. Every new user will have a file  that includes (privet and public key, username, and encrypted password). the application  encrypts the messages after it was written by the sender and saves it encrypted in a file to  make sure no one can see the content rather than the receiver. The receiver can decrypt the  message using his privet key

## Sender GUI
He sends the message encrypted and puts his signature on it with his private key

![App Screenshot](https://l.top4top.io/p_2365v2v381.png)

## Recipient GUI

![App Screenshot](https://a.top4top.io/p_2365o59rc2.png)

#### When you finish reading the message, all files related to it will be deleted, and this achieves the principle of security
![App Screenshot](https://a.top4top.io/p_23655bkup1.png)

## Approach and steps to implementation
1 -  User register to the application by entering username and password.

2 -  System open new file, storing user’s name and his encrypted password (use caesar cipher algorithm to encrypt the password).

3 - System creates pair of keys -public key and private key- using RSA libraries and storing these keys in a file.

4 - When user login into the application public key will appear in the home page.

5 - User can choses from two options, if he wants to send a file will click “Send file” 
button, or if he wants to check is there any massage he has received? will click 
“Inbox” button. 

6 - System creates a symmetric-key randomly using the random library, which used in the encryption of the file using AES algorithm implemented in **Encrypt function.**

7 - System encrypt the AES_key created in step 6 using RSA algorithm implemented in 
**E_RSA function** by using receiver’s public key.

8 - When the receiver wants to access a message he has received (encrypted message), the system decrypt the AES_key using RSA algorithm implemented in **D_RSA function** by using receiver’s private key, these decrypted AES_key used in the decryption of the message using AES algorithm implemented in **Decrypt function**.
## Functions
#### Encrypt function

```bash
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

```

#### E_RSA function

```bash
def E_RSA(key, public_key):
    return rsa.encrypt(key, public_key)

```

#### D_RSA function

```bash

def D_RSA(ciphertext, key):
    try:
        return rsa.decrypt(ciphertext, key)

    # It means that the key was not able to decrypt the message
    except:
        return False

```
#### Decrypt function

```bash
  
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
```

## Prepared By 
- Sarah Abdullah Alsarami    samalsarami@sm.imamu.edu.sa
- Asia Omar alrajeh      aonalrajeh@sm.imamu.edu.sa
- Hajar abdullaziz Aljassar  haaaljassar@sm.imamu.edu.sa
## References 
- [Semple GUI python ](https://www.simplifiedpython.net/python-gui-login/)
- [Semple GUI python ](https://www.tutussfunny.com/login-form-using-python-tkinter/)
- [Caesar cipher algorithm](https://stackoverflow.com/questions/8886947/caesar-cipher-function-in-python)
- [AES algorithms]( https://www.youtube.com/watch?app=desktop&v=F2av7TaVc5Q)
- [RSA algorithms]( https://www.section.io/engineering-education/rsa-encryption-and-decryption-in-python)
