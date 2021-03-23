from cryptography.fernet import Fernet



def GenerateKey():
    """
    Generates a key and save it into a file
    """
    key = Fernet.generate_key()
    with open("secret.key", "wb") as keyFile:
        keyFile.write(key)

def LoadKey():
    return open("secret.key", "rb").read()

def GetMessage():
    plaintext = input("Enter your plaintext message.")
    print(plaintext)

    return plaintext

def EncryptMessage(message):
    key = LoadKey()
    encodedMessage = message.encode()
    f = Fernet(key)
    ciphertext = f.encrypt(encodedMessage)
    print(ciphertext)
    with open("ciphertext.txt", "wb") as ciphertextFile:
        ciphertextFile.write(ciphertext)

    
    return ciphertext

def DecryptMessage(ciphertext):
    key = LoadKey()
    f = Fernet(key)
    plaintext = f.decrypt(ciphertext)
    plaintext = plaintext.decode()
    print(plaintext)

    return plaintext

def ClearVariable(toBeCleared):
    toBeCleared = ""


if __name__ == "__main__":
    GenerateKey()
    plaintext = GetMessage()
    ciphertext = EncryptMessage(plaintext)
    ClearVariable(plaintext)
    message = DecryptMessage(ciphertext)