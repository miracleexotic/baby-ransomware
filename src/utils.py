# -*- coding: utf-8 -*-
"""Cryptography with Aes and Rsa.

This module is build for CyberSec project in SUT.

Example:
    :: --- Get RSA --- ::
    rsa = Rsa.getRSAKeyPair('RSA/private_key.pem', 'RSA/public_key.pem')

    :: --- Encrypt --- ::
    aes = Aes.genarateKeyAndIV(32)
    print(aes.key, len(aes.key))
    aes.encrypt('1.jpg')

    with open('LocalKey', 'wb') as f:
        f.write(aes.key+aes.iv)

    rsa.encrypt('LocalKey')

    :: --- Decrypt --- ::
    rsa.decrypt('LocalKey')

    aes = Aes.getSecretKey(32, 'LocalKey')
    print(aes.key, len(aes.key))
    aes.decrypt('1.jpg')

Todo:
    * None

"""

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from typing import TypeVar, Type


T = TypeVar('T', bound='Aes')

class Aes():
    """Encryption with AES.

    Attributes:
        key (bytes): The initialization key(Random).
        iv (bytes): The initialization vector to use for encryption or decryption(Random). Defaults to None.

    """

    def __init__(self, size: int, key: bytes, iv: bytes = None) -> None:
        """AES Cipher.

        Args:
            size (int): Key size.
            key (bytes): The initialization key(Random).
            iv (bytes): The initialization vector to use for encryption or decryption(Random). Defaults to None.
        
        """
        self._size = size
        self.key = key
        self.iv = iv
    
    @classmethod
    def genarateKeyAndIV(cls: Type[T], key_size: int) -> T:
        """Genarate Key and IV.
        
        Args:
            key_size (int): Key size.

        Returns:
            T: Class instance of Aes.
        
        """
        key = get_random_bytes(key_size)
        iv = AES.new(key, AES.MODE_CBC).iv
        return cls(key_size, key, iv)

    @classmethod
    def getSecretKey(cls: Type[T], key_size: int, aesFile: str) -> T:
        """Get SecretKey from encrypt file by PublicKey.
        
        Args:
            key_size (int): Key size.
            aesFile (str): File path of Aes file.

        Returns:
            T: Class instance of Aes.
        
        """
        with open(aesFile, 'rb') as f:
            key = f.read(key_size)
            iv = f.read(16)
        return cls(key_size, key, iv)

    def encrypt(self, file: str):
        """Encryption file with key and iv.
        
        Args:
            file (str): File for encryption.

        """
        # create encoder with key and iv
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)

        # open file and get data
        with open(file, 'rb') as f:
            data = f.read()

        # padding to 16 bytes
        data = pad(data, AES.block_size)

        # encrypt data
        e_data = cipher.encrypt(data)

        # open file and write bytes with encrypt
        with open(file, 'wb') as f:
            f.write(self.iv)
            f.write(e_data)

    def decrypt(self, file: str):
        """Decryption file with key and iv.
        
        Args:
            file (str): File for decryption.

        """
        # open file and get data
        with open(file, 'rb') as f:
            iv = f.read(16) # get iv of each file stored in first 16 bytes of file.
            e_data = f.read()

        # create decoder with iv
        ciper = AES.new(self.key, AES.MODE_CBC, iv)

        # decrypt data
        data = ciper.decrypt(e_data)

        # reverse order
        data = unpad(data, AES.block_size)

        # save decrypt data into file
        with open(file, 'wb') as f:
            f.write(data)


T = TypeVar('T', bound='Rsa')

class Rsa():
    """Encryption with RSA.

    Attributes:
        privateKey (bytes): The private key bytes object.
        publicKey (bytes): The public key bytes object.

    """

    def __init__(self, size: int, privateKey: bytes, publicKey: bytes) -> None:
        """Rsa Cipher.

        Args:
            size (int): Key size.
            privateKey (bytes): The private key bytes object.
            publicKey (bytes): The public key bytes object.
        
        """
        self._size = size
        self.privateKey = privateKey
        self.publicKey = publicKey

    @classmethod
    def genarateRSA(cls: Type[T], size: int) -> T:
        """Genarate a Public/ Private key pair.
        
        Args:
            size (int): Key size.

        Returns:
            T: Class instance of Aes.

        """
        #Generate a public/ private key pair using 2048 bits key length (256 bytes)
        new_key = RSA.generate(size)

        #The private key in PEM format
        private_key = new_key.exportKey("PEM")

        with open("private_key.pem", "wb") as f:
            f.write(private_key)

        #The public key in PEM Format
        public_key = new_key.publickey().exportKey("PEM")

        with open("public_key.pem", "wb") as f:
            f.write(public_key)

        return cls(size, private_key, public_key)

    @classmethod
    def getRSAKeyPair(cls: Type[T], privateFile: str, publicFile: str) -> T:
        """Get a Public/ Private key pair from file.
        
        Args:
            privateFile (str): File path to private file.
            publicFile (str): File path to public file.

        Returns:
            T: Class instance of Aes.

        """
        # get private rsa key
        with open(privateFile, 'rb') as f:
            bytesPrvKey = f.read()
        
        # get public rsa key
        with open(publicFile, 'rb') as f:
            bytesPubKey = f.read()

        # get size of rsa key
        size = RSA.import_key(bytesPubKey).size_in_bits()

        return cls(size, bytesPrvKey, bytesPubKey)

    def encrypt(self, file: str):
        """Encryption file with public key.
        
        Args:
            file (str): File for encryption.
        
        """
        # get public rsa key
        rsaPubKey = RSA.import_key(self.publicKey)

        # create encoder with RSA public key
        rsaCipher = PKCS1_OAEP.new(rsaPubKey)

        # get data from file
        with open(file, 'rb') as f:
            data = f.read()

        # padding data using OAEP padding with b' ' for (bytes/8) - 42
        # A 2048-bit key can encrypt up to (2048/8) – 42 = 256 – 42 = 214 bytes.
        pad = round((self._size/8))-42
        if len(data) < pad:
            data += (b' ' * (pad - len(data)))
        elif len(data) > pad:
            raise Exception('An error occurred: lenght of data to encrypt > maximum data can encrypt.')
        else:
            pass # data == pad

        # encrypt data
        e_data = rsaCipher.encrypt(data)

        # save encrypt data to file
        with open(file, 'wb') as f:
            f.write(e_data)

    def decrypt(self, file: str):
        """Decryption file with private key.
        
        Args:
            file (str): File for decryption.
        
        """
        # get private rsa key
        rsaPrvKey = RSA.import_key(self.privateKey)

        # create decoder with RSA private key
        rsaCipher = PKCS1_OAEP.new(rsaPrvKey)

        # get data from file
        with open(file, 'rb') as f:
            e_data = f.read()

        # decrypt data with rsa private key
        data = rsaCipher.decrypt(e_data)

        # save decrypt data to file
        with open(file, 'wb') as f:
            f.write(data)
        

if __name__ == '__main__':
    # --- Get RSA ---
    rsa = Rsa.getRSAKeyPair('RSA/private_key.pem', 'RSA/public_key.pem')

    # --- Encrypt ---
    aes = Aes.genarateKeyAndIV(32)
    print(aes.key, len(aes.key))
    aes.encrypt('1.jpg')

    with open('LocalKey', 'wb') as f:
        f.write(aes.key+aes.iv)

    rsa.encrypt('LocalKey')

    # --- Decrypt ---
    rsa.decrypt('LocalKey')

    aes = Aes.getSecretKey(32, 'LocalKey')
    print(aes.key, len(aes.key))
    aes.decrypt('1.jpg')




