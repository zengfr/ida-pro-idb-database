import base64
import hashlib
from pyDes import *
import time
import json

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

class My_AES_CBC():
    def __init__(self, key, iv):
        # key 和 iv 必须为 16 位
        self.key = key
        self.mode = AES.MODE_CBC
        self.cryptor = AES.new(self.key, self.mode, iv)

    def encrypt(self, plain_text):
        encode_text = plain_text.encode('utf-8')
        pad_text = pad(encode_text, AES.block_size)
        encrypted_text = self.cryptor.encrypt(pad_text)
        # base64_text = base64.b32encode(encrypted_text)
        return encrypted_text

    def decrypt(self, encrypted_text):
        plain_text = self.cryptor.decrypt(encrypted_text)
        plain_text = unpad(plain_text, AES.block_size).decode()
        return plain_text