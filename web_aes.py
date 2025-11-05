import base64,os
from Crypto.Util.Padding import pad, unpad
import struct
import binascii
from Crypto.Cipher import AES, DES
import re
from urllib import parse

from hashlib import md5
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class AESUtil:
    def __init__(self, key=None, iv=None,b64=None):
        if type(key) == str and b64==None:
            self.key = key.encode("utf-8")
            self.iv = iv.encode("utf-8")

        elif type(key) == str and b64!=None:
            self.key = base64.b64decode(key)
            self.iv = base64.b64decode(iv)
        else:
            key_bytes = b''.join([struct.pack('>I', word & 0xFFFFFFFF) for word in key['words']])
            self.key=key_bytes
            iv_bytes = b''.join([struct.pack('>I', word & 0xFFFFFFFF) for word in iv['words']])
            self.iv = iv_bytes

            # key_words = key["words"]
            # key_sig_bytes = key["sigBytes"]
            # # Convert integers to bytes and concatenate them
            # key_bytes = b''
            # for word in key_words:
            #     key_bytes += struct.pack('>I', word)  # 'I' denotes an unsigned int (4 bytes)
            # # Truncate the key to the specified sigBytes
            # self.key = key_bytes[:key_sig_bytes]
            # # print(self.key.decode())
            # if iv != "":
            #     iv_words = iv["words"]
            #     iv_sig_bytes = iv["sigBytes"]
            #     # Convert integers to bytes and concatenate them
            #     iv_bytes = b''
            #     for word in iv_words:
            #         iv_bytes += struct.pack('>I', word)  # 'I' denotes an unsigned int (4 bytes)
            #     # Truncate the key to the specified sigBytes
            #     self.iv = iv_bytes[:iv_sig_bytes]

    def ecb_encode(self, plaintext, mode="aes"):
        ciphertext = None
        if mode == "aes":
            aes = AES.new(self.key, AES.MODE_ECB)
            ciphertext = aes.encrypt(pad(plaintext.encode("utf-8"), AES.block_size))
        elif mode == "des":
            des = DES.new(self.key, DES.MODE_ECB)
            ciphertext = des.encrypt(pad(plaintext.encode("utf-8"), DES.block_size))
        ciphertext_base64 = base64.encodebytes(ciphertext).decode().replace("\n", "")
        return ciphertext_base64.strip()

    def ecb_decode(self, ciphertext, mode="aes"):
        plaintext = None
        if mode == "aes":
            aes = AES.new(self.key, AES.MODE_ECB)
            plaintext = aes.decrypt(base64.b64decode(ciphertext))
        elif mode == "des":
            des = DES.new(self.key, DES.MODE_ECB)
            plaintext = des.decrypt(base64.b64decode(ciphertext))
        plaintext = re.sub(rb"[\x00-\x1F\x7F]", b"", plaintext)
        return (plaintext.decode("utf-8")).strip()

    def ecb_decode_hex(self, ciphertext, mode="aes"):
        info = binascii.unhexlify(ciphertext)
        plaintext = None
        if mode == "aes":
            aes = AES.new(self.key, AES.MODE_ECB)
            plaintext = aes.decrypt(info)
        elif mode == "des":
            des = DES.new(self.key, DES.MODE_ECB)
            plaintext = des.decrypt(info)
        plaintext = re.sub(rb"[\x00-\x1F\x7F]", b"", plaintext)
        return (plaintext.decode("utf-8")).strip()

    def cbc_encode(self, plaintext, mode="aes"):
        ciphertext = None
        if mode == "aes":
            aes = AES.new(self.key, AES.MODE_CBC, self.iv)
            ciphertext = aes.encrypt(pad(plaintext.encode("utf-8"), AES.block_size))
        elif mode == "des":
            des = DES.new(self.key, DES.MODE_CBC, self.iv)
            ciphertext = des.encrypt(pad(plaintext.encode("utf-8"), DES.block_size))
        ciphertext_base64 = base64.encodebytes(ciphertext).decode().replace("\n", "")
        return ciphertext_base64.strip()

    def cbc_decode(self, ciphertext, mode="aes"):
        plaintext = None
        if mode == "aes":
            aes = AES.new(self.key, AES.MODE_CBC, self.iv)
            plaintext = aes.decrypt(base64.b64decode(ciphertext))
        elif mode == "des":
            des = DES.new(self.key, DES.MODE_CBC, self.iv)
            plaintext = des.decrypt(base64.b64decode(ciphertext))
        plaintext = re.sub(rb"[\x00-\x1F\x7F]", b"", plaintext)
        return (plaintext.decode("utf-8")).strip()


class AESDefault:
    def __init__(self, passphrase=None):
        self.passphrase = passphrase.encode()

    def fn_pad(self, s):
        return s + (16 - len(s) % 16) * chr(16 - len(s) % 16).encode()

    def fn_unpad(self, s):
        return s[0:-ord(s[len(s) - 1:])]

    def bytes_to_key(self, data, salt, output=48):
        assert len(salt) == 8, len(salt)
        data += salt
        key = md5(data).digest()
        final_key = key
        while len(final_key) < output:
            key = md5(key + data).digest()
            final_key += key
        return final_key[:output]

    def encrypt(self, data):
        salt = os.urandom(8)
        # salt = "DFބf$t:".encode()
        key_iv = self.bytes_to_key(self.passphrase, salt, 32 + 16)
        key = key_iv[:32]
        iv = key_iv[32:]
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        encrypted = encryptor.update(self.fn_pad(data.encode())) + encryptor.finalize()
        cipherbyte = base64.b64encode(b"Salted__" + salt + encrypted)
        return cipherbyte.decode()

    def decrypt(self, data):
        data = base64.b64decode(data)
        assert data[:8] == b'Salted__'
        salt = data[8:16]
        key_iv = self.bytes_to_key(self.passphrase, salt, 32 + 16)
        key = key_iv[:32]
        iv = key_iv[32:]
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        plainbyte = self.fn_unpad(decryptor.update(data[16:]) + decryptor.finalize())
        return plainbyte.decode()


def main():
    # 用法一 数组格式的密钥
    key_data = {
    "words": [
        1932851105,
        -1926688403,
        -1998111825,
        -377075010
    ],
    "sigBytes": 16
}
    aes = AESUtil(key=key_data, iv=key_data)
    en="c4xsvnw63OVpgZVyiMrFMpNO4AK/EUpJ8bqeteIdqlxVTBvsbOc88ARGkqMyW+xBzfDAuaK2eFsBvhRAdRRLhdhjCpSSjWvbwWWjFAYRKvfphHMooAk6ve4Jj1FMJ68sk9q9Hy/sk0zWMNSFpTn/XDG87nKbvugt7TEXOQj8w2A="
    print(aes.cbc_decode(en))

    # 用法二 base64格式的密钥
    aes2 = AESUtil(key="czT3oY0pEW2I5zuv6YZKvg==", iv="czT3oY0pEW2I5zuv6YZKvg==",b64=True)
    print(aes2.cbc_decode(en))

    # 用法三 明文格式密钥
    aes3 = AESUtil(key="e19b93bfdb4b4d5b", iv="e19b93bfdb4b4d5b")
    print(aes3.cbc_encode(en))


    # 用法三 cryptojs无需key和iv，默认加密
    aesDf = AESDefault(passphrase="__CryptoJS_Str__")
    print(aesDf.decrypt("U2FsdGVkX19ERt6EZiR0OmLMg8TrImrTKpI0efprqjk="))


if __name__ == '__main__':
    main()
