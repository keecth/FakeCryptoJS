import base64
import binascii
from gmssl import sm4

class SM4_Crypt(Exception):

    def __init__(self, key: str, iv: str):
        """
        设置 Key 和 IV
        :param key: 16 字节长度的 String , 只能包含大小写英文、阿拉伯数字
        :param iv: 16 字节长度的 String , 只能包含大小写英文、阿拉伯数字
        :return: bool
        """
        self._KEY = binascii.unhexlify(key)
        self._IV = binascii.unhexlify(iv)
        self._SM4_CRYPT = sm4.CryptSM4()

    def encrypt_ECB_base64(self, data: str) -> str:
        """
        进行 ECB 方式的 SM4 加密操作
        :param data: String 格式的原文 data
        :return: String 格式的密文 enc_data
        """
        data_utf8 = data.encode("utf-8")
        self._SM4_CRYPT.set_key(self._KEY, sm4.SM4_ENCRYPT)
        enc_data = self._SM4_CRYPT.crypt_ecb(data_utf8)  # bytes类型
        enc_data=base64.b64encode(enc_data).decode()
        return enc_data

    def decrypt_ECB_base64(self, enc_data: str) -> str:
        """
        进行 ECB 方式的 SM4 解密操作
        :param enc_data: String 格式的密文 enc_data
        :return: String 格式的原文 data
        """
        enc_data = base64.b64decode(enc_data)
        self._SM4_CRYPT.set_key(self._KEY, sm4.SM4_DECRYPT)
        dec_data = self._SM4_CRYPT.crypt_ecb(enc_data)  # bytes类型
        return dec_data.decode().strip()

    def encrypt_ECB_hex(self, data: str) -> str:
        """
        进行 ECB 方式的 SM4 加密操作
        :param data: String 格式的原文 data
        :return: String 格式的密文 enc_data
        """
        data_utf8 = data.encode("utf-8")
        self._SM4_CRYPT.set_key(self._KEY, sm4.SM4_ENCRYPT)
        enc_data = self._SM4_CRYPT.crypt_ecb(data_utf8)  # bytes类型
        return binascii.hexlify(enc_data).decode()

    def decrypt_ECB_hex(self, enc_data: str) -> str:
        """
        进行 ECB 方式的 SM4 解密操作
        :param enc_data: String 格式的密文 enc_data
        :return: String 格式的原文 data
        """
        enc_data = binascii.unhexlify(enc_data)
        self._SM4_CRYPT.set_key(self._KEY, sm4.SM4_DECRYPT)
        dec_data = self._SM4_CRYPT.crypt_ecb(enc_data)  # bytes类型
        return dec_data.decode().strip()

    def encrypt_CBC_base64(self, data: str) -> str:
        """
        进行 CBC 方式的 SM4 加密操作
        :param data: String 格式的原文 data
        :return: String 格式的密文 enc_data
        """
        data_utf8 = data.encode("utf-8")
        self._SM4_CRYPT.set_key(self._KEY, sm4.SM4_ENCRYPT)
        enc_data = self._SM4_CRYPT.crypt_cbc(self._IV, data_utf8)
        enc_data=base64.b64encode(enc_data).decode()
        return enc_data

    def decrypt_CBC_base64(self, enc_data: str) -> str:
        """
        进行 CBC 方式的 SM4 解密操作
        :param enc_data: String 格式的密文 enc_data
        :return: String 格式的原文 data
        """
        enc_data = base64.b64decode(enc_data)
        self._SM4_CRYPT.set_key(self._KEY, sm4.SM4_DECRYPT)
        dec_data = self._SM4_CRYPT.crypt_cbc(self._IV, enc_data)
        return dec_data.decode()

    def encrypt_CBC_hex(self, data: str) -> str:
        """
        进行 CBC 方式的 SM4 加密操作
        :param data: String 格式的原文 data
        :return: String 格式的密文 enc_data
        """
        data_utf8 = data.encode("utf-8")
        self._SM4_CRYPT.set_key(self._KEY, sm4.SM4_ENCRYPT)
        enc_data = self._SM4_CRYPT.crypt_cbc(self._IV, data_utf8)
        return binascii.hexlify(enc_data).decode()

    def decrypt_CBC_hex(self, enc_data: str) -> str:
        """
        进行 CBC 方式的 SM4 解密操作
        :param enc_data: String 格式的密文 enc_data
        :return: String 格式的原文 data
        """

        enc_data = binascii.unhexlify(enc_data)
        self._SM4_CRYPT.set_key(self._KEY, sm4.SM4_DECRYPT)
        dec_data = self._SM4_CRYPT.crypt_cbc(self._IV, enc_data)
        return dec_data.decode()


# """
# SM4
# """
def main():
    data = """{"schoolId":"17822086828032"}"""
    sm4_crypt = SM4_Crypt("5dea70b8500e0f1990092906f7bf29d9","5dea70b8500e0f1990092906f7bf29d9")

    enc_data = sm4_crypt.encrypt_ECB_base64(data)
    print("enc_data: " + enc_data)
    dec_data = sm4_crypt.decrypt_ECB_base64(enc_data)
    print("dec_data: " + dec_data)
    if data == dec_data:
        print("data == dec_data: True")

    enc_data = sm4_crypt.encrypt_ECB_hex(data)
    print("enc_data: " + enc_data)
    dec_data = sm4_crypt.decrypt_ECB_hex(enc_data)
    print("dec_data: " + dec_data)
    if data == dec_data:
        print("data == dec_data: True")

    enc_data = sm4_crypt.encrypt_CBC_base64(data)
    print("enc_data: " + enc_data)
    dec_data = sm4_crypt.decrypt_CBC_base64(enc_data)
    print("dec_data: " + dec_data)
    if data == dec_data:
        print("data == dec_data: True")

    enc_data = sm4_crypt.encrypt_CBC_hex(data)
    print("enc_data: " + enc_data)
    dec_data = sm4_crypt.decrypt_CBC_hex(enc_data)
    print("dec_data: " + dec_data)
    if data == dec_data:
        print("data == dec_data: True")

if __name__ == '__main__':
    main()
