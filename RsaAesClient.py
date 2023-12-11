import logging
from typing import Any, Dict
import base64
import hashlib
from typing import Any
from Crypto.Cipher import AES, PKCS1_OAEP, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import unpad
from base64 import b64decode
import os

# from config.ConfigFormat import ConfigFormat


def remove_heading_trailling_lines(value, start_str, end_str):
    return value.replace(start_str,
                         "").replace(end_str, "").replace("\n", "")

sftp_config = {
            "host": "centsftp.centralbank.co.in",
            "username": "spocto_ccc",
            "password": "$p0cto_CCC",
            "port": 22,
            "is_private_key_supported": False,
            "csv_delimiter": ",",
            "is_rsa_aes_enabled": True,
            "rsa_aes_private_key": "MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQCywuDP8v33YTVvBEwgrmF4QANfm1TiAeVzwtcqdVCJUy1X95rFbYQBr10jIar7AP86dXKig55wlfogBAN88U91NWG6j16+hE+z3gszoqqTYC8YuAS0lCkcJT9XvYDJ1PzDCEN/QuXbSH/cCUs/zC/H9k0QtsXI3WW8NDUyAnefuetU0U66xng5EcTqeB4IGQS/7FauERaYKhvQS+mMNIjW9fv35JVzDJvvpw+f1KpGWFVfx+O/Olk7gJ3WmrVQxzUDbDKE3Uc7TudS7Hrnv4QXFzg++nmsJjNU3ofUkFjfxrpFJPgpoNOzcjHYjUDeeGj8hMewXntHESYUe7HTRRc9AgMBAAECggEAUPzYdG3+4KJSXosgYFgQwbWisaCCmuhIB6O47rv6slSUQPvlS1fcDBViiWWZ/KENgPMv7e/aiuBv0yxuVh9Po+b88VQ+FOuF3pQVGB400JMtkzHfs95CJ8W6RmqNHCPaJhQq3E+3KptUjiBJzswXw6zTamScA+5GRreSeCdFAgAqUF/YH3odzU9/o+Kqh8zZlF1UU4w1PK4IJnuX9zGDdZ6eAV4uynOoIv6hPsJx76rBTOdg3Cs8HGqX+JPnN/DOFPhH715uVT7QPz7ciZNR8Uw6lpQNYlXrbCcaKzFbe3aR6F6Bd0TvsKtaX8ekjuc/5bKcUEnrMDrAF6MIp6mM8wKBgQD0UtWJ0v1W9wdoEidW2n1wKc1e+keKbvoyUvYEfnZua16LDhNgK7SnapvxEj4tdXm9jysMAo4FjNfJMhqZqICX96RPqvW3Faa5s3K8yGJ4yAyrYuP5+u3Pc3pT6Xnu6J8tZhSY6UHf4VR/nIpmQlTn2CRVU/Ep5pL5NA1CmirQzwKBgQC7Tey1+3abO+YmlVzz+VnRMntNnx2iqBnCYmgsf1Q1+ZutfdrzGXHgXU6BvdFRbLtjwzVOuXXsilMbfyWOqcWEIEbG4VD5Tt1QzfOU+7MlyBV8++XEgWDl/FkOXNd1e07Evyi0a+VFQkiSssU3eQTF6EOdWwG3LyZTywR/b14iMwKBgQDf2HSkTZamcrVqeBdqz8tVVDdA6XVaM8svCCs2etbu25hHNqIx3lkpedddyyUEaTkcn2sFGeIc26loQGt2lJccpFr6UtvE3iVexjY9GCqAFmjlLTlJ8sim5FoTPznj1WThJ0F/x1X/VGcic72pauR3dePz+XBev02w3Cu59Z18qQKBgQCyIVbIb4EJ+vpToWMIaBDCQmc/l96ATaxJ0HrQLrvwpRUn9vRek8lYHoTGILbL4EOKiiDNYNXEgnytPsuCFPVSRbvp8mim4RjbezJ3crSabuH4vjtzGbQEpWwwm50RDpcHx+C3TZF6v6HzWe7zZbVjXhPHt8A27bFeqUn6w/hbPwKBgQCNaZFuhRReNTo2nQngrNdO6aH3/DWMt+R8xDegd84nqMLQccHnNntUY/XoPKdJzxtwf0/Gwu0BdL9Rm/Nuw//pVtEXt3TP0qBxZdwhULRY80lbcQyBmGs7YxDQhm3wr+vtWLs14GGhZSG6+sRu/i55fBsK+m6zlshLPsYtkVumkg==",
            "rsa_aes_secret_key": "WjH3korhuc0rDEULwf/7+OCqJOIib7OKzaPRkgNQz4rdn6GAMphUIQR10ZOyAhc4HaP21NXY6g6LWRbVcuzULVrQYbcc235QlR+C2EB0pw/mOpRbw6PXjUs21Limk84DoX07w5u61zFXc3Lohqo0O5nVMmKn4ZfujLGHAiXxZXwCFtp/KHxujT5XE1bJLY7GeQoNCVUpLfquwkOPwif1e/bzsBIREhRqc3nxCb7WpRWst5iX3cp8zXBDNxkQHLgjw3tqiCQdNkgsFdk/HOIP7duMXjDnvr8gHSfC9WQKj50CAWlN18FzQaEMFj0tjKWy6hoXSaa+aOq+MJeyEPodkw=="
        }

class RsaAesClient:

    def __init__(self):
        self.__aes_secret_key = ""
        self.__rsa_private_key = None
        self.__block_size = 16

    @property
    def private_key(self):
        rsa_private_key = None
        # sftp_config: Dict[str, Any] = ConfigFormat().sftp_client

        if bool(sftp_config):
            rsa_private_key = sftp_config.get("rsa_aes_private_key")
            print("rsa_private_key",rsa_private_key)

        return rsa_private_key

    def unpad(self, s):
        # helper method to unpad data
        return s[0:-ord(s[-1:])]

    def get_private_key(self, secret_key, salt):
        # method to derive private key from secret key and salt
        try:
            return hashlib.pbkdf2_hmac('SHA256', secret_key.encode(), salt.encode(), 65536, 32)

        except (TypeError, ValueError) as e:
            # handle any exceptions that may occur
            logging.error("Error in get_private_key:", e)

    # method to read RSA keys from file

    def read_rsa_keys(self):
        try:
            # read private key from file
            key = self.private_key

            # extract key data from PEM format and decode from base64
            key = remove_heading_trailling_lines(
                key, "-----BEGIN RSA PRIVATE KEY-----", "-----END RSA PRIVATE KEY-----")

            key = b64decode(key)

            # import key into RSA object
            key = RSA.importKey(key)

            # set private key
            self.__rsa_private_key = key

        except Exception as e:
            # handle any exceptions that may occur
            logging.error("Error reading RSA keys:", e)

    def decryption_using_rsa(self, aesFileName):
        # method to decrypt data using RSA private key
        try:
            # read ciphertext from file
            with open(aesFileName, "r") as f:
                ciphertext = f.read()
            print(ciphertext)

            logging.info(f'Ciphertext successfully read during rsa')

            # create RSA cipher object
            cipher = PKCS1_v1_5.new(self.__rsa_private_key)

            # decrypt ciphertext using RSA private key
            plainText = cipher.decrypt(
                b64decode(ciphertext), "Error decrypting the input string!")

            logging.info(f'Decryption successfully during rsa')

            # assign plaintext to __aes_secret_key
            self.__aes_secret_key = plainText.decode()

        except FileNotFoundError as e:
            # handle file not found error
            logging.error(
                "Error in decryption_using_rsa: file not found", e)

        except IOError as e:
            # handle IO-related errors
            logging.error(
                "Error in decryption_using_rsa: accessing file:", e)
        except Exception as e:
            # handle any other exceptions that may occur
            logging.error("Error in decryption_using_rsa:", e)

    def aes_decryption_for_files(self, encrypted_file):
        # method to decrypt AES-encrypted file using given secret key
        try:
            # set salt for key derivation
            salt = "rsaaes@1234salt"

            # read ciphertext from file and decode from base64
            with open(encrypted_file, "rb") as f:
                encoded = (f.read())
            cipher_text = base64.b64decode(encoded)

            logging.info(f'Ciphertext successfully read during aes')

            # derive prcipher_text[:AES.__block_size]ate key from secret key and salt

            private_key = self.get_private_key(self.__aes_secret_key, salt)

            logging.info(f'Successfully fetched the private key')

            # extract initialization vector from ciphertext and create AES cipher object
            iv = cipher_text[:AES.block_size]
            cipher = AES.new(private_key, AES.MODE_CBC, iv)

            # decrypt ciphertext and unpad data
            plain_bytes = self.unpad(
                cipher.decrypt(cipher_text[self.__block_size:]))

            logging.info(f'Successfully decrypted the cipher key')

            # write plaintext to file
            with open(encrypted_file + "_D", "w") as f:
                f.write(bytes.decode(plain_bytes, errors='ignore'))

            logging.info(f'Writing the file successful for aes decryption')

        except FileNotFoundError as e:
            # handle file not found error
            logging.error(
                "Error in aes_decryption_for_files: file not found", e)

        except Exception as e:
            # handle any other exceptions that may occur
            logging.error("Error in aes_decryption_for_files:", e)

    def decryptFile(self, encryptedFileName, aesFileName):
        try:
            self.read_rsa_keys()
        except Exception as e:
            raise RuntimeError("Error reading RSA keys:", e)

        try:
            self.decryption_using_rsa(aesFileName)
        except Exception as e:
            raise RuntimeError("Error decrypting using RSA:", e)

        try:
            self.aes_decryption_for_files(
                encryptedFileName)
        except Exception as e:
            raise RuntimeError("Error in AES decryption for files:", e)

    @property
    def iv_param_value(self):
        return self._iv_param_value

    @iv_param_value.setter
    def iv_param_value(self, iv_param_value):
        self._iv_param_value = iv_param_value

    @property
    def aes_secret_key(self):
        return self._aes_secret_key

    @aes_secret_key.setter
    def aes_secret_key(self, aes_secret_key):
        self._aes_secret_key = aes_secret_key

    @property
    def rsa_private_key(self):
        return self._rsa_private_key

    @rsa_private_key.setter
    def rsa_private_key(self, rsa_private_key):
        self._rsa_private_key = rsa_private_key

    @property
    def rsa_public_key(self):
        return self._rsa_public_key

    @rsa_public_key.setter
    def rsa_public_key(self, rsa_public_key):
        self._rsa_public_key = rsa_public_key
        
        
# Usage
rsa_aes_client = RsaAesClient()
rsa_aes_client.decryptFile('uat_spocto_sma_collection_report_encrypted.csv', 'uat_spocto_sma_collection_report_encrypted_aes.txt')