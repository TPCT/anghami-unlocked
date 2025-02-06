import hashlib
import os
from nacl.bindings import crypto_aead_chacha20poly1305_encrypt

class Utils:
    @staticmethod
    def convert_device_id_to_integer(device_id):
        return sum([ord(c) for c in device_id])

    @staticmethod
    def xor_arrays(arr1, arr2):
        return bytes([b1 ^ b2 for b1, b2 in zip(arr1, arr2)])

    @staticmethod
    def get_md5_from_iso_8859_1(string):
        message_digest = hashlib.md5()
        message_digest.update(string.encode('iso-8859-1'))
        return Utils.c(message_digest.digest())

    @staticmethod
    def c(byte_array):
        result = []
        for b in byte_array:
            i10 = (b >> 4) & 15
            i11 = 0
            while True:
                result.append(chr((i10 - 10 + 97) if (i10 < 0 or i10 > 9) else (i10 + 48)))
                i10 = b & 15
                i12 = i11 + 1
                if i11 >= 1:
                    break
                i11 = i12
        return ''.join(result)


    @staticmethod
    def encodeRequest(payload, key):
        nonce = os.urandom(8)
        additional_data = os.urandom(12)
        ciphertext = crypto_aead_chacha20poly1305_encrypt(payload, additional_data, nonce, key)
        return b"##" + nonce + additional_data + ciphertext

    @staticmethod
    def hash_sha1(data):
        sha1 = hashlib.sha1()
        sha1.update(data)
        sha1.update(b"07v8Q7baW2")
        return sha1.hexdigest()[:32]

    @staticmethod
    def hash_with_salt(sign, data):
        try:
            message_digest_2 = hashlib.sha256()
            message_digest_2.update(sign)
            message_digest_2.update(data)
            return message_digest_2.hexdigest()
        except Exception:
            return ""

    @staticmethod
    def combine_arrays(array1, array2):
        return array1 + array2

    @staticmethod
    def concatenate_and_sign(url_path_bytes, encrypted_payload):
        combined = url_path_bytes + encrypted_payload
        return combined