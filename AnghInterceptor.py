from utils import Utils
import gzip
import time
from urllib import parse
from nacl.bindings import crypto_aead_chacha20poly1305_decrypt
import uuid
import random
import string


class AnghInterceptor:
    USER_AGENT = "Anghami Android 7.0.85 / V 13 (7000850) Google store"
    SESSION_ID = "i7:asdfwerqs:866380rn74p355r1:asdqwewedscsds:RT:d:ra:n7.0.85:58::n7.0.85:0:na:qop73141p4"
    SALT = "af9e36f0-b49f-4fe7-9ba5-ca6361ed79b3"
    SIGN = bytes([x if x >= 0 else x + 256 for x in [104,101,57,66,84,89,77,53,87,112,112,66,103,116,79,53,114,108,76,76,116,121,65,106,43,107,119,61,10,97,102,57,101,51,54,102,48,45,98,52,57,102,45,52,102,101,55,45,57,98,97,53,45,99,97,54,51,54,49,101,100,55,57,98,51]])
    ENCRYPTION_ARRAY = bytes([x if x >= 0 else x + 256 for x in [111, -82, -95, 90, -86, 55, 70, -100, 7, 80, 48, 112, -88, -66, 54, -21, 88, 103, -30, -4, 78, -48, 41, -91]])
    DEVICE_ENCRYPTION_ARRAY = bytes([x if x >= 0 else x + 256 for x in [35, -55, -117, 18, -55, 82, 22, -23, 54, 39, 95, 3, -40, -36, 91, -60, 33, 40, -63, -34, 42, -125, 76, -61]])

    def __init__(self):
        self._install_id = uuid.uuid4()
        self._device_id ="".join(random.choices(string.ascii_lowercase + string.digits, k=16))

    def generateToken(self, time_millis, convert):
        k10 = Utils.convert_device_id_to_integer(self._device_id) % (7 if convert else 13)
        encryption_text = Utils.xor_arrays(self.ENCRYPTION_ARRAY, self.DEVICE_ENCRYPTION_ARRAY)
        encryption_text = str(encryption_text, 'utf-8')
        for i in range(k10+1):
            encryption_text = Utils.get_md5_from_iso_8859_1(encryption_text + self._device_id + str(time_millis))
        return bytes(encryption_text, 'utf-8')

    def decrypt_response(self, encrypted_payload, key):
        nonce = encrypted_payload[2:10]
        additional_data = encrypted_payload[10:22]
        return gzip.decompress(crypto_aead_chacha20poly1305_decrypt(encrypted_payload[22:], additional_data, nonce, key)).decode()

    def intercept(self, url, headers, body):
        current_time = int(time.time())
        gzipped_body = gzip.compress(body) if body else None
        encryption_token = self.generateToken(current_time, True)
        decryption_token = self.generateToken(current_time, False)
        encrypted_payload = Utils.encodeRequest(gzipped_body, encryption_token) if body else None

        headers['User-Agent'] = self.USER_AGENT
        headers['X-ANGH-ENCPAYLOAD'] = '3'
        headers['X-ANGH-TS'] = str(current_time)
        headers['X-ANGH-INSTALL'] = str(self._install_id)
        headers['X-ANGH-UDID'] = self._device_id
        headers['Accept-Encoding'] = 'gzip'
        headers['Content-Type'] = 'application/x-www-form-urlencoded'
        headers['Connection'] = "Keep-Alive"

        url = f"{url}?output=jsonhp&sid={self.SESSION_ID}"
        path_url = url.strip()
        index = path_url.find('/rest/')
        if index != -1:
            path_url = path_url[index:].strip()

        payload_signature = Utils.concatenate_and_sign(path_url.encode(), encrypted_payload or bytearray())
        salt = self.SALT
        headers["X-ANGH-RGSIG"] = Utils.hash_sha1(payload_signature)
        headers["X-ANGH-APP-RGSIG"] = Utils.hash_with_salt(self.SIGN, payload_signature)
        headers["X-ANGH-APP-SALT"] = salt

        return url, headers, encrypted_payload, decryption_token


if __name__ == '__main__':
    interceptor = AnghInterceptor()
    payload = {
        'device_size': '35.79455',
        'installdate': int(time.time()),
        'endDate': int(time.time() + 10000),
        'language': 'en',
        'locale': 'en',
        'operator': '310-270',
        'networkoperator': '310-260',
        'random': '518',
        'dataConsumption': '184215',
        'udid': '866380ea74c355e1',
        'connectiontype': 'wifi',
        'detectedmsisdn': '310-270',
        'c': 'vbox86p-Android7.0.85-13',
        'amplitudedeviceid': '20f9e4a6-3381-45d8-b32b-79316ec873feR',
        'privateip': '10.0.2.15',
        'advertisingid': 'b8dd34c8-23d4-4103-9a60-e343a63f4d32',
        'services': 'push%2Cbluetooth',
        'm': 'an',
        'p': 'Me@123456',
        'fcm_push_token': 'ctni0Ns8TRiPEnFYOW6UR9%3AAPA91bFcVbR-ZJQMfeWIuxgakWj2qyShvDy2BfobeCqU3xmdYOyzXF6MGpzvtlfJ4xvRB91JChBanXpV8ExN7bd8mXjr28i63u8OFxPfaAIXyD-m06rgqNA',
        'u': 'nihcit@mo2qt.xyz',
        'v': '1.0.0',
        'isvpn': '1',
        'supports_atmos': '0',
        'startDate': '-1',
        'contacts': '0',
        'DeviceName': 'Genymobile-A50'
    }

    url_encoded = parse.urlencode(payload)
    interceptor.intercept('', {}, url_encoded.encode())