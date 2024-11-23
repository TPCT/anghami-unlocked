import re
from uuid import uuid4
from requests import Session
from urllib import parse
from time import time, perf_counter, sleep
from warnings import filterwarnings
from AnghInterceptor import AnghInterceptor
from json import loads
from concurrent.futures import ThreadPoolExecutor
from threading import Lock


filterwarnings("ignore")

def log(*args, **kwargs):
    with lock:
        print(*args, **kwargs)

class AnghScrapper:
    LOGIN_URL = "https://coussa.anghami.com/rest/v1/authenticate.view"
    POST_CLAPS_URL = "https://coussa.anghami.com/rest/v1/POSTclaps.view"
    GET_PLAY_QUEUE = "https://coussa.anghami.com/rest/v1/GETplayqueue.view"

    def __init__(self, email, password):
        self._email = email
        self._password = password
        self._session = Session()
        self._session_id = None
        self._interceptor = AnghInterceptor()

    def login(self):
        thread_time = int(perf_counter() * 1000 % 10000)
        payload = {
            'device_size': '35.79455',
            'installdate': '1732292542',
            'endDate': '1732293887495',
            'language': 'en',
            'locale': 'en',
            'operator': '310-270',
            'networkoperator': '310-260',
            'dataConsumption': '184215',
            'udid': '866380ea74c355e1',
            'connectiontype': 'wifi',
            'detectedmsisdn': '310-270',
            'c': 'vbox86p-Android7.0.85-13',
            'amplitudedeviceid': '20f9e4a6-3381-45d8-b32b-79316ec873feR',
            'privateip': '10.0.2.15',
            'advertisingid': 'b8dd34c8-23d4-4103-9a60-e343a63f4d32',
            'services': 'push,bluetooth',
            'm': 'an',
            'p': self._password,
            'fcm_push_token': 'ctni0Ns8TRiPEnFYOW6UR9%3AAPA91bFcVbR-ZJQMfeWIuxgakWj2qyShvDy2BfobeCqU3xmdYOyzXF6MGpzvtlfJ4xvRB91JChBanXpV8ExN7bd8mXjr28i63u8OFxPfaAIXyD-m06rgqNA',
            'u': self._email,
            'v': '1.0.0',
            'isvpn': '1',
            'supports_atmos': '0',
            'startDate': '-1',
            'contacts': '0',
            'DeviceName': 'Genymobile-A50',
            'random': f'{thread_time}'
        }

        url, headers, encrypted_payload, decryption_key = self._interceptor.intercept(
            self.LOGIN_URL, {}, parse.urlencode(payload).encode()
        )

        response = self._session.post(url, headers=headers, data=encrypted_payload)
        response = loads(self._interceptor.decrypt_response(response.content, decryption_key))
        self._session_id = response.get('authenticate', {}).get('sessionid')
        if not self._session_id:
            log(f"[-] {self._email}:{self._password} is invalid")
            return False
        log(f"[+] {self._email} Logged in successfully, session_id: {self._session_id}")
        return True

    def get_live_channel_queue(self, live_channel_id):
        if not self._session_id:
            log(f"[-] {self._email}:{self._password} Please Login First")
            return None

        url_params = {
            'output': 'jsonhp',
            'sid': self._session_id,
            'compact': 0,
            'live_channel_id': live_channel_id,
            'playqueueid': f'user-play-queue-{live_channel_id.split('.')[2]}-{time()}',
            'timestamp': int(time()),
        }


        url, headers, encrypted_payload, decryption_key = self._interceptor.intercept(
            self.GET_PLAY_QUEUE + "?" + parse.urlencode(url_params),
            {},
            None
        )

        headers['X-ANGH-ENCPAYLOAD'] = '0'
        response = (
            self._session
            .get(
                self.GET_PLAY_QUEUE,
                params=url_params,
                headers=headers
            ).json()
        )

        songs = response['playqueue']['songs']
        log(f"[+] Found {len(songs)} songs")
        return songs


    def claps(self, song_id, channel_id, claps_count=20):
        try:
            if not self._session_id:
                log(f"[-] {self._email}:{self._password} Please Login First")
                return None

            payload = {
                'local_id': f"{uuid4()}",
                'clap_count': claps_count,
                'song_id': song_id,
                'live_channel_id': channel_id
            }

            url, headers, encrypted_payload, decryption_key = self._interceptor.intercept(
                self.POST_CLAPS_URL, {}, parse.urlencode(payload).encode()
            )

            headers['X-Socket-ID'] = f"{uuid4()}"
            headers['X-ANGH-ENCPAYLOAD'] = '0'

            response = (
                self._session
                .post(self.POST_CLAPS_URL + f"?output=jsonhp&sid={self._session_id}", data=payload, headers=headers)
                .json()
            )
            if response['status'] == "failed":
                log(f"[-] {song_id} Maximum Claps Reached")
                sleep(10)
                return False
            sleep(10)
            log(f"[+] Sent {claps_count} to {song_id} Successfully")
            return True
        except Exception as e:
            log(f'[x] An error occurred, {e}, trying within 10 seconds')
            sleep(60)
            return self.claps(song_id, channel_id, claps_count)


    def get_live_channel_id(self, invitation_link):
        if not self._session_id:
            log(f"[-] {self._email}:{self._password} Please Login First")
            return None

        response = self._session.get(invitation_link).text
        channel_id = re.findall("presence-Anghami.User.([0-9]+).Live.Playqueue.([a-z0-9]{32})", response)
        if len(channel_id):
            channel_id = channel_id[0]
            log(f'[+] Found Channel id: {channel_id}')
            return f"presence-Anghami.User.{channel_id[0]}.Live.Playqueue.{channel_id[1]}"
        log("[-] Couldn't find Channel id")
        return None


def thread(_email, _password, live_id, claps):
    angh_scrapper = AnghScrapper(_email, _password)
    angh_scrapper.login()
    live_channel_id = angh_scrapper.get_live_channel_id(f"https://open.anghami.com/{live_id}")
    if live_channel_id:
        songs = angh_scrapper.get_live_channel_queue(live_channel_id)
        with ThreadPoolExecutor(max_workers=4) as e:
            for song in songs[::-1]:
                log(f"[+] Sending {claps_count.strip()} to {song['id']}")
                e.submit(angh_scrapper.claps, song['id'], live_channel_id, int(claps))

if __name__ == '__main__':
    lock = Lock()
    while True:
        with open('users.txt', 'r') as f, ThreadPoolExecutor(max_workers=10) as executor:
            for index, line in enumerate(f):
                if not line.strip() or index == 0:
                    continue
                email, password, token, claps_count = line.split(':')
                executor.submit(thread, email, password, token, claps_count)
