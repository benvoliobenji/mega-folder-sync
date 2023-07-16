import getpass
import json
import logging
import os
import re
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Tuple

import requests as request
import validators
from colorama import Fore, Style, just_fix_windows_console
from Crypto.Cipher import AES
from Crypto.Util import Counter
from mega import Mega
from mega.crypto import (
    a32_to_str,
    base64_to_a32,
    base64_url_decode,
    decrypt_attr,
    decrypt_key,
    str_to_a32,
)
from mega.errors import RequestError
from mega.mega import get_chunks
from tqdm.auto import tqdm

just_fix_windows_console()

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.INFO)
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)


# Credit to this GOAT:
# https://stackoverflow.com/questions/64488709/how-can-i-list-the-contents-of-a-mega-public-folder-by-its-shared-url-using-meg


def get_nodes_in_shared_folder(root_folder: str) -> dict:
    """Get the nodes in a MEGA shared folder.
    This will get all folders and files within a root directory URL handle

    Args:
        root_folder (str): A folder handle. Done by extracting from the user URL. Reference parse_folder_url

    Returns:
        dict: A dictionary of encrypted information of the folder
    """
    data = [{"a": "f", "c": 1, "ca": 1, "r": 1}]
    response = request.post(
        "https://g.api.mega.co.nz/cs",
        params={"id": 0, "n": root_folder},  # self.sequence_num
        data=json.dumps(data),
    )
    json_resp = response.json()
    return json_resp[0]["f"]


def get_nodes_to_download(root_folder: str, node: dict) -> dict:
    """Similar to get_nodes_in_shared_folder, but the API request is altered to get the
    relevant information for downloading

    Args:
        root_folder (str): A folder handle. Done by extracting from the user URL. Same as the argument passed in to get_nodes_in_shared_folder.
        node (dict): The "encrypted" node dictionary for the specific node to download (likely a file)

    Returns:
        dict: The node details to facilitate downloads
    """
    data = [{"a": "g", "g": 1, "n": node["h"]}]
    response = request.post(
        "https://g.api.mega.co.nz/cs",
        params={"id": 0, "n": root_folder},  # self.sequence_num
        data=json.dumps(data),
    )
    json_resp = response.json()
    return json_resp[0]


def parse_folder_url(url: str) -> Tuple[str, str]:
    """Parses the user-provided URL and outputs the relevant handle and key.

    Args:
        url (str): The URL.

    Returns:
        Tuple[str, str]: Returns (public_handle, key) if valid. If not returns None.
    """
    REGEXP1 = re.compile(
        r"mega.[^/]+/folder/([0-z-_]+)#([0-z-_]+)(?:/folder/([0-z-_]+))*"
    )
    REGEXP2 = re.compile(
        r"mega.[^/]+/#F!([0-z-_]+)[!#]([0-z-_]+)(?:/folder/([0-z-_]+))*"
    )
    m = re.search(REGEXP1, url)
    if not m:
        m = re.search(REGEXP2, url)
    if not m:
        print("Not a valid URL")
        return None
    root_folder = m.group(1)
    key = m.group(2)
    # You may want to use m.groups()[-1]
    # to get the id of the subfolder
    return (root_folder, key)


def decrypt_node_key(key_str: str, shared_key: str) -> Tuple[int, ...]:
    """Decrypts the key for a specific node

    Args:
        key_str (str): The encrypted node key
        shared_key (str): The shared key extracted from the URL

    Returns:
        Tuple[int, ...]: The decrypted key.
    """
    encrypted_key = base64_to_a32(key_str.split(":")[1])
    return decrypt_key(encrypted_key, shared_key)


def mega_download_file(
    mega: Mega,
    file_data,
    file_key,
    dest_path=None,
    dest_filename=None,
    file=None,
) -> Path:
    """Downloads a file. Stolen from mega.py's internal _download_file, but with a few changes to make it actually work.
    This is due to mega.py being deprecated, making it no longer work with the current API.

    Args:
        mega (Mega): The Mega instance (either anonymous or logged in)
        file_data (Dict): The node details provided in get_nodes_to_download
        file_key (Tuple): The decrypted node key
        dest_path (str, optional): The local file path to download to. Defaults to None.
        dest_filename (str, optional): The new file name to write to locally. Defaults to None.
        file (Dict, optional): The raw file data. Defaults to None.

    Raises:
        RequestError: API request failure
        ValueError: Mismatched mac

    Returns:
        Path: The downloaded file location
    """
    if file is None:
        k = (
            file_key[0] ^ file_key[4],
            file_key[1] ^ file_key[5],
            file_key[2] ^ file_key[6],
            file_key[3] ^ file_key[7],
        )
        iv = file_key[4:6] + (0, 0)
        meta_mac = file_key[6:8]
    else:
        file_data = mega._api_request({"a": "g", "g": 1, "n": file["h"]})
        k = file["k"]
        iv = file["iv"]
        meta_mac = file["meta_mac"]

    # Seems to happens sometime... When this occurs, files are
    # inaccessible also in the official also in the official web app.
    # Strangely, files can come back later.
    if "g" not in file_data:
        raise RequestError("File not accessible anymore")
    file_url = file_data["g"]
    file_size = file_data["s"]
    attribs = base64_url_decode(file_data["at"])
    attribs = decrypt_attr(attribs, k)

    if dest_filename is not None:
        file_name = dest_filename
    else:
        file_name = attribs["n"]

    input_file = request.get(file_url, stream=True).raw

    if dest_path is None:
        dest_path = ""
    else:
        dest_path += "/"

    with tempfile.NamedTemporaryFile(
        mode="w+b", prefix="megapy_", delete=False
    ) as temp_output_file:
        k_str = a32_to_str(k)
        counter = Counter.new(128, initial_value=((iv[0] << 32) + iv[1]) << 64)
        aes = AES.new(k_str, AES.MODE_CTR, counter=counter)

        mac_str = "\0" * 16
        mac_encryptor = AES.new(k_str, AES.MODE_CBC, mac_str.encode("utf8"))
        iv_str = a32_to_str([iv[0], iv[1], iv[0], iv[1]])

        with tqdm(
            desc="Downloading...",
            total=file_size,
            unit="B",
            unit_scale=True,
            unit_divisor=1024,
        ) as pbar:
            amount_downloaded = 0
            for chunk_start, chunk_size in get_chunks(file_size):
                chunk = input_file.read(chunk_size)
                chunk = aes.decrypt(chunk)
                temp_output_file.write(chunk)

                encryptor = AES.new(k_str, AES.MODE_CBC, iv_str)
                for i in range(0, len(chunk) - 16, 16):
                    block = chunk[i : i + 16]
                    encryptor.encrypt(block)

                # fix for files under 16 bytes failing
                if file_size > 16:
                    i += 16
                else:
                    i = 0

                block = chunk[i : i + 16]
                if len(block) % 16:
                    block += b"\0" * (16 - (len(block) % 16))
                mac_str = mac_encryptor.encrypt(encryptor.encrypt(block))

                file_info = os.stat(temp_output_file.name)
                logger.debug("%s of %s downloaded", file_info.st_size, file_size)
                pbar.update(file_info.st_size - amount_downloaded)
                amount_downloaded = file_info.st_size
        file_mac = str_to_a32(mac_str)
        # check mac integrity
        if (file_mac[0] ^ file_mac[1], file_mac[2] ^ file_mac[3]) != meta_mac:
            raise ValueError("Mismatched mac")
        output_path = Path(dest_path + file_name)
        temp_output_file.close()
        shutil.move(temp_output_file.name, output_path)
        return output_path


def update_folders():
    """The main function. Iterates through all items listed in file_locations.json and attempts to download any files that don't already exist in the provided local directory."""
    json_file_name = "file_locations.json"

    mega = Mega()

    while True:
        email = input("Please enter MEGA email: ")
        pwd = getpass.getpass("Please enter MEGA password: ")

        try:
            m = mega.login(email, pwd)
            print(Fore.GREEN + "Logged in")
            print(Style.RESET_ALL)
            break
        except Exception as e:
            print(Fore.RED + "User not found, perhaps wrong email and password?")
            print(Style.RESET_ALL)

    f = open(json_file_name)
    file_locations = json.load(f)
    f.close()

    for entry in file_locations:
        logging.debug(entry)
        name = entry["name"]
        local_directory = entry["local-location"]
        url = entry["folder-url"]

        print("Checking entry - " + Fore.CYAN + name + Style.RESET_ALL)

        try:
            valid = validators.url(url)
            if not valid:
                print(Fore.RED + "URL not valid. Moving to next entry...")
                print(Style.RESET_ALL)
                break
        except Exception as e:
            logging.debug(f"Exception in validating URL: {e}")
            print(Fore.RED + "URL not valid. Moving to next entry...")
            print(Style.RESET_ALL)
            break

        if not os.path.exists(local_directory):
            os.makedirs(local_directory)

        (root_folder, shared_enc_key) = parse_folder_url(url)
        shared_key = base64_to_a32(shared_enc_key)
        nodes = get_nodes_in_shared_folder(root_folder)
        for node in nodes:
            key = decrypt_node_key(node["k"], shared_key)
            if node["t"] == 0:  # Is a file
                k = (key[0] ^ key[4], key[1] ^ key[5], key[2] ^ key[6], key[3] ^ key[7])
                attrs = decrypt_attr(base64_url_decode(node["a"]), k)
                file_name = attrs["n"]

                print("\tFile Name: " + Fore.CYAN + file_name + Style.RESET_ALL)

                if not os.path.isfile(os.path.join(local_directory + "\\" + file_name)):
                    download_data = get_nodes_to_download(root_folder, node)
                    mega_download_file(m, download_data, key, dest_path=local_directory)
                    print("\t\t" + Fore.GREEN + "Downloaded" + Style.RESET_ALL)
                    print()
                else:
                    print(
                        Fore.YELLOW
                        + "\t\tFile already exists - skipping"
                        + Style.RESET_ALL
                    )
                    print()
            elif node["t"] == 1:  # Is a folder
                k = key
                attrs = decrypt_attr(base64_url_decode(node["a"]), k)
                file_name = attrs["n"]
                logging.debug(f"Folder Name: {file_name}")


if __name__ == "__main__":
    update_folders()
