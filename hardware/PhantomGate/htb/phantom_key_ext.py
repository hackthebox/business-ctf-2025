#!/usr/bin/python3

import sys
import os

KNOWN_TEXT_START_INDX = 32
KEY_LEN = 32

def recover_key_byte(cipher_byte, plain_byte, prev_byte, key_offset):
    return (prev_byte ^ cipher_byte ^ (plain_byte + key_offset)) & 0xFF

def extract_key(enc):
    base_filename = os.path.splitext(os.path.basename(enc))[0]
    conf_file = (base_filename + "-meta.conf")[2:]
    print(f"[+] Known bytes: {conf_file}")

    key = ""
    with open(enc, "rb") as f:
        encrypted_fw = f.read()
        for i in range(KEY_LEN):
            index = KNOWN_TEXT_START_INDX + i

            prev_byte = encrypted_fw[index - 1]
            cipher_byte = encrypted_fw[index]
            plain_byte = conf_file[i]
            key_offset = i
        
            key_byte = recover_key_byte(
                cipher_byte=cipher_byte,
                prev_byte=prev_byte,
                plain_byte=ord(plain_byte), 
                key_offset=key_offset
            )
            key += chr(key_byte)
    return key


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python phantom_key_ext.py <encrypted_file>")
        sys.exit(1)

    encrypted_file = sys.argv[1]
    print(f"[+] Encrypted firmware: {encrypted_file}")

    key = extract_key(encrypted_file)

    print(f"[+] Key: {key}")