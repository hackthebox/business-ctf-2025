#!/usr/bin/python3

import sys

def decrypt(ciphertext: bytes, key: bytes) -> bytes:
    cleartext = bytearray(len(ciphertext))
    ptr = 0
    previous_ciphertext_byte = 0xFF
    key_len = len(key)
    num_bytes = len(ciphertext)

    while True:
        block_offset = 0
        key_offset = 0

        while block_offset != 0x200:
            offs = ptr + block_offset
            if offs >= num_bytes:
                return bytes(cleartext)

            ciphertext_byte = ciphertext[offs]
            xor = previous_ciphertext_byte ^ ciphertext_byte ^ key[key_offset]
            xor = (xor + 256) & 0xFF

            cleartext[offs] = (xor - key_offset) & 0xFF

            previous_ciphertext_byte = ciphertext_byte
            key_offset = (key_offset + 1) % key_len
            block_offset += 1

            if ptr + block_offset > num_bytes:
                return bytes(cleartext)

        ptr += 0x200
        if ptr >= num_bytes:
            return bytes(cleartext)

def main():
    if len(sys.argv) != 4:
        print(f"Usage: {sys.argv[0]} <input_file> <output_file> <key>")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]
    key = sys.argv[3].encode('utf-8')

    try:
        # Read the input file
        with open(input_file, 'rb') as f:
            ciphertext = f.read()

        # Decrypt the data
        cleartext = decrypt(ciphertext, key)

        # Write the decrypted data to the output file
        with open(output_file, 'wb') as f:
            f.write(cleartext)

        print(f"Decryption successful. Output written to {output_file}")

    except IOError as e:
        print(f"File error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()