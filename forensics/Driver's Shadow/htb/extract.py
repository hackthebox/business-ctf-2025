with open("./volnaya_usr", "rb") as f:
    f.seek(0x3120)
    data = f.read(0x666C0)


key = bytes.fromhex("881ba50d42a430791ca2d9ce0630f5c9")
elf_hdr = data[:0x40]
elf_body = data[0x40:]

with open("./module", "wb") as f:
    f.write(elf_hdr)
    f.write(bytes([b ^ key[i % 16] for i, b in enumerate(elf_body)]))
