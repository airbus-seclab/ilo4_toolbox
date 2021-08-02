from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto import Random

import os
import sys
import struct
import argparse
import pathlib
from hexdump import hexdump


KEY_MASK = [
    0x00000000,
    0x000000CE,
    0x00000000,
    0x00D00000,
    0x0086C900,
    0x009A0000,
    0x00700000,
    0x00190000
]


HW_KEY = [
    0xbf7fffc3,
    0x851C0D00,
    0x32f26410,
    0x08000621,
    0x8000009f,
    0x81001012,
    0x810010dc,
    0x81001121
]


CERT_END = b"--=</End HP Signed File Fingerprint\\>=--\n"
HPIMAGE_HDR_SIZE = 0x4B8
RSA_FILE = 'rsa_private_key_ilo5.asc'


def pem_password_cb():
    return struct.pack("L" * 8, *list(x ^ y for x, y in zip(KEY_MASK, HW_KEY)))


def load_private_key():
    with open(RSA_FILE, 'r') as key_file:
        print(f"[+] loading RSA pem (\"{RSA_FILE}\")")
        key_buffer = key_file.read()
        pkey = RSA.import_key(key_buffer, passphrase=pem_password_cb())
        print(f"> key size: {pkey.size_in_bits()}")
        return pkey


def skip_cert(fd):
    buffer = fd.read(0x1000)
    pos = buffer.find(CERT_END)

    if pos == -1:
        print("[x] failed to find HP Signed File fingerprint")
        sys.exit()

    fd.seek(0, os.SEEK_SET)
    hdr = fd.read(pos + len(CERT_END) + HPIMAGE_HDR_SIZE)
    print(f"[+] skipping HP Signed File fingerprint ({fd.tell()} bytes)")
    return hdr


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--infile', type=pathlib.Path, required=True)
    parser.add_argument('--outfile', type=pathlib.Path, default=None)
    args = parser.parse_args()

    with args.infile.open('rb') as fw_fd_in:
        print(f"[+] input file: \"{args.infile}\"")
        hdr = skip_cert(fw_fd_in)

        enc_aes_key = fw_fd_in.read(0x200)
        aes_iv = fw_fd_in.read(0xc)

        rsa_pkey = load_private_key()
        cipher_rsa = PKCS1_v1_5.new(rsa_pkey)

        dsize = 0x20
        sentinel = Random.new().read(15+dsize)
        aes_key = cipher_rsa.decrypt(enc_aes_key, sentinel)

        print(f"[+] aes key material")
        print(f"> aes key: {aes_key.hex()}")
        print(f"> aes iv: {aes_iv.hex()}")
        print("--\n")

        print(f"[+] decrypting")
        blob = fw_fd_in.read()
        tag = blob[-0x10:]
        data = blob[:-0x10]
        cipher = AES.new(aes_key[:0x20], AES.MODE_GCM, aes_iv)
        clear = b''

        try:
            clear = cipher.decrypt_and_verify(data, tag)
        except ValueError as e:
            print("[x] decrypt_and_verify failed? MAC tag is not valid,")
            sys.exit()

        print("> ok")

        if not args.outfile:
            outfile = args.infile.stem + '.clear.bin'
        else:
            outfile = args.outfile

        print(f"[+] writing output file \"{outfile}\":\n")
        with open(outfile, 'wb') as fw_fd_out:
            fw_fd_out.write(hdr)
            fw_fd_out.write(clear)
            hexdump(clear[:0x100], "firmware header", remove_dup=False)

    print("[!] done captain")
