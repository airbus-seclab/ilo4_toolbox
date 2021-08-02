from Crypto.PublicKey import ECC
from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes
import hashlib

import sys
import os
import re
import argparse
import pathlib
import collections

from ilo5lib import *
from pathlib import Path
from hexdump import hexdump


ECPRIVATEKEY_PEM_STORE = collections.OrderedDict([
    (r'2\.3\d',
"""-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDDL5f7Q6tWLtBia0ZkYVGEVkm4N51SonPNNMZL0xXhnXQMUTZx6xb9a
aDRDhSyhxDCgBwYFK4EEACKhZANiAAThK1Eg3o0WLpfTTRo0wt48ObSZiZcikN/T
cquOSFaNlbzPdA17JRdU3EdrJkQoUvpeTq+ORhh4k12qD3ITMjRrYYrZ6ZKCngNE
2BTJSmLHSOrn6WW4pdZTIVDqsEnjkOs=
-----END EC PRIVATE KEY-----
"""),
    (r'2\.41',
"""-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDD/qBk3Rt1Vev5RmZPYwY3mZVZnXYQJcCZb+puocKLNhP8qRdZWJAYx
z5G9v3Z8a+ugBwYFK4EEACKhZANiAATPEJPbk607ubtwUOiPQX57BUw3sCsBEgMY
zYj69eO5V/pvoV9kx81thL3U6Iysbqix+PC9Z10F5+BGOCPy8w4thfO3UwKvZeiS
RRI2uv+eFbdqO+L105w3sI9sZe4UIDw=
-----END EC PRIVATE KEY-----
""")
])


def extract_one_shot(filename='clear.bin', outdir='outdir'):
    IMG_HDR_SIZE = 0x800
    stem = Path(filename).stem

    if not os.path.exists(outdir):
        os.makedirs(outdir)

    with open(filename, 'rb') as fff:
        data = fff.read()
        print("[+] header")

        ilo_header = data[:IMG_HDR_SIZE]
        data = data[IMG_HDR_SIZE:]

        with open(os.path.join(outdir, "%s.hdr" % stem), "wb") as fff:
            fff.write(ilo_header)

        img_header = ImageHeader.from_buffer_copy(ilo_header)
        img_header.dump()

        check_header_crc(ilo_header, img_header)

        with open(os.path.join(outdir, "%s.sig" % stem), "wb") as fff:
            fff.write(bytearray(img_header.signature))

        module = data[:img_header.compressed_size]
        with open(os.path.join(outdir, "%s.raw" % stem), "wb") as fff:
            fff.write(module)

        check_img_crc(module, img_header)

        if (img_header.flags & 1) == 1:
            output_size = decompress_all(module, os.path.join(outdir, "%s.bin" % stem))
            print("output_size : 0x%08x\n" % (output_size))

            print("[+] extracted %s.bin" % stem)


def ECDH_compute_key(P, d):
    return long_to_bytes((P * d).x)


def dump_ec_key(pkey, key_type='pub'):

    print(f"[+] ec {key_type} key")
    print(f"> {key_type}key: {pkey}\n")
    print(f"> {key_type}.pointQ.x: {hex(pkey.pointQ.x)}")
    print(f"> {key_type}.pointQ.y: {hex(pkey.pointQ.y)}")

    if key_type != 'pub':
        print(f"> {key_type}.d: {hex(pkey.d)}")

    print("--\n")


def match_key(hdr_file):
    if hdr_file:
        with hdr_file.open('rb') as hdr_in:
            print(f"[+] loading header file {args.rawfile}")

            version_string = hdr_in.read(4).decode()
            print(f"> version string: {version_string}")

            for pattern, ec_pkey in ECPRIVATEKEY_PEM_STORE.items():
                if re.match(pattern, version_string):
                    return ec_pkey

            print(f"[x] no known key for this version")
            sys.exit()

    else:
        print(f"[+] no hdr file, defaulting to the last known private key")
        pattern, ec_pkey = ECPRIVATEKEY_PEM_STORE.popitem(last=True)
        versions = pattern.replace("\\", '').replace('d', 'x')
        print(f"> pattern string: {versions}")
        return ec_pkey


parser = argparse.ArgumentParser()
parser.add_argument('--rawfile', type=pathlib.Path, required=True)
parser.add_argument('--outfile', type=pathlib.Path, default=None)
parser.add_argument('--hdrfile', type=pathlib.Path, default=None)
parser.add_argument('--outdir', type=pathlib.Path, default='extract')
args = parser.parse_args()


ec_privkey = match_key(args.hdrfile)


with args.rawfile.open('rb') as fd_in:
    print(f"[+] loading {args.rawfile}")

    point = fd_in.read(0x200)

    try:
        ec_pub = ECC._import_subjectPublicKeyInfo(point.rstrip(b'\x00'))
        dump_ec_key(ec_pub, 'pub')
    except Exception as e:
        print("[x] failed to load public key from envelope header")
        print(e)
        sys.exit()

    try:
        print(f"[+] using private key:\n{ec_privkey}\n")
        ec_priv = ECC.import_key(ec_privkey)
        dump_ec_key(ec_priv, 'priv')
    except ValueError as e:
        print("[x] failed to load private key")
        print(e)
        sys.exit()

    secret = ECDH_compute_key(ec_pub.pointQ, ec_priv.d)
    print(f"[+] shared secret:\n{secret.hex()}")
    print("--\n")

    print(f"[+] aes key material")
    m = hashlib.sha384()
    m.update(secret)
    aes_key = m.digest()
    aes_iv = fd_in.read(0xc)

    print(f"> aes key: {aes_key.hex()}")
    print(f"> aes iv: {aes_iv.hex()}")
    print("--\n")

    print(f"[+] decrypting")
    blob = fd_in.read()
    tag = blob[-0x10:]
    data = blob[:-0x10]
    cipher = AES.new(aes_key[:0x20], AES.MODE_GCM, aes_iv)
    clear = b''

    try:
        clear = cipher.decrypt_and_verify(data, tag)
    except ValueError as e:
        print("[x] decrypt_and_verify failed. MAC tag is not valid :(")
        sys.exit()

    print("> ok")

    if not args.outfile:
        outfile = args.rawfile.stem + '.clear.bin'
    else:
        outfile = args.outfile

    with open(outfile, 'wb') as fw_fd_out:
        fw_fd_out.write(clear)
        hexdump(clear[:0x100], "firmware header", remove_dup=False)

    print(f"[+] extracting decrypted image")
    extract_one_shot(outfile, args.outdir)

print("[!] done captain")
