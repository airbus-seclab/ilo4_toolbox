from Crypto.PublicKey import ECC
from Crypto.Cipher import AES
from Crypto.Util.number import bytes_to_long, long_to_bytes
import hashlib
import sys
from ilo5lib import *
from pathlib import Path
from hexdump import hexdump


# private key for iLO 2.3x and greater
ECPrivateKeyPEM_23X = """-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDDL5f7Q6tWLtBia0ZkYVGEVkm4N51SonPNNMZL0xXhnXQMUTZx6xb9a
aDRDhSyhxDCgBwYFK4EEACKhZANiAAThK1Eg3o0WLpfTTRo0wt48ObSZiZcikN/T
cquOSFaNlbzPdA17JRdU3EdrJkQoUvpeTq+ORhh4k12qD3ITMjRrYYrZ6ZKCngNE
2BTJSmLHSOrn6WW4pdZTIVDqsEnjkOs=
-----END EC PRIVATE KEY-----
"""


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

        with open(outdir + "/%s.hdr" % stem, "wb") as fff:
            fff.write(ilo_header)

        img_header = ImageHeader.from_buffer_copy(ilo_header)
        img_header.dump()

        check_header_crc(ilo_header, img_header)

        with open(outdir + "/%s.sig" % stem, "wb") as fff:
            fff.write(bytearray(img_header.signature))

        module = data[:img_header.compressed_size]
        with open(outdir + "/%s.raw" % stem, "wb") as fff:
            fff.write(module)

        check_img_crc(module, img_header)

        if (img_header.flags & 1) == 1:
            output_size = decompress_all(module, outdir + "/%s.bin" % stem)
            print("output_size : 0x%08x\n" % (output_size))

            print("[+] extracted %s.bin" % stem)


def ECDH_compute_key(P, d):
    return long_to_bytes((P * d).x)


def dump_ec_key(pkey, type='pub'):

    print(f"[+] ec {type} key")
    print(f"> {type}key: {pkey}\n")
    print(f"> {type}.pointQ.x: {hex(pkey.pointQ.x)}")
    print(f"> {type}.pointQ.y: {hex(pkey.pointQ.y)}")

    if type != 'pub':
        print(f"> {type}.d: {hex(pkey.d)}")

    print("--\n")


INPUT = "elf_secure.raw"

print(f"[+] loading {INPUT}")

with open(INPUT, "rb") as fw_fd_in:
    point = fw_fd_in.read(0x200)

    try:
        ec_pub = ECC._import_subjectPublicKeyInfo(point.rstrip(b'\x00'))
        dump_ec_key(ec_pub, 'pub')
    except Exception as e:
        print("[x] failed to load public key")
        print(e)
        sys.exit()

    try:
        ec_priv = ECC.import_key(ECPrivateKeyPEM_23X)
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
    aes_iv = fw_fd_in.read(0xc)

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

    with open('clear.bin', 'wb') as fw_fd_out:
        fw_fd_out.write(clear)
        hexdump(clear[:0x100], "firmware header", remove_dup=False)

    print(f"[+] extracting")
    extract_one_shot()

print("[!] done captain")
