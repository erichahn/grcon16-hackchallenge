#!/usr/bin/env python

import argparse, hashlib, binascii, base64

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(dest="hash", type=str)
    parser.add_argument(dest="level", type=int)

    args = parser.parse_args()

    h64 = args.hash

    missing_padding = len(h64) % 4
    if missing_padding != 0:
        h64 += ("="* (4 - missing_padding))
    try:
        h = base64.b64decode(h64)
    except:
        h = base64.b64decode(args.hash[:-1])
    v = int(binascii.hexlify(h), 16)
    i = v + args.level
    s = hex(i).rstrip('L').lstrip('0x').decode('hex')
    sha = hashlib.sha256()
    sha.update(s)
    new_hash = sha.digest()

    print base64.encodestring(new_hash),

if __name__ == '__main__':
    main()