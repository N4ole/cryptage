"""Implémentation indépendante (libsodium + argon2 C) du format cryptage v1.

Génère un vecteur de test : fichier chiffré avec en-tête fixe, 2 morceaux de 4 Kio + 1 partiel.
"""
import struct
import sys

from argon2.low_level import Type, hash_secret_raw
from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_encrypt

out_path = sys.argv[1]
password = "Bonjour à tous !".encode("utf-8")
m, t, p = 65536, 3, 1
salt = bytes(range(16))
nonce_prefix = bytes(range(100, 119))
chunk_log2 = 12
plaintext = bytes((i * 7 + 3) % 256 for i in range(2 * 4096 + 1000))

header = (
    b"CRYPTAGE"
    + struct.pack("<H", 1)
    + bytes([1])
    + struct.pack("<III", m, t, p)
    + salt
    + bytes([1, chunk_log2])
    + nonce_prefix
)
assert len(header) == 60

key = hash_secret_raw(password, salt, time_cost=t, memory_cost=m, parallelism=p,
                      hash_len=32, type=Type.ID, version=19)
chunk = 1 << chunk_log2
chunks = [plaintext[i:i + chunk] for i in range(0, len(plaintext), chunk)] or [b""]
out = bytearray(header)
for idx, c in enumerate(chunks):
    last = idx == len(chunks) - 1
    nonce = nonce_prefix + struct.pack(">I", idx) + bytes([1 if last else 0])
    out += crypto_aead_xchacha20poly1305_ietf_encrypt(c, header, nonce, key)

with open(out_path, "wb") as f:
    f.write(out)
print(len(out), "octets écrits")
