"""Pure-stdlib secp256k1 public-key recovery for Ethereum personal_sign (EIP-191 version 0x45). Verification only;
no secret is held. Uses the suite's own keccak.py. Low-s (EIP-2) is enforced by the caller, not here."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from keccak import keccak256  # noqa: E402

P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def _add(a, b):
    if a is None: return b
    if b is None: return a
    if a[0] == b[0] and (a[1] + b[1]) % P == 0: return None
    if a == b:
        l = 3 * a[0] * a[0] * pow(2 * a[1], P - 2, P) % P
    else:
        l = (b[1] - a[1]) * pow(b[0] - a[0], P - 2, P) % P
    x = (l * l - a[0] - b[0]) % P
    return (x, (l * (a[0] - x) - a[1]) % P)


def _mul(k, pt):
    r = None
    while k:
        if k & 1: r = _add(r, pt)
        pt = _add(pt, pt); k >>= 1
    return r


def personal_sign_hash(msg: bytes) -> bytes:
    return keccak256(b"\x19Ethereum Signed Message:\n" + str(len(msg)).encode() + msg)


def recover(msg_hash: bytes, r: int, s: int, recid: int):
    """-> uncompressed public point, or None if the signature does not define one."""
    if not (1 <= r < N and 1 <= s < N and recid in (0, 1)):
        return None
    x = r
    y2 = (pow(x, 3, P) + 7) % P
    y = pow(y2, (P + 1) // 4, P)
    if y * y % P != y2:
        return None
    if y % 2 != recid:
        y = P - y
    R = (x, y)
    e = int.from_bytes(msg_hash, "big")
    rinv = pow(r, N - 2, N)
    Q = _mul(rinv, _add(_mul(s, R), _mul((-e) % N, G)))
    return Q


def address(Q) -> str:
    return "0x" + keccak256(Q[0].to_bytes(32, "big") + Q[1].to_bytes(32, "big"))[-20:].hex()


def sign(msg_hash: bytes, priv: int, k: int):
    """TEST-VECTOR GENERATION ONLY (fixed nonce). -> (r, s, recid) with low s."""
    R = _mul(k, G); r = R[0] % N
    s = pow(k, N - 2, N) * (int.from_bytes(msg_hash, "big") + r * priv) % N
    recid = R[1] % 2
    if s > N // 2:
        s = N - s; recid ^= 1
    return r, s, recid
