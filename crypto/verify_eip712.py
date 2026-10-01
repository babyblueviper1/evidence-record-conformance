#!/usr/bin/env python3
"""EIP-712 payload-signature profile (x402 offer-and-receipt Receipt), stdlib only + the suite's keccak.py.
Pinned (never read from the record): domain {name: "x402 receipt", version: "1", chainId: 1}, primaryType Receipt,
Receipt(uint256 version,string network,string resourceUrl,string payer,uint256 issuedAt,string transaction).
Input: {format, payload, signature, signer}. Order: format == "eip712" else unsupported_format; payload has exactly the six
Receipt fields, uint256 fields integer tokens in [0, 2**256), string fields str, else malformed_input; signer a 0x-address
(normalized as the core's identifier_normalization) else malformed_input; signature exactly 0x + 130 hex, v in {27, 28}
else malformed_signature; low-s before recovery else non_canonical_s; recovery over the EIP-712 digest defines a point else
unrecoverable; its address equals signer else signer_mismatch. String fields are hashed exactly as written: `payer` is a
string, so a re-cased address is a different message (unlike an identifier)."""
import os, re, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE); sys.path.insert(0, os.path.dirname(HERE))
from keccak import keccak256  # noqa: E402
import secp256k1_recover as S  # noqa: E402
from verify_crypto import norm_hex, _SIG_RE  # noqa: E402

DOMAIN = {"name": "x402 receipt", "version": "1", "chainId": 1}
DOMAIN_TYPE = "EIP712Domain(string name,string version,uint256 chainId)"
RECEIPT_TYPE = "Receipt(uint256 version,string network,string resourceUrl,string payer,uint256 issuedAt,string transaction)"
FIELDS = (("version", "uint256"), ("network", "string"), ("resourceUrl", "string"), ("payer", "string"),
          ("issuedAt", "uint256"), ("transaction", "string"))
REJECT_REASONS = ("unsupported_format", "malformed_input", "malformed_signature", "non_canonical_s", "unrecoverable", "signer_mismatch")


def _u(x):
    return int(x).to_bytes(32, "big")


def _h(s):
    return keccak256(s.encode("utf-8"))


def digest(message, domain=DOMAIN, receipt_type=RECEIPT_TYPE, fields=FIELDS):
    dom = keccak256(_h(DOMAIN_TYPE) + _h(domain["name"]) + _h(domain["version"]) + _u(domain["chainId"]))
    enc = b"".join(_u(message[k]) if t == "uint256" else _h(message[k]) for k, t in fields)
    return keccak256(b"\x19\x01" + dom + keccak256(_h(receipt_type) + enc))


def check(inp):
    if not isinstance(inp, dict) or inp.get("format") != "eip712":
        return "reject", "unsupported_format"
    m = inp.get("payload")
    if not isinstance(m, dict) or set(m) != {k for k, _ in FIELDS}:
        return "reject", "malformed_input"
    for k, t in FIELDS:
        v = m[k]
        if t == "uint256" and not (isinstance(v, int) and not isinstance(v, bool) and 0 <= v < 2 ** 256):
            return "reject", "malformed_input"
        if t == "string" and not isinstance(v, str):
            return "reject", "malformed_input"
    signer = norm_hex(inp.get("signer"), 20)
    if signer is None:
        return "reject", "malformed_input"
    sig = inp.get("signature")
    if not (isinstance(sig, str) and _SIG_RE.match(sig)):
        return "reject", "malformed_signature"
    b = bytes.fromhex(sig[2:])
    if b[64] not in (27, 28):
        return "reject", "malformed_signature"
    r, s = int.from_bytes(b[:32], "big"), int.from_bytes(b[32:64], "big")
    if s > S.N // 2:
        return "reject", "non_canonical_s"
    Q = S.recover(digest(m), r, s, b[64] - 27)
    if Q is None:
        return "reject", "unrecoverable"
    return ("valid", None) if S.address(Q) == signer else ("reject", "signer_mismatch")
