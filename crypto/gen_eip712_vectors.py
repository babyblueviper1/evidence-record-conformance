#!/usr/bin/env python3
"""Generates the EIP-712 payload-signature vectors (crypto/eip712_vectors/) and crypto/EIP712_MANIFEST.json. Stdlib only."""
import json, os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE); sys.path.insert(0, os.path.dirname(HERE))
from keccak import keccak256  # noqa: E402
import secp256k1_recover as S  # noqa: E402
import verify_eip712 as E  # noqa: E402
from gen_crypto_vectors import PRIV, K, TEST_ADDR, sighex, with_sig, off_curve_r, TEST_KEY_DERIVATION, TEST_NONCE_DERIVATION  # noqa: E402

P1 = json.load(open(os.path.join(os.path.dirname(HERE), "vectors", "p1-live-genesis-receipt.json")))["input"]["payload"]
LEDGER = "0x9d38BA84730271eb27Ac9bD4Bd2620c08dB4FDa6"


def tsign(msg, **kw):
    return sighex(*S.sign(E.digest(msg, **kw), PRIV, K))


def main():
    live = {"format": P1["format"], "payload": P1["payload"], "signature": P1["signature"], "signer": P1["payload"]["payer"]}
    m = P1["payload"]
    tmsg = {**m, "payer": TEST_ADDR}
    t = {"format": "eip712", "payload": tmsg, "signature": tsign(tmsg), "signer": TEST_ADDR}
    reordered = "Receipt(uint256 version,string network,string resourceUrl,string payer,string transaction,uint256 issuedAt)"
    reorder_fields = tuple(f for f in E.FIELDS if f[0] != "issuedAt" and f[0] != "transaction") + (("transaction", "string"), ("issuedAt", "uint256"))
    s_int = int(P1["signature"][66:130], 16); v_live = int(P1["signature"][130:], 16)
    LIVE_SRC = "p1's payload, signature and payer as served (core vector p1, live-ledger); Tersign published the typed-data construction on PR #11"
    V = [
        ("ep1-live-p1-payload-signature", "valid", None, live, "live-ledger-derived", LIVE_SRC),
        ("ep2-test-key-accepting-twin", "valid", None, t, "synthetic", "test key signs a Receipt naming itself as payer"),
        ("en1-domain-chainid-8453", "reject", "signer_mismatch", {**t, "signature": tsign(tmsg, domain={**E.DOMAIN, "chainId": 8453})}, "synthetic", "test key signs under chainId 8453 (Base), the record's own network, not the pinned domain"),
        ("en2-domain-name-altered", "reject", "signer_mismatch", {**t, "signature": tsign(tmsg, domain={**E.DOMAIN, "name": "x402 receipts"})}, "synthetic", "test key signs under a domain name one letter off"),
        ("en3-type-fields-reordered", "reject", "signer_mismatch", {**t, "signature": tsign(tmsg, receipt_type=reordered, fields=reorder_fields)}, "synthetic", "test key signs with issuedAt and transaction swapped in the type string"),
        ("en4-issuedat-drift", "reject", "signer_mismatch", {**live, "payload": {**m, "issuedAt": m["issuedAt"] + 1}}, "live-ledger-derived", "p1 with issuedAt + 1"),
        ("en5-payer-recased", "reject", "signer_mismatch", {**live, "payload": {**m, "payer": m["payer"].lower()}}, "live-ledger-derived", "p1 with payer written lower-case: payer is a string, hashed as written"),
        ("en6-high-s-malleated", "reject", "non_canonical_s", {**live, "signature": with_sig(P1["signature"], s=S.N - s_int, v=55 - v_live)}, "live-ledger-derived", "p1's signature malleated to s' = n - s, v flipped"),
        ("en7-personal-sign-over-struct", "reject", "signer_mismatch", {**t, "signature": sighex(*S.sign(S.personal_sign_hash(E.digest(tmsg)), PRIV, K))}, "synthetic", "test key personal_signs the EIP-712 digest instead of signing it"),
        ("en8-version-string", "reject", "malformed_input", {**live, "payload": {**m, "version": "1"}}, "live-ledger-derived", "p1 with version as the string \"1\""),
        ("en9-issuedat-negative", "reject", "malformed_input", {**live, "payload": {**m, "issuedAt": -1}}, "live-ledger-derived", "p1 with issuedAt -1"),
        ("en10-field-missing", "reject", "malformed_input", {**live, "payload": {k: v for k, v in m.items() if k != "transaction"}}, "live-ledger-derived", "p1 with transaction removed"),
        ("en11-extra-field", "reject", "malformed_input", {**live, "payload": {**m, "amount": "1000"}}, "live-ledger-derived", "p1 with a field the Receipt type does not have"),
        ("en12-format-not-eip712", "reject", "unsupported_format", {**live, "format": "eip191"}, "live-ledger-derived", "p1 labelled eip191"),
        ("en13-ledger-key-is-not-payload-signer", "reject", "signer_mismatch", {**live, "signer": LEDGER}, "live-ledger-derived", "p1 with the ledger's counter-signing key declared as the payload signer"),
        ("en14-recovery-byte-29", "reject", "malformed_signature", {**live, "signature": with_sig(P1["signature"], v=29)}, "live-ledger-derived", "p1's signature with v = 29"),
        ("en15-unrecoverable-r-off-curve", "reject", "unrecoverable", {**live, "signature": with_sig(P1["signature"], r=off_curve_r())}, "live-ledger-derived", "p1's s and v with r off the curve"),
    ]
    out = os.path.join(HERE, "eip712_vectors")
    os.makedirs(out, exist_ok=True)
    for f in os.listdir(out):
        os.remove(os.path.join(out, f))
    entries = []
    for vid, expect, reason, inp, cls, src in V:
        v = {"id": vid, "kind": "payload_signature", "expect": expect}
        if reason:
            v["reject_reason"] = reason
        v["input"] = inp
        with open(os.path.join(out, vid + ".json"), "w") as fh:
            fh.write(json.dumps(v, indent=2) + "\n")
        entries.append({"file": vid + ".json", "kind": "payload_signature", "expect": expect, "author": "@babyblueviper1", "origin": {"class": cls, "source": src}})
    man = {"profile": "EIP-712 payload signature (x402 offer-and-receipt Receipt)", "runner": "crypto/verify_eip712.py",
           "generator": "crypto/gen_eip712_vectors.py", "domain": E.DOMAIN, "primary_type": "Receipt", "type": E.RECEIPT_TYPE,
           "reject_reasons": list(E.REJECT_REASONS), "test_key_address": TEST_ADDR, "test_key_derivation": TEST_KEY_DERIVATION,
           "test_nonce_derivation": TEST_NONCE_DERIVATION, "vectors": entries}
    with open(os.path.join(HERE, "EIP712_MANIFEST.json"), "w") as fh:
        fh.write(json.dumps(man, indent=1, ensure_ascii=False) + "\n")
    bad = 0
    for vid, expect, reason, inp, _, _ in V:
        got = E.check(inp)
        ok = got == (expect, reason); bad += not ok
        print(("ok  " if ok else "FAIL"), vid, got)
    print(f"{len(V) - bad}/{len(V)}")


if __name__ == "__main__":
    main()
