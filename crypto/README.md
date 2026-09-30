# Crypto profile: counter-signature recovery over chain links

This is the first cut of the milestone named in the README's *Scope boundary*. The stdlib core decides the structural predicate. This profile checks what the structural predicate cannot: that each chain link was counter-signed by the declared party.

The runner is pure standard library: `crypto/secp256k1_recover.py` (verification only) plus the suite's own `keccak.py`. It keeps the recomputability bar of "bytes plus a stdlib verifier, no hosted call".

```
python3 crypto/verify_crypto.py            # 8/8 vectors, verdict + reject reason
python3 crypto/verify_crypto.py --mutants  # 6 plausible broken verifiers, each killed by a named vector
```

## The check

1. `link = keccak256(artifact_digest || prev_digest (or 32 zero bytes) || seq_uint64_be)`. This is the core `chain_link` recomputed from the vector's own fields, so the signature is bound to the structural link, not to a hash supplied beside it.
2. The counter-signature must be 65 bytes `r || s || v`, with `v ∈ {27, 28}`.
3. It must be low-s (EIP-2: `s ≤ n/2`), checked on the signature bytes **before** recovery, and a high-s signature MUST be rejected, not normalized to `n - s`. After recovery the two encodings are indistinguishable by address, since both return the same signer.
4. EIP-191 `personal_sign` recovery over the 32 link bytes must return `ledger_signer`, compared as a 0x-address after strip and lowercase.

Reject reasons: `malformed_signature`, `non_canonical_s`, `unrecoverable`, `signer_mismatch`.

**Uniqueness of encoding (normative).** A conformant counter-signature suite MUST admit exactly one byte string per signer and link. For ECDSA over secp256k1 that is rule 3. A suite admitted later MUST state its canonical-encoding rule and reject every other encoding before verification. For Ed25519 that means rejecting a non-canonical `S` (`S ≥ L`, RFC 8032 §5.1.7). A suite whose verifier accepts two encodings of one signature is not conformant, whatever its other properties. (Thanks to @stillmarcus24, whose independent runner confirmed cn3 and raised both the ordering and the per-suite rule.)

## Vectors (two-sided)

| id | expect | what it pins |
|---|---|---|
| cp1 | valid | **live**: the ledger's counter-signature over the genesis link (p1 provenance, link as p4) recovers to `0x9d38…FDa6` |
| cp2 | valid | accepting twin of cn4: a published test key's signature, declared signer = that key (catches a runner that hard-codes the ledger signer) |
| cn1 | reject `signer_mismatch` | the live signature moved to seq 2: the link commits to position |
| cn2 | reject `signer_mismatch` | a foreign key signs the genuine link while the record claims the ledger |
| cn3 | reject `non_canonical_s` | **the live signature malleated to `s' = n - s`, v flipped. It recovers to the same ledger signer.** |
| cn4 | reject `signer_mismatch` | a raw-digest signature (no EIP-191 prefix): the domain must be pinned |
| cn5 | reject `malformed_signature` | 64 bytes, recovery byte dropped |
| cn6 | reject `malformed_signature` | `v = 29`: rejected, not normalized |

**On cn3.** A verifier that only checks "recovered address == signer" accepts cn3. That includes one built on `eth_account` (0.13.7, `Account.recover_message`), which returns the ledger address for it. So a single link would admit two distinct signature byte strings, and any system that keys or deduplicates on signature bytes breaks. EIP-2 low-s is what makes the signature canonical.

**Independent cross-check.** `eth_account` agrees with this runner on every vector except cn3 (it accepts the high-s form, above). cn5 and cn6 are refused there with a `ValueError`.

The test key is published in `MANIFEST.json` (`test_key_address`). It is derived as `keccak256("evidence-record-conformance crypto-profile test key v1")` and is never a real signer.

## Not yet covered

- EIP-712 typed-data counter-signatures. p1's *payload* signature is EIP-712; this profile covers only the ledger's `personal_sign` over links.
- Signer-set rotation: which key was authoritative at which seq.
- Counter-signatures on non-genesis live links: only one is public today (p27's chain). More live vectors can be added as the ledger publishes them.
