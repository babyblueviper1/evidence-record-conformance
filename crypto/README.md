# Crypto profile: counter-signature recovery over chain links

This is the first cut of the milestone named in the README's *Scope boundary*. The stdlib core decides the structural predicate. This profile checks what the structural predicate cannot: that each chain link was counter-signed by the declared party.

The runner is pure standard library: `crypto/secp256k1_recover.py` (verification only) plus the suite's own `keccak.py`. It keeps the recomputability bar of "bytes plus a stdlib verifier, no hosted call".

```
python3 crypto/verify_crypto.py            # 18/18 vectors, verdict + reject reason
python3 crypto/verify_crypto.py --mutants  # 8 plausible broken verifiers, each killed by a named vector
```

## The check

1. `link = keccak256(artifact_digest || prev_digest (or 32 zero bytes) || seq_uint64_be)`. This is the core `chain_link` recomputed from the vector's own fields, so the signature is bound to the structural link, not to a hash supplied beside it.
2. The counter-signature must be 65 bytes `r || s || v`, with `v ∈ {27, 28}`.
3. It must be low-s (EIP-2: `s ≤ n/2`), checked on the signature bytes **before** recovery, and a high-s signature MUST be rejected, not normalized to `n - s`. After recovery the two encodings are indistinguishable by address, since both return the same signer.
4. EIP-191 `personal_sign` recovery over the 32 link bytes must return `ledger_signer`, compared as a 0x-address after strip and lowercase.

Reject reasons: `malformed_signature`, `non_canonical_s`, `unrecoverable`, `signer_mismatch`, `malformed_input`.

**Field-shape validation (normative).** `artifact_digest`, `prev_digest` (when present), `seq` and `ledger_signer` MUST each be checked against their exact declared form — 32-byte 0x-hex digest, 0x-hex 20-byte address, and `seq` a genuine integer (never a `bool`, `str` or `float`) in `[0, 2**64)` — *before* the counter-signature is parsed at all. A verifier that instead reaches straight for `bytes.fromhex()` / `int(seq).to_bytes(8, "big")` either raises uncaught on a malformed field (not a reject) or silently coerces a wrong-typed field to a value indistinguishable from a well-formed one (`seq: "1"` behaving exactly like `seq: 1`). An absent `prev_digest` (key omitted or explicit `null`) is not itself malformed — both mean genesis, 32 zero bytes — but a *present, malformed* `prev_digest` is a distinct rejectable case and MUST NOT be silently treated as absent. `malformed_signature` stays scoped to the signature field's own shape: exactly `0x` followed by 130 hex digits, no surrounding whitespace and no missing prefix tolerated — a leniently-parsed signature (a dropped `0x`, a stray embedded space) that still happens to recover correctly MUST NOT be accepted, since the field was never validly encoded in the first place. (Thanks to Noûs, an AI agent operating under Roberto Locatelli's mandate — `robertolocatelli81-dev` — whose independent third runner found this class of gap across five malformed-field cases while confirming the published crypto profile byte-identical elsewhere; see PR #11 for the report.)

**Uniqueness of encoding (normative).** A conformant counter-signature suite MUST reject every *alternative encoding* of a signature it already accepts — the malleated re-expression of one signing operation, not a second, independently-produced signature over the same signer and link. For ECDSA over secp256k1 that is rule 3: `s' = n - s` with `v` flipped is a re-encoding of the same signing operation and MUST be rejected, never normalized. A suite admitted later MUST state its own canonical-encoding rule and reject every other encoding of an accepted signature before verification; for Ed25519 that means rejecting a non-canonical `S` (`S ≥ L`, RFC 8032 §5.1.7). This is **not** a claim that a signer can produce only one valid signature byte string per link — ECDSA's random nonce `k` means a signer legitimately produces a distinct low-s signature per choice of `k` over the same message, and a conformant verifier accepts all of them. Any system that deduplicates or indexes on signature bytes MUST key on `(signer, link)` instead, since signature bytes alone are not a stable identity for "the same counter-signature". A suite whose verifier accepts two *encodings of one signing operation* is not conformant, whatever its other properties. (Thanks to @stillmarcus24, whose independent runner confirmed cn3 and raised both the ordering and the per-suite rule; thanks to @TKCollective, who found this scoping gap — the published test helper produces two accepted low-s signatures for the same signer and link under nonces 2 and 3, which the original wording would have wrongly called nonconformant.)

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
| cn7 | reject `malformed_input` | `artifact_digest` not valid hex — must reject cleanly, not raise |
| cn8 | reject `malformed_input` | `seq` negative — must reject cleanly, not raise `OverflowError` |
| cn9 | reject `malformed_input` | `seq` ≥ 2**64 — must reject cleanly, not raise `OverflowError` |
| cn10 | reject `malformed_input` | `seq` is the string `"1"`, not an int — must not silently coerce |
| cn11 | reject `malformed_input` | `seq` is `True` (bool is an int subclass) — must not silently coerce |
| cn12 | reject `malformed_input` | `ledger_signer` not a well-formed 20-byte address |
| cn13 | reject `malformed_input` | `prev_digest` present but malformed — distinct from absent |
| cn14 | reject `malformed_signature` | countersignature missing its `0x` prefix — otherwise-valid bytes must still be refused |
| cn15 | reject `malformed_signature` | countersignature with embedded whitespace — otherwise-valid bytes must still be refused |
| cp3 | valid | `prev_digest` key omitted entirely resolves identically to cp1's explicit `null` |

**On cn3.** A verifier that only checks "recovered address == signer" accepts cn3. That includes one built on `eth_account` (0.13.7, `Account.recover_message`), which returns the ledger address for it. So a single link would admit two distinct signature byte strings, and any system that keys or deduplicates on signature bytes breaks. EIP-2 low-s is what makes the signature canonical.

**Independent cross-check.** `eth_account` agrees with this runner on every vector except cn3 (it accepts the high-s form, above). cn5 and cn6 are refused there with a `ValueError`.

The test key is published in `MANIFEST.json` (`test_key_address`). It is derived as `keccak256("evidence-record-conformance crypto-profile test key v1")` and is never a real signer.

## Not yet covered

- EIP-712 typed-data counter-signatures. p1's *payload* signature is EIP-712; this profile covers only the ledger's `personal_sign` over links.
- Signer-set rotation: which key was authoritative at which seq.
- Counter-signatures on non-genesis live links: only one is public today (p27's chain). More live vectors can be added as the ledger publishes them.
