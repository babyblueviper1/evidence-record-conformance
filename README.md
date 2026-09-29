# evidence-record-conformance

[![verify](https://github.com/tersignhq/evidence-record-conformance/actions/workflows/verify.yml/badge.svg)](https://github.com/tersignhq/evidence-record-conformance/actions/workflows/verify.yml)

Conformance vectors for the **evidence-record layer** of agent commerce — the layer whose
properties must survive the record being held by an interested party.

Record shapes and signatures (maturing in several parallel efforts) answer *"is this record
intact, and what does it name?"* The evidence-record layer sits above them and answers three
questions no record shape or signature supplies by structure alone:

- **Independence** — a record attested only by parties to the transaction evidences
  *structure*, not *independence*. An evaluator **MUST NOT** treat issuer-attested
  composition as a neutral finding. (`independence_reject`)
- **Completeness** — an issuer-attested sequence evidences *ordering*, not *no-omission*.
  Without a committed head, a truncated sequence is invisible; without an independently
  verifiable existence bound, the head itself is just another claim. (`completeness_reject`,
  `existence_reject`)
- **Phase separation** — a record evidencing one economic phase (funding) **MUST NOT** verify
  as evidence of a later one (delivery, settlement). (`phase_reject`)

All three are proposed normatively in the open compliance-fields extension PR
([x402-foundation/x402#2853](https://github.com/x402-foundation/x402/pull/2853), under
review); this suite makes them executable.

**Externally exercised.** The corpus has been executed and attacked from outside this
repository, on the record: byte-identical reproduction from the IETF `web-bot-auth` list
([Songbo Bu, 2026-08-10](https://mailarchive.ietf.org/arch/msg/web-bot-auth/8JVz3WDXgmS9W71Az_oALXM5cW4/) —
verifier, TypeScript cross-check, 258-case differential and byte-identical regeneration, against
`46ad663`); a published mutation-adequacy re-grade by
[@Rul1an](https://github.com/tersignhq/evidence-record-conformance/issues/1#issuecomment-5416529673)
(2026-08-25, at `0e560c1`: 11 declared mutants killed, 0 survived, 1 declared equivalent); the
anchor-preimage relation recomputed from a separate implementation
([#3](https://github.com/tersignhq/evidence-record-conformance/issues/3)); and four vector classes
contributed by external authors ([CONTRIBUTORS.md](CONTRIBUTORS.md)).

## Run

```
python3 verify.py
```

stdlib-only, no dependencies, no network. Exit 0 only if every vector produces its expected
verdict **and** the run observed both verdicts **and** the pinned closure of 10 reject reasons
and 11 vector kinds was fully exercised, **and every kind produced both verdicts** — the closure is pinned in the verifier, not derived
from the manifest, so a fork that quietly drops a class goes red. A green run demonstrates
the verifier discriminates, not merely accepts.

## Vector classes

| class | accepts | rejects | reason code |
|---|---|---|---|
| content address (keccak256 over RFC 8785) | p1 (live), p3 | n1 value drift | `recompute_mismatch` |
| canonical bytes | p2 | n2 **hoisted integer keys**, n12 **code-point key order** | `canonicalization_reject` |
| number domain (I-JSON integers) | p12 (2^53−1 boundary), p13 (**decimal string** beside integer — spec-lockstep) | n10 **float**, n11 integer past 2^53−1 | `number_domain_reject` |
| number token in the digest domain | p25 (**integer token** via raw `payload_text`) | n35 **integer-valued float token** (wire bytes `2.0` — `JSON.parse` collapses it to `2`, the cross-engine divergence the pair closes) | `number_domain_reject` |
| supplementary-plane key order (UTF-16 vs code point) | p14 | n12 | `canonicalization_reject` |
| chain link (artifact ∥ prev ∥ seq) | p4 | n3 wrong predecessor | `continuity_reject` |
| per-seller set continuity + completeness | p6 (with per-record links) | n4 **silently omitted record**, n17 **renumbered omission** (stale link), n38 **float `seq` token** (p6's set with `head.seq` written `3.0` — `JSON.parse` collapses it to `3`; a sequence number is an integer token) | `completeness_reject`, `continuity_reject` |
| witnessed inclusion vs completeness | p24 (**witnessed complete set**) | n34 **witnessed inclusion is not completeness** | `completeness_reject` |
| chain commitment (accumulator over counter-signed links) | p26, p27 (live) | n36 **substituted prefix**, n37 **last-link-only accumulator** | `continuity_reject` |
| duplicate sequence number (equivocation) | p28 (issuer-only, **distinct seqs**), p29 (**committed prefix**) | n39 **two records at one seq** (issuer-only), n40 **equivocating record at a committed position** | `completeness_reject`, `continuity_reject` |
| anchored existence bound | p5 (live) | n5 truncated/substituted head | `existence_reject` |
| economic-phase separation | p7 | n6 funding-as-delivery, n18 **unrecognized phase** | `phase_reject` |
| offer binding (receipt commits to the accepted offer's canonical digest) | p15 | n19 **offer substitution** (same resource/network, different amount/payTo) | `binding_reject` |
| decision-evidence binding (protected record commits to the canonical authority reduction) | p19 | n27 **unbound reduction**, n28 **reduction substitution** | `binding_reject` |
| boundary binding | p18 (binds prefix **and** position), p20 (**suite transition** preserves the prefix under the suite in force when written) | n25 **fabricated boundary** (prefix-only binding), n26 **downgrade** (coverage over an empty attestation), n29 **retroactive re-digest** (transition binds the successor-suite digest of the same bytes — the engine that re-hashes history agrees with it, so it discriminates) | `boundary_reject` |
| independence criterion | p8, p9 (no claim), p10 (claim **set**), p11 (set, silence only), p16 (scope ⊆ **derived** commitments), p17 (**derived** commitments, resolvable settlement), p21 (**URN identities** — the criterion decides under a second identity syntax), p22 (**delivery commitment**, recomputed digest, claim silent), p23 (**delivery independence within commitment** — the vector that drives the delivery derivation; no settlement present) | n7 issuer-only attestation, n8 **unrecognized claim**, n9 **unread member in a set**, n13 **party alias** (whitespace), n14 unparseable attestor, n15 claim w/o attestations, n16 non-object attestation, n20 **scope past commitment**, n21 **empty settlement** (derived commitments), n22 **declared override** (list beside derivable result), n23 **explicit-null declaration** (the engine-fork input), n24 **declared with no scope asserted** (the presence rule's second half), n30 **URN self-attested** (rejects for the independence reason, not the identifier), n31 **URN alias** (trailing slash — n13 one syntax over; percent-encoding stays a stated open sibling), n32 **delivery self-attested** (same record as p22, independence claimed over it — the deliverer's own signature is the only attestation), n33 **delivery substitution** (p23's bytes tampered, digest as issued — commits to no delivery, the claim overreaches; rejects on the scope branch, not the unevaluable one) | `independence_reject` |

Two design rules, both enforced by the run itself:

1. **At least one adversarial vector per known failure class** — an all-happy-path suite
   proves nothing about the class it never exercises. n2 encodes a failure observed in a real
   implementation (JS engines hoist integer-like keys into numeric order on object rebuild,
   silently defeating sort-then-stringify; RFC 8785 orders `"1" < "10" < "2"` by UTF-16 code
   units); n12 is the same rule where it bites hardest — a supplementary-plane key sorts FIRST
   by UTF-16 code units and LAST by code point. n4 is the completeness class this layer exists
   for, and n17 is its harder sibling: omission hidden by renumbering, visible only because
   the relabeled record carries the link computed for its original position.
2. **Every criterion is two-sided** — each class has an accepting twin, so an implementation
   that unconditionally rejects a class fails the suite just as one that unconditionally
   accepts it does (p7/p8 exist for exactly this). **Enforced per kind since 2026-08-19**,
   not per run: until then the gate checked `{valid, reject}` over the whole run, so a
   criterion whose accepting vectors all disappeared stayed green as long as some other
   criterion contributed a `valid` somewhere — the rule was real in this paragraph and absent
   from the gate. Reported by @Rul1an (#1), who also traced what it had already let through:
   `d50545a` moved the independence criterion from deciding to not-deciding under URN
   identities, and the run said nothing. It is also why p21/n30 exist — one accepting vector
   per identity syntax the manifest says the criterion evaluates, so that trade goes red at
   the commit.

A third rule, added after this suite failed it: **a criterion's trigger must fail closed.**
An exact-equality trigger (`if claimed != "independent": valid`) reads any unfamiliar claim
string — including a *stronger* one — as no claim at all, switching the check off precisely
where more was asserted. Silence is a valid state (p9); an assertion the verifier cannot
interpret is not (n8). Failing closed also means *returning a verdict for every shape*: a
claim with no attestations (n15), an attestation that is not an object (n16), or an attestor
identifier that does not parse as an address (n14) each produce a reject, where earlier
implementations raised and produced no verdict at all — including the set form (p10), which
is where a field carrying two orthogonal criteria has to land. Reported against this suite
by [@Rul1an](https://github.com/tersignhq/evidence-record-conformance/issues/1).

A fourth criterion property, from the extension's commitment-scope rule (first proposed in
[x402-foundation/x402#2887](https://github.com/x402-foundation/x402/issues/2887), 2026-07-27):
**an independence claim reaches exactly as far as the record's commitments.** However
independent the attestor, the attestation covered the committed bytes and nothing else — a
claim covering an uncommitted fact class rejects (n20), and a scoped claim within the
commitments accepts (p16). This is a rule its authors fail-safe on deliberately: a record with
no delivered-bytes commitment carries no delivery independence, whoever counter-signed it.
Three fact classes are derivable (`MANIFEST.json` → `commitment_derivation`): `settlement` and
`network` off a settlement result, and — since v0.4.0 — `delivery` off the record's own bytes,
when `keccak256(utf8(deliverable_bytes))` recomputes to `deliverable_digest` (p23 accepts a
delivery-scoped claim with a non-party attestor; n33 substitutes one byte of the deliverable and
the claim overreaches). Until then no record could commit to `delivery` at all, so n20 rejected
for a structural reason that happened to be correct for the wrong cause — enumerated by
[@0rkz](https://github.com/tersignhq/evidence-record-conformance/issues/3), whose PayPerByte
fixture (p22/n32) anticipated the derivation and does not move under it. Field naming follows
the manifest's `field_naming` rule: harness keys `snake_case`, protocol-quoted keys keep the
protocol's spelling.

A fifth property, and the reason the fourth cannot be satisfied by assertion: **a record's
commitments are DERIVED from the record, never declared alongside it — and a declared
commitment scope is itself a rejectable input, whatever it holds.** A declared commitment
list lets a record assert the very scope the commitment-scope rule exists to bound, which makes
the rule vacuous exactly where it matters. The concrete case: x402 v2 §5.3.2 defines the empty
string as what `transaction` carries when settlement failed, while the type only requires a
string — so `success: true` with `transaction: ""` is well formed and commits to no settlement
anyone can resolve. Deriving commitments off the settlement result rejects an independence claim
over that record (n21) without resolving anything on-chain, and accepts the same claim when the
result carries a transaction reference that resolves (p17). The property is enforced on the
field's *presence*: a record carrying `record_commits` beside a derivable result rejects even
when the list matches the claim (n22 — the override that made the first, fallback-shaped fix
decorative), and an explicit `null` rejects identically in both implementations (n23 — the
input on which a value-sentinel guard forked the two engines; both now guard on key presence,
whose semantics are identical in Python and JS). Reported against this suite — twice, the
second time against the first fix — by
[@Rul1an](https://github.com/tersignhq/evidence-record-conformance/issues/4).

A sixth, added by the same review discipline: **identity comparison runs after
normalization.** EIP-55 mixed case and stray whitespace are the same address; without
normalization, a party relabels itself as its own "outside" witness by appending a space to
its own address (n13) — an alias bypass of the independence criterion, failing open exactly
where the criterion exists to fail closed. An identifier that does not parse *after*
normalization is not evaluable and rejects (n14).

A seventh property applies the same binding arithmetic to a different semantic object:
**a protected record presented as evidence of an authority decision must commit to the exact
decision-evidence object it names.** Without that commitment, the presented reduction is
unbound and rejects (n27). n27 deliberately exercises only this missing-commitment branch;
the distinct-object contrast is load-bearing across p19/n28: a commitment to reduction A
accepts A (p19) and rejects B (n28). This structural criterion does not validate the authority
intersection, authenticate the producer or establish historical position; it only makes a
missing commitment and substitution detectable.

This suite instantiates the relation with its local RFC-8785-compatible canonicalizer and
Keccak-256. The conformance property is the algorithm-parametric relation “matching canonical
object accepts; missing or mismatching commitment rejects”, not a prescription of a digest,
canonicalization, or field location for AUEC, MCP, or another protocol.

## Per-vector provenance (v0.5.3)

Every `MANIFEST.json` entry names its `author` and its `origin`. `author` is the GitHub account
that authored the commit adding the vector; check any entry with
`git log --diff-filter=A -- vectors/<file>`. `origin.class` says where the vector's material came
from, from a closed set, and `origin.source` names the PR, commit, fixture, published reproduction
or live record.

| `origin.class` | vectors | material |
|---|---|---|
| `synthetic` | 48 | inputs constructed in `tools/gen_vectors.py` |
| `live-ledger` | 3 (p1, p5, p27) | a record from the live ledger, unaltered, with a `provenance` block in the vector |
| `live-ledger-derived` | 4 (p4, n1, n3, n5) | a value from those records, reused or altered |
| `contributed` | 14 | an outside contributor's PR, commit, fixture or published reproduction |

Of the 69 vectors, nine were authored by four outside contributors (@Rul1an p11/n9,
@mohammedmessaoudene-cmd p19/n27/n28, @navigatorbuilds p20/n29, @0rkz p22/n32). Five more were
written here on outside material, and their origin names its author: p23/n33 on @0rkz's
PayPerByte fixture, and n22/n23/n24 from @Rul1an's published reproductions in issue #4. Thirteen
vectors carry the live ledger's signer address as sample data, and their `origin.source` says so.
Both engines read it only as an attestor outside the parties, so any other well-formed address
outside a vector's parties gives the same verdicts.

Generation fails if a vector has no entry, if its class disagrees with the live-ledger values or
`provenance` block in its own bytes, or if it carries @0rkz's fixture without crediting him. The
class of every other `contributed` entry is declared rather than derived from the bytes; each
names the PR, commit or issue comment it rests on, which is where to check it. Authorship is not
decidable from the bytes either; the git command above checks it.
Credit for *reporting* a failure class a vector pins is not material and stays in
[CONTRIBUTORS.md](CONTRIBUTORS.md).

Metadata only: every vector file is byte-identical to v0.5.2, and neither engine reads the new
fields, so verdicts, kinds and the reject-reason closure are unchanged.

## Duplicate sequence numbers (v0.5.2)

A sequence attested only by its issuer evidences ordering. It does not evidence that no other
record carries the same `seq` and `correctionSeq`: an issuer holding two records under one
number can present each to a different relying party, and each presentation is complete on its
own terms. `chain_set` has always rejected a second record at an occupied seq, but no vector
reached that branch — a verifier that deduplicated records by seq before the completeness check
passed all 65 pre-0.5.2 vectors (measured 2026-09-28, in both engines). n39 pins it: two
different records carrying the same `seq` and `correctionSeq`, presented together beside the
issuer's own attestation, reject on the duplicate; p28 is the same records at distinct numbers.

What one presentation cannot show is the record it does not contain. n40 is the issuer's other
record presented alone at position 2 of p29's prefix, prevs and links recomputed: it passes the
structural `chain_set` predicate under p29's head digest (asserted in `tools/gen_vectors.py` on
every regeneration), and only the accumulator over every link rejects it. Arithmetically n40 is
n36's substitution at an interior position, and the mutants it kills are ones n36 and n37
already kill; what it adds is the class — a second record under an existing number, not a
forgery.

Additive: every pre-0.5.2 vector is byte-identical. The differential battery gained a
duplicated-record mutation for both chain kinds; against a TypeScript engine that deduplicates
by seq it goes red where the previous battery stayed green.

## Number-token class on integer fields (v0.5.1)

`JSON.parse` collapses the wire token `3.0` to the integer `3`; Python's `json` keeps a float, and
every integer predicate in `verify.py` rejects it. Until v0.5.1 the two engines therefore diverged on
the same bytes for a fractional or exponent `seq` token — a real parity fork, found by an adversarial
review of v0.5.0. The suite's number-domain boundary has always been the TOKEN class (p25/n35 pin it
for canonical bytes); n38 pins the same boundary for sequence numbers, and the TypeScript engine now
loads every vector and differential case through a reviver that reads integer fields at the token
level (Node ≥ 21 source access), so both engines reject `3.0` / `3e0` wherever an integer is
required. Additive: every pre-0.5.1 vector is byte-identical; the differential battery gained
float-token mutations on `head.seq` and `records[].seq` for both chain kinds.

## Commitment accumulator (v0.5.0)

A committed head binds the **last** record only. Two prefixes that end in the same record —
the real one, and one whose earlier rows were substituted with prevs and links recomputed —
both pass the `chain_set` predicate and both sit under the same anchored head digest; the
head cannot tell them apart, and an anchor over the head therefore commits to the final
record, not to the prefix beneath it. The `chain_commitment` kind pins the construction that
closes this: an accumulator folded over **every** recomputed link,

```
acc_0 = keccak256(utf8("tersign-chain-commitment-v1"))
acc_n = keccak256(acc_{n-1} || link_n)        link_n = keccak256(artifact_n || prev_n || seq_be8)
```

with `prev_n` the previous record's artifact digest (32 zero bytes at `seq` 1). `head.acc`
must equal `acc_{head.seq}`; any omission, insertion, reordering or rewrite below the head
changes it. The seed is a tagged digest, never the 32-zero-byte link-genesis sentinel — link
preimages are 72 raw bytes, accumulator preimages 64, every canonical-object digest is UTF-8
text starting `{`, so the three domains cannot collide by construction. Production anchors
`keccak256(utf8(canonical({acc, head, schema: "tersign-chain-commitment-v1", seq})))` rather
than the head digest, so one anchored value commits the whole prefix (p27 is that live chain;
its anchor row carries the subject object). n36 is the substituted prefix presented with the
real chain's accumulator; n37 is an accumulator folded over the last link only — the exact
value an anchor over the head commits to, and the shape this kind exists to reject.

The kind is **additive**: every pre-0.5.0 vector is byte-identical, `chain_set`'s semantics
are unchanged (`chain_commitment` runs it first and propagates any non-valid verdict as-is),
and the external reproductions at `46ad663` (Songbo Bu) and `0e560c1` (@Rul1an) stand as
published. Verification is O(N) in the number of records — one link and one accumulator step
per record, hashing only — which is the cost of a completeness check that does not delegate
to anyone's word; the anchor over the commitment is what turns the fold into an existence
bound (`anchor_relation` over the commitment digest).

## Scope boundary — structural profile vs crypto profile

This stdlib core decides the **structural predicate**: digests, canonical bytes, sequence
closure, link arithmetic, declared-claim evaluation. It does **not** recover
counter-signatures. A structurally complete set whose head and links were all recomputed
wholesale by a single forging party passes the structural predicate — what prevents that in
production is that every chain link is counter-signed at transaction time by a party outside
the transaction, and the chain's commitment is anchored (p5, p27). Signature recovery over the links (secp256k1
`personal_sign`; signer published at `https://tersign.ai/v1/ledger`) is the **crypto
profile**, the suite's next milestone — deliberately outside the stdlib core so that every
check above needs hashing only.

## Live provenance — three vectors are records from the live ledger

Four more (p4, n1, n3, n5) reuse or alter a value from these records; their manifest
`origin.class` is `live-ledger-derived`.

**p1** is the tersign ledger's genesis (demo) receipt — the one receipt whose full body is
public by design. Re-fetch the bytes and recompute the digest yourself:

```
curl https://tersign.ai/v1/genesis        # the record body — same bytes as the vector
python3 verify.py                         # recomputes the digest from the committed bytes
curl https://tersign.ai/v1/receipts/0xe5874f1ffe87f0a6dd9eb157730f67b86ee4538b125fe30fcc4e165213dd3fc4/verify
```

(The payload's embedded `resourceUrl` is the historical demo resource the genesis record was
issued against, on the ledger's legacy workers.dev alias — the record's validity derives from
digest, counter-signature and anchor, never from URL liveness.)

**p5** is a counter-signed chain head anchored in Bitcoin block 958163. The existence bound
is checkable without trusting the operator:

```
curl https://tersign.ai/v1/anchors/ledger:0xb2c5d2bd28ff65e13c1549a718a4c447916d5277ce046b2061ed63749ff287d9
                                          # the anchor record BY ID; fetch proof.ots from its proofUrl
ots verify -d cf48bed1712f5b7df2a309fb52cb2b3d51ab1a04730e3b115cd3db79c96c9b1a proof.ots
```

(Fetch it by id: the unqualified `/v1/anchors` listing returns the newest rows and will
eventually not include this one.) `ots verify` needs a local Bitcoin node to confirm the block
header. Without one, the no-node path is stronger anyway — it shows the trust chain
explicitly: `ots info proof.ots` prints the Bitcoin attestation (height 958163, merkle root
`d23b2da439b5…f85df18c`); compare that root against block 958163 in any block explorer.

**p27** is the ledger's genesis chain — 13 counter-signed records, seq 1 being the genesis
receipt p1 — with the accumulator over all 13 links, and the commitment over it is anchored
in Bitcoin block 964428. Re-walk and re-fold it yourself, then check the anchor:

```
curl https://tersign.ai/v1/receipts/0x339800528596c7d53d32571ad999695aef6dfc8fc86dcc4fb827bb6080493961/verify
                                          # the head; follow prevDigest 12 more times to seq 1 (prevDigest null)
python3 verify.py                         # folds the accumulator over the 13 committed records
curl https://tersign.ai/v1/anchors/seller:0xcbbef04598368ed02ae67fc0c8ffade6753628d0b8faf4e9211c9dd49a2dbe7b
                                          # subjectArtifact = {acc, head, schema, seq}; merklePath to batchRoot; proofUrl
```

The anchor's `subjectDigest` is `keccak256(utf8(canonical(subjectArtifact)))` and its
`anchoredDigest` is `sha256` of those bytes (the same `anchor_relation` p5 pins); the vector's
`provenance` block carries both values.

Counter-signatures in the live vectors are secp256k1 `personal_sign` material; recovering them
requires an EVM crypto library and sits outside the stdlib core by design — every check above
needs hashing only.

**Pin the signer, do not fetch it.** The ledger signer at genesis is
`0x9d38BA84730271eb27Ac9bD4Bd2620c08dB4FDa6`, committed in this repository since
`p1-live-genesis-receipt.json` (field `ledger_signer`) and reproduced byte-identically by
`tools/gen_vectors.py` on every CI run. `https://tersign.ai/v1/ledger` serves the same value,
but a key fetched at verification time only proves what the server says *now* — "verify
offline" has to mean against a key committed at a fixed point in time, which is what the
vector gives you. The genesis receipt digest is likewise fixed
(`0xe5874f1ffe87f0a6dd9eb157730f67b86ee4538b125fe30fcc4e165213dd3fc4`) and its chain head is
Bitcoin-anchored, so the pinned pair is recoverable from an anchored record rather than from
an endpoint. Any future signer rotation must be published as a new pinned vector, never as a
silent change at that URL.

## Canonicalization contract

RFC 8785 (JCS) over the I-JSON vector domain: integer numerics within `|n| ≤ 2^53−1`
(enforced two-sidedly — p12 accepts the boundary value, n11 rejects one past it), **no
non-integer JSON numbers** (n10 — RFC 8785 §3.2.2.3 routes numbers through ECMAScript
`Number::toString` over IEEE 754 doubles, so a fractional value's bytes depend on the
producer's number pipeline, and the digest binds the nearest double rather than the decimal
the source system held; fractional values are decimal **strings**, pinned in lockstep with
the compliance-fields extension's number rule by p13), duplicate object names rejected at
load. Keys sort by **UTF-16 code units** (the verifier encodes to UTF-16BE and compares
bytes — explicit, not delegated to the host language's default; p14/n12 pin the
supplementary-plane case where code-unit and code-point order genuinely diverge). Content
addresses are keccak256 (pre-NIST padding, as used by Ethereum) — `hashlib.sha3_256` is a
different function; a compact Keccak implementation is vendored in `keccak.py`, self-checked
at import against measured known-answer values.

## Reproduction

Independent reproduction means a run by an implementation that shares no code and no authors with this suite's engines. At `0eda303`, two such implementations have each run the full set and published the output: a Node verifier ([#8](https://github.com/tersignhq/evidence-record-conformance/issues/8)) and a clean-room Python verifier ([#9](https://github.com/tersignhq/evidence-record-conformance/issues/9)). Both match all 69 verdicts and every named reject reason. That reproduces the 69 vectors; a reading no vector pins is not reproduced by it. Agreement makes no verifier a reference, ours included. Earlier outside runs re-ran *our* verifier (byte-identical at `46ad663`; mutation-tested at `0e560c1`), and an outside verifier ran `p18`, `n25` and `n26` (CONTRIBUTORS.md, @Tetsurohhori).

Cross-implementation measurement: `tools/cross_check_ts.mjs` is a second implementation of
**every check** on a TypeScript stack, written by the same authors as `verify.py`. Agreement
between the two is therefore not independent reproduction (see *Reproduction* above); it is
run over the **full committed corpus**
(`npm i viem` in the repo root, then `node tools/cross_check_ts.mjs`) — two implementations,
one vector set, byte-level agreement required on every verdict and reason. CI runs both on
every push.

That corpus runner scores each engine against `MANIFEST.json`, so engine-to-engine agreement
there is *transitive through the shared expectations* — both implementations can hold the same
wrong assumption and stay green, and an input the corpus does not carry is never compared at
all. `tools/differential.py` is the non-transitive control: every vector **plus** an
off-corpus mutation battery at fork-prone keys (explicit nulls, declared/derivable conflicts,
containers of the wrong shape), run through **both engines directly**, verdict and reason
compared with no manifest in between. Replayed against the pre-fix engines it reports exactly
the null-guard fork it was built after; on current code it must report zero divergences. CI
runs it beside the corpus pass. The limit it closes was identified by
[@Rul1an](https://github.com/tersignhq/evidence-record-conformance/issues/4): parity through a
shared oracle confirms a shared assumption instead of catching it.

Regeneration is deterministic and diffable: `python3 tools/gen_vectors.py` rewrites
`vectors/` + `MANIFEST.json` byte-identically (CI asserts this on every push).

## Contributors

Who sharpened which criterion, and how each contribution landed, is recorded in
[CONTRIBUTORS.md](CONTRIBUTORS.md) — credited by commit authorship rather than by a merge
badge, since some contributions were cherry-picked onto a hardened `main` and their PRs
therefore read as closed.

## License

Apache-2.0. Maintained by [Tersign](https://tersign.ai). Cross-runs, counter-vectors, and
adversarial additions welcome.
