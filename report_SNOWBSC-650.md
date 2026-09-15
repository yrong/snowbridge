# Parachain light client: Verification.verifyCommitment accepts a forged BridgeHub c ommitment via second-preimage node substitution (unbounded headProof.width), drain ing the AssetHub Agent (SNOWBSC-650)

- **ID:** SNOWBSC-650
- **State:** in_review
- **Severity:** High (8.9)
- **Author:** @zake
- **Assignee:** @HP-Triage0x00
- **Submitted:** August 04, 2026 09:50 AM
- **Published:** August 04, 2026 09:54 AM
- **Vulnerability type:** Other
- **Program:** Snowbridge On-Chain Code

## Vulnerability details

## Summary

`Verification.verifyCommitment` reconstructs the parachain-heads Merkle root from caller-supplied
calldata. It takes `proof.headProof.pos` and `proof.headProof.width` verbatim and the only
constraint applied anywhere is `pos < width`. Nothing binds `width` to the real number of
parachains, so a caller can declare a tree one level deeper than the real one and have the verifier
perform an extra fold on their behalf.

Independently, the parachain-heads tree that BEEFY commits to is built by
`binary_merkle_tree::merkle_root::<Keccak256, _>` over *raw, variable-length* leaves, hashed with
the **same** hasher used for inner nodes and with **no domain separator** — the crate says so
itself: *"leaves, that are initially hashed using the same hasher as the inner nodes"*. A leaf whose
preimage is exactly 64 bytes is therefore indistinguishable from an inner node. The leaf preimage is
`SCALE((ParaId: u32, HeadData: Vec<u8>))` =
`u32le(paraId)[4] ++ compact(len)[1 when len <= 63] ++ head_data[len]`, and `4 + 1 + 59 = 64`:
**a parachain whose head data is exactly 59 bytes owns an inner node.**

Composing the two: a party controlling one leaf of the BEEFY parachain-heads tree can make the
Gateway accept a BridgeHub commitment that BridgeHub never produced — without breaking a single
hash and without touching BEEFY. Every validator signature involved stays genuine.

## Affected components (deployed, Ethereum mainnet)

Gateway proxy `0x27ca963c279c93801941e1eb8799c23f407d68e7` (`operatingMode() == Normal`) →
implementation `0x36e74FCAAcb07773b144Ca19Ef2e32Fc972aC50b` (`Gateway202602`); BeefyClient
`0x7cfc5C8b341991993080Af67D940B6aD19a010E1`; AssetHub Agent (custodian of all bridged value)
`0xd803472c47a87D7B63E888DE53f03B4191B846a8`, currently holding 1091.02 ETH, 471.56 WETH,
429,768 USDT, 546,219 USDC, 19,324 LINK, 0.121 WBTC.

V2 is live: `v2_outboundNonce() == 696`; `v2_isDispatched(n)` is `true` for n = 1..200+.

Source, repo HEAD `ac97538310b72042c95c6944afa615319a0dac03`:
`Verification.sol:105-134` (`verifyCommitment`), `:215-240` (`createParachainHeader`),
`utils/SubstrateMerkleProof.sol:54-93` (`computeRoot`). The same defect is in the verified deployed
sources of `Gateway202602` (pre-#1798 walker, `src/utils/SubstrateMerkleProof.sol:36-54`); the PoC
exercises both generations side by side.

## Root cause

**(1) `computeRoot` imposes no structural bound.** At HEAD the walk is driven purely by
`(position, width)`: `promoted = position + 1 == width && width & 1 == 1`, and when not promoted it
consumes one sibling, then `position >>= 1; width = ((width - 1) >> 1) + 1`.

Submit `pos = 2j+1`, `width = 2W`. `2W` is even so `promoted` is false; `2j+1` is odd so the
verifier computes `keccak(proof[0] ++ node)`; afterwards `position -> j`, `width -> W`. From there
the walk is bit-for-bit the canonical path of leaf `j` in the genuine width-`W` tree, so the
post-#1798 exact-length check `i == proof.length` is satisfied by supplying exactly one extra
element. The #1798 hardening (commit `74486b1`) fixed proof-length *aliasing*; it does not
constrain `width` and does not close this.

**(2) No leaf/node domain separation in the tree being verified.**
`substrate/utils/binary-merkle-tree` hashes `keccak(raw_leaf)` and `keccak(left ++ right)` with the
same function. Corroborated by Snowbridge's own relayer:
`relayer/chain/relaychain/connection.go:166-169` defines
`type ParaHead struct { ParaID uint32; Data types.Bytes }`, and
`relayer/relays/parachain/merkle-proof.go:82` does `preLeaf, _ := types.EncodeToBytes(head)`.

## The forgery construction (no hash grinding)

1. Fabricate a BridgeHub header `H*` whose digest carries the attacker's own message root `C'` as
   `DigestItem::Other(0x01 ++ C')` — accepted by `isCommitmentInHeaderDigest`
   (`Verification.sol:137-156`).
2. Compute `A = keccak(u32le(1002) ++ compact(len(H*)) ++ H*)`, exactly what
   `createParachainHeaderMerkleLeaf` computes for it.
3. Pick `S = u32le(attackerParaId) ++ 0xEC ++ <27 free bytes>` (32 bytes; `0xEC` = `compact(59)`).
4. Publish head data `head_data = S[5..32] ++ A` (27 + 32 = **59 bytes**).

The honest relay chain now stores a leaf whose preimage is `u32le(paraId) ++ 0xEC ++ head_data`,
which **is** `S ++ A`. So the honest leaf hash equals `keccak(S ++ A)` — precisely the value the
Gateway's walker produces when it folds `A` with left sibling `S`. The asymmetry that makes this
cheap: `A` is chosen **first** and published **afterwards** inside the attacker's own head data.
There is no preimage search and no grinding of any kind.

The remaining `headProof.proof` elements are the *genuine* Merkle path of the attacker's leaf, so
the fold terminates at the *genuine* parachain-heads root. `createMMRLeaf` is then fed the real
MMR-leaf fields and `BeefyClient.verifyMMRLeafProof` checks a real MMR proof against an honestly
relayed `latestMMRRoot`.

## Impact

`verifyCommitment` returning `true` is the only thing between calldata and command dispatch. With a
forged commitment accepted, `Gateway.v2_submit` (`Gateway.sol:401-436`) dispatches whatever is in
`message.commands`: `UnlockNativeToken` (`v2/Handlers.sol:48-59` resolves the agent as
`Functions.ensureAgent(Constants.ASSET_HUB_AGENT_ID)` **unconditionally**, with no origin check, so
the full ~US$6M held by `0xd803472c…` moves to an attacker-chosen recipient) or `Upgrade`
(`Gateway.sol:505-506` replaces the implementation outright, yielding permanent control of the proxy
and of every foreign-token mint). `submitV1` shares `_verifyCommitment` and is affected identically.
Direct, irreversible loss of user principal — not protocol revenue, not a broken invariant.

## Reachability — honest assessment (why I scored High, not Critical)

The forgery needs one leaf in the BEEFY parachain-heads set whose head data is 59 bytes. I checked
the live relay chain rather than assuming.

The **deployed** Polkadot runtime (`polkadot-fellows/runtimes`, `relay/polkadot/src/lib.rs:484-499`)
merkleizes only `parachains_paras::Parachains::get()` chained with a hard-coded
`BEEFY_WHITELISTED_PARATHREADS = [3367]`. Queried at relay block 32,404,496:
`Paras::Parachains = [1002, 1004, 1005]` with head lengths 228 / 247 / 228, and parathread 3367 at
313. **No 64-byte leaf exists today.** Entry to `Paras::Parachains` requires
`ParaLifecycle::Parachain`, whose only non-test writers are the legacy `slots` (lease) pallet and
`paras_registrar::swap`; coretime assignment does **not** change lifecycle. So on Polkadot mainnet
**today the last step needs governance**, and I am not claiming otherwise.

What makes this urgent rather than academic: **polkadot-sdk master has already replaced that
provider.** `polkadot/runtime/parachains/src/paras/mod.rs:1544-1552` exposes `sorted_para_heads()`,
which iterates **all** of `Paras::Heads` up to `MAX_PARA_HEADS = 1024` with no parachain filter, and
`polkadot/runtime/westend/src/lib.rs:448-458` already uses it. Under that provider any
permissionlessly registered parathread is a leaf, and `registrar.register(id, genesis_head, code)`
writes `genesis_head` straight into `Paras::Heads` — no collator, no block production, no PVF. The
attacker simply registers with a 59-byte `genesis_head`; the metrics become `AC:L` and the score
**9.1 Critical**. Snowbridge does not control which provider the relay chain uses, and the fix
belongs on the Ethereum side anyway.

## Remediation

1. **Bind the walk depth (smallest change).** Require `width <= MAX_PARACHAINS` and reject anything
   larger. Even a generous cap of 1024 removes the extra-level trick, since the attack needs `2W`
   where `W` is already the real width. A stored monotonic high-water mark for `width` is an equally
   cheap variant.
2. Long term, domain-separate leaves from inner nodes — correct, but it needs a matching
   relay-chain change, so it is not something Snowbridge can ship alone.

## Not covered by the exclusion list

- **L1/L2 adaptors, `delegatecall` in Agent.sol, V1 relayer economics, off-chain code:** none are in the path — no adaptor, prefunding assumption or residual sweep appears anywhere. The Go relayer and the Rust crate are cited only as evidence of the production leaf format; the defect and the fix are both in deployed Solidity.
- **`message.origin` in V2 handlers:** the attack does not rely on `origin` at all — `unlockNativeToken` ignores it and pins `ASSET_HUB_AGENT_ID`, `Upgrade` takes no origin. The break is *upstream* of dispatch.
- **BEEFY signature-usage counter:** untouched. No `submitInitial`, no tickets, no sampling; every signature used is genuine.
- **Front-running:** no ordering, mempool or race element; the proof is valid standalone.
- **Theoretical / no demonstration:** 8 executed tests from a clean clone are attached, and defect (1) is demonstrated unconditionally against *real mainnet calldata* — a 5-element proof the verifier **rejects** at the true `width = 13` is **accepted** at the fabricated `width = 26`.
- **Not the already-public #1798 issue,** which was index aliasing from short lone-promoted proofs (fixed by `74486b1`). This is node substitution: canonical-length proof, no dependence on promotion, and it survives the #1798 rewrite — the PoC asserts it against **both** walkers.

## Steps to reproduce

Everything below was run end-to-end from a **fresh clone** on a machine with nothing pre-configured.
Two test files are attached; no other change to the repository is needed. They reuse the
repository's own helpers (`test/utils/MerkleLib.sol`, `test/mocks/VerificationWrapper.sol`,
`test/mocks/BeefyClientMock.sol`), so nothing is hand-rolled that the project does not already ship.

## Prerequisites

Foundry only. If you do not have it:

```bash
curl -L https://foundry.paradigm.xyz | bash
foundryup                      # forge 1.7.1 was used
```

## Step 1 — clone at the exact commit

```bash
git clone https://github.com/Snowfork/snowbridge.git
cd snowbridge
git checkout ac97538310b72042c95c6944afa615319a0dac03
git submodule update --init --recursive --depth 1
```

## Step 2 — drop in the two attached test files

Copy the attachments `ZSecondPreimage.t.sol` and `ZProdAnchor.t.sol` into `contracts/test/`.

```bash
cp /path/to/ZSecondPreimage.t.sol contracts/test/
cp /path/to/ZProdAnchor.t.sol     contracts/test/
```

## Step 3 — run the forgery proof

```bash
cd contracts
forge test --match-path test/ZSecondPreimage.t.sol -vv
```

**Observed output (verbatim, from the clean clone):**

```
[⠃] Compiling 110 files with Solc 0.8.34
[⠒] Solc 0.8.34 finished in 4.84s
Compiler run successful!

Ran 5 tests for test/ZSecondPreimage.t.sol:ZSecondPreimageTest
[PASS] test_1_leafPreimageIsExactly64BytesAndCollidesWithAnInnerNode() (gas: 238680)
[PASS] test_2_bothWalkersFoldForgedLeafToTheGenuineRoot() (gas: 251538)
[PASS] test_3_verifyCommitmentAcceptsAForgedBridgeHubCommitment() (gas: 297008)
[PASS] test_4_worksAcrossTreeShapes() (gas: 93628479)
[PASS] test_5_controlNormalLengthHeadDoesNotForge() (gas: 468317)
Suite result: ok. 5 passed; 0 failed; 0 skipped; finished in 136.61ms (139.33ms CPU time)
```

What each assertion establishes:

- **test_1** — the attacker's leaf preimage is exactly **64 bytes**, and the honest relay chain's
  leaf hash `keccak(u32le(paraId) ++ 0xEC ++ head_data)` is bit-for-bit equal to the inner node
  `keccak(S ++ A)`.
- **test_2** — `SubstrateMerkleProof.computeRoot` at repo HEAD returns `valid = true` **and the
  genuine parachain-heads root** for the fabricated `(pos = 2j+1, width = 2W)`. The same test
  repeats the assertion against a byte-for-byte copy of the **pre-#1798 walker that is live on
  mainnet today**, so both generations are shown to be affected.
- **test_3** — the real `Verification.verifyCommitment` (library call, not a mock) returns `true`
  for a commitment BridgeHub never made. `BeefyClientMock.latestMMRRoot` is set to the MMR leaf
  built over the **genuine** parachain-heads root, i.e. exactly what an honest relayer publishes —
  nothing about BEEFY is faked. The negative control in the same test asserts an unrelated
  commitment is still rejected.
- **test_4** — the forgery holds for widths 8, 9, 15, 40, 51, 64 and every attacker index, i.e. it
  is not an artefact of one tree shape (odd widths and promoted positions included).
- **test_5** — control: with a normal-length head data the fold misses the genuine root, confirming
  the 64-byte leaf is the load-bearing element and not something incidental.

## Step 4 — run the production anchor

```bash
forge test --match-path test/ZProdAnchor.t.sol -vv
```

**Observed output (verbatim):**

```
[⠃] Compiling 1 files with Solc 0.8.34
[⠊] Solc 0.8.34 finished in 785.04ms
Compiler run successful!

Ran 3 tests for test/ZProdAnchor.t.sol:ZProdAnchorTest
[PASS] test_prod_forgeryAtProductionWidth13() (gas: 81630)
[PASS] test_prod_realProofFoldsToGenuineParachainHeadsRoot() (gas: 41921)
Logs:
  real BridgeHub parachain-head leaf: 0xe54ef836ebe8fa13c1af1bccef2ed89b122ce88ac3bd54934b50d22029d39c4f
  genuine parachain-heads root: 0xa4f505d91e68accb057b68406a9daf9b091737dec6c4ded952b2f588cfbb8a27
  real production tree width: 13
  real BridgeHub leaf index: 1

[PASS] test_prod_widthIsUnbounded_extraFoldIsAccepted() (gas: 38443)
Logs:
  fabricated-geometry root (accepted, wrong value): 0xaacce79bd7786b81282793c38663694a2c51819cbb8272d8820bb8b4705ca8a3

Suite result: ok. 3 passed; 0 failed; 0 skipped; finished in 2.22ms (879.89µs CPU time)

Ran 1 test suite in 62.60ms (2.22ms CPU time): 3 tests passed, 0 failed, 0 skipped (3 total tests)
```

Every input in this file is lifted verbatim from a **real mainnet transaction**:

> `0x5f6834f58d9db5018f6fa2fd4bd6d442e76a2249d71f286aa1cb6ec44b93f9dc`
> (Ethereum block 25,288,092 — `v2_submit` on the Gateway)

You can re-derive them yourself:

```bash
cast tx 0x5f6834f58d9db5018f6fa2fd4bd6d442e76a2249d71f286aa1cb6ec44b93f9dc input \
  --rpc-url https://ethereum-rpc.publicnode.com
```

then decode with the `v2_submit` signature. The `headProof` tuple reads `(pos: 1, width: 13, [4 proof items])`,
and the header's third digest item is
`(kind 0, engine 0x00000000, data 0x01125a5f2a8a0088f5c666ad31d605c001c9a7cbecb269fc3462d5c260b87cac80)`
— i.e. the V2 discriminator `0x01` followed by the commitment.

This anchors three things that would otherwise be assumptions:

1. The parachain-heads leaf really is `keccak(u32le(paraId) ++ compact(len) ++ header)` — the real
   proof folds cleanly through the unmodified library.
2. The real production tree width is **13**, with BridgeHub at index **1**.
3. **`test_prod_widthIsUnbounded_extraFoldIsAccepted` is the unconditional part of this report.**
   A 5-element proof is **rejected** (`valid == false`) at the true `width = 13`, and the *same
   5 elements* are **accepted** (`valid == true`) at the fabricated `width = 26`. This uses only
   real production data and demonstrates, with no preconditions whatsoever, that the verifier
   imposes no structural bound on the walk.

## Step 5 — confirm nothing else was disturbed

```bash
forge test
```

**Observed:** `Ran 27 test suites: 270 tests passed, 0 failed, 0 skipped (270 total tests)` —
that is the project's own 262 tests plus the 8 added here. No existing test was modified or
weakened.

## On-chain facts you can re-check independently

```bash
export ETH_RPC_URL=https://ethereum-rpc.publicnode.com
cast call 0x27ca963c279c93801941e1eb8799c23f407d68e7 "implementation()(address)"
#   -> 0x36e74FCAAcb07773b144Ca19Ef2e32Fc972aC50b
cast call 0x27ca963c279c93801941e1eb8799c23f407d68e7 "v2_outboundNonce()(uint64)"
#   -> 696                      (V2 is live)
cast call 0x27ca963c279c93801941e1eb8799c23f407d68e7 \
  "agentOf(bytes32)(address)" \
  0x81c5ab2571199e3188135178f3c2c8e2d268be1313d029b30f534fa579b69b79
#   -> 0xd803472c47a87D7B63E888DE53f03B4191B846a8   (AssetHub Agent)
cast balance 0xd803472c47a87D7B63E888DE53f03B4191B846a8
#   -> 1091019266726591167327    (1091.02 ETH, plus 471.56 WETH / 546,219 USDC / 429,768 USDT / 19,324 LINK)
```

The verified deployed sources for `Gateway202602` are on Sourcify
(`https://sourcify.dev/server/v2/contract/1/0x36e74FCAAcb07773b144Ca19Ef2e32Fc972aC50b?fields=sources`);
`src/utils/SubstrateMerkleProof.sol` there is the pre-#1798 walker reproduced as
`DeployedSubstrateMerkleProof` in the PoC.

## Relay-chain state I checked (please verify — it decides the severity)

Queried via `state_getStorage` on a public Polkadot RPC at relay block **32,404,496**:

- `Paras::Parachains` (key `0xcd710b30bd2eab0352ddcc26417aa1940b76934f4cc08dee01012d059e1b83ee`)
  = `[1002, 1004, 1005]`
- `Paras::Heads` lengths: 1002 → 228, 1004 → 247, 1005 → 228, whitelisted parathread 3367 → 313

So **no 64-byte leaf exists on Polkadot today**, and the deployed
`polkadot-fellows/runtimes` provider (`relay/polkadot/src/lib.rs:484-499`) merkleizes only
`Paras::Parachains` plus the hard-coded whitelist. Entry to `Paras::Parachains` needs
`ParaLifecycle::Parachain`, whose only non-test writers are the legacy `slots` pallet and
`paras_registrar::swap` — coretime assignment does **not** change lifecycle. I state this plainly
rather than overclaiming: **on mainnet as it stands, the final step needs governance.**

The reason this is still worth fixing now: `polkadot-sdk` master already replaced that provider
with `parachains_paras::Pallet::sorted_para_heads()`
(`polkadot/runtime/parachains/src/paras/mod.rs:1544-1552`), which iterates **all** of `Paras::Heads`
up to `MAX_PARA_HEADS = 1024` with no filter, and `polkadot/runtime/westend/src/lib.rs:448-458`
already uses it. Under that provider any permissionlessly registered parathread is a leaf, and
`registrar.register(id, genesis_head, code)` writes `genesis_head` directly into `Paras::Heads` —
so the attacker just registers with a 59-byte `genesis_head`, with no collator and no PVF. The
Ethereum-side fix is a bound on `width` and costs nothing.

## Notes for the triager

- I have **not** touched Polkadot mainnet in any way. No parachain was registered, nothing was
  submitted to the live Gateway. All chain interaction was read-only RPC.
- The PoC deliberately does **not** use `setCommitmentsAreVerified(true)` or a `MockGateway`.
  `test_3` calls the real `Verification.verifyCommitment` library function, and the BEEFY root it
  is checked against is the honest one. The excluded "bypass BEEFY with a mock" pattern is exactly
  what this report avoids.
- Happy to extend this to a mainnet-fork run that moves real USDC out of the AssetHub Agent if you
  want the value-extraction half demonstrated as well; it needs `vm.store` on `latestMMRRoot` to
  stand in for the honest relayer, which is why I kept it out of the primary PoC.

## Target

`https://github.com/Snowfork/snowbridge`

## Attachments

- [ZProdAnchor.t.sol](https://dashboard.hackenproof.com/attachments/6a71b6a240041c000d13b2a6)
- [ZSecondPreimage.t.sol](https://dashboard.hackenproof.com/attachments/6a71b6a240041c000d13b2a7)
- [screenshot-zprodanchor.png](https://dashboard.hackenproof.com/attachments/6a71b6a240041c000d13b2a8)
- [screenshot-zsecondpreimage.png](https://dashboard.hackenproof.com/attachments/6a71b6a240041c000d13b2a9)

## Comments

### @zake (author) — August 04, 2026 11:01 AM

## 0. Correction to the test count in "Validation steps", Step 5

I wrote:

> `Ran 27 test suites: 270 tests passed ... that is the project's own 262 tests plus the 8 added here.`

**That is wrong.** 270 came from my working copy, which still contained a throwaway probe file I did
not attach. Following the steps exactly as written, `forge test` reports:

| what | suites | tests |
|---|---|---|
| the repository alone at `ac97538` | 24 | **259** |
| + the two attached PoC files | 26 | **267** |
| + `ZMmrRecency.t.sol` (attached with this comment) | 27 | **269** |

So Step 5 should read **267 tests / 26 suites**, being the project's own 259 plus the 8 added.
Everything else in the report reproduces exactly as written; the per-file outputs in Steps 3 and 4
are unaffected. Apologies for the noise — I would rather flag it than have you hit a mismatch.

## 1. `HeadData` on Polkadot is an arbitrary blob, not a header — measured, not assumed

The report's precondition is "one leaf in the BEEFY parachain-heads set whose head data is exactly
59 bytes". The natural objection is that 59 bytes is a contrived length because a real parachain
header is ~230 bytes. That objection does not survive contact with the live chain.

`Paras::Heads` is opaque to the relay chain — it is whatever the PVF returned, or whatever
`genesis_head` was supplied at registration. Reading all 91 entries from Polkadot at relay block
32,404,496 (`state_getKeysPaged` + `state_queryStorageAt` over the `Paras::Heads` prefix
`0xcd710b30bd2eab0352ddcc26417aa1941b3c252fcb29d88eff4f3de5de4476c3`):

| ParaId | `head_data` length | `head_data` bytes |
|---|---|---|
| 2053 | **7** | `0x4f6d6e69425443` — ASCII `"OmniBTC"` |
| 3440 | **32** | 32 zero bytes |
| 3403–3407 | **72** | zero padding + `011b4d03dd8c01f1…` |

Para 2053's head data is literally a seven-character product name. Head data of *any* length is
routine on Polkadot today, 59 included; nothing constrains it, and no collator, block production or
custom PVF is needed to place it — `registrar.register(id, genesis_head, code)` writes
`genesis_head` straight into `Paras::Heads` at onboarding.

Full length histogram over all 91 registered paras (min 7, max 395):
`228×30, 98×22, 268×10, 72×5, 186×5, 247×4, 226×3, 252×2, 395×2, 238, 313, 299, 32, 7`.

## 2. No recency binding on the MMR leaf — the precondition only has to hold ONCE, ever

The report scoped reachability to the parachain-heads set *as it stands today*. That is stricter
than the code requires.

`Verification.verifyCommitment` ends with
`createMMRLeaf(proof.leafPartial, parachainHeadsRoot)` fed to
`BeefyClient.verifyMMRLeafProof`, which is just
`MMRProof.verifyLeafProof(latestMMRRoot, leafHash, proof, proofOrder)` — **no leaf index, no MMR
size, no recency check**. `proof.leafPartial.parentNumber` is hashed into the leaf but never
compared to anything (`Verification.sol:242-259`), and `v2_submit` / `submitV1` add nothing.

Since an MMR is append-only, every leaf ever inserted stays provable against every later root. So
the attacker may use the `parachainHeadsRoot` of **any historical relay block covered by the current
MMR**, supplying that block's genuine MMR leaf and proof.

I have now demonstrated this rather than merely asserting it. `ZMmrRecency.t.sol` (attached) builds
an MMR exactly the way `pallet-mmr` does — nodes `keccak(left ++ right)`, peaks from the binary
decomposition of the leaf count, root by right-to-left bagging (`bag_rhs_peaks`) — and asserts:

```
[PASS] test_everyLeafOfALargeMmrVerifiesAgainstTheCurrentRoot() (gas: 17203287)
[PASS] test_verifyCommitmentAcceptsTheOldestHistoricalParachainHeadsRoot() (gas: 5150599)
Logs:
  MMR leaves at verification time: 1000
  leaf index used: 0
  blocks of staleness accepted: 999
```

The second test calls the real `Verification.verifyCommitment` and it accepts a parachain-heads root
that is **999 relay blocks stale** against the current MMR root. The first test is the control that
the MMR model is faithful: every leaf of the 1000-leaf MMR verifies against the same root.

Practical consequence: the 59-byte leaf does not have to exist *now*. It only has to have existed in
the BEEFY set at *some* relay block in the past, and the forgery stays valid forever afterwards.
That set is not static — the same decoded mainnet calldata cited in the report shows
`headProof.width == 13` at relay block ~31,619,998, whereas `Paras::Parachains` today is
`[1002, 1004, 1005]`.

I have **not** audited Polkadot's full head-data history for a 59-byte entry; that needs an archive
node and I will not claim it without measuring it.

## Why I am not upgrading my own severity

Getting a para into `Paras::Parachains` still needs governance under the deployed fellows runtime
(`relay/polkadot/src/lib.rs:484-499`), and I verified that coretime assignment does not change
`ParaLifecycle`. What the two points above establish is narrower and, I think, more useful:

- the "59 bytes" shape is ordinary, not exotic; and
- the exposure window is the chain's entire history, not the current block — so waiting for the
  current set to look safe is not a mitigation.

The remediation is unchanged and still cheap: bound `headProof.width` (or pin BridgeHub's leaf
position) in `Verification.verifyCommitment`. That closes it regardless of what the relay chain does
with `Paras::Heads`, now or in the past.
