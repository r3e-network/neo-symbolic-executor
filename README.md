# Neo Symbolic Executor

Symbolic execution, security analysis, and bounded formal verification for Neo N3 smart
contracts. Designed to ship as a Neo DevPack submodule so contracts can run `neo-sym analyze`
and the default `neo-sym verify --profile neo-n3-security` proof gate automatically after compile.

## Status

| Component | LOC |
|---|---|
| Engine + decoder + types | ~16,500 |
| Formal verifier / proof engine | ~26,400 |
| NEF + manifest parsers | ~900 |
| 37 detectors + reports + gates + framework | ~5,300 |
| CLI | ~1,700 |
| SMT-LIB layer | ~2,100 |
| Fuzzer (23 targets, multi-worker) | ~3,800 |
| **Total** | **~56,700** |

**Tests:** 1420 xUnit cases passing (smoke + audit-regression + security-hardening + per-detector + parser
edge cases + end-to-end vulnerability showcase + property-style fuzz harness +
locale-stability + clone-isolation + formal-verification/security-profile regressions).

The CLI's `analyze` command runs the engine once per manifest ABI entrypoint, seeding the eval
stack with one fresh symbolic value per declared parameter. Without a manifest the engine runs
once from offset 0 with an empty stack — useful for ad-hoc bytecode but not for real DevPack
contracts whose dispatcher needs the method-name argument.

**Proof scope:** both `analyze` and `verify --profile` reason per ABI **method body**, jumping
directly to each method's declared offset with symbolic parameters. The compiled offset-0
dispatcher/routing bytecode and the non-ABI `_deploy`/`_initialize` routing surface are not
executed as proof entrypoints, so a passing gate certifies the analyzed method bodies, not the
dispatcher's method-selector routing. (Manifest-level dispatch keys are still validated: duplicate
same-name/same-arity ABI methods are rejected, matching Neo's name+param-count dispatch.)

Neo N3 C# coverage is first-class: DevPack `.nef` + `.manifest.json` artifacts drive per-method
analysis from ABI offsets, primitive parameters are sorted as Integer/Boolean/ByteString-style
symbols, `Integer` parameters carry NeoVM StackItem integer range constraints, variable-byte ABI
parameters such as `ByteString`, `ByteArray`, and `String` carry `0 <= size <= MaxItemSize`
constraints, ABI `String` parameters additionally carry strict UTF-8 validity facts, fixed-size
ABI primitives such as `Hash160`, `Hash256`, `PublicKey`, and `Signature` carry their Neo
byte-length constraints at method entry. ABI `PublicKey` method-entry parameters prove 33-byte
length and valid secp256r1 ECPoint encoding; ABI returntype conformance for `PublicKey`
also requires a valid ECPoint encoding. ABI `Array`, `Map`, and `Struct` parameters are seeded as heap-backed NeoVM compound values.
Malformed manifest object-array sections such as `groups`, `permissions`, ABI `methods`,
`events`, or `parameters` fail closed instead of silently shrinking the analyzed contract surface.
Declared ABI methods must include a non-empty `name`, non-empty `returntype`, integer `offset`,
and typed parameters; `Void` is treated as a return-only ABI type, so `Void` parameters fail closed
instead of being seeded as synthetic ByteString inputs. Missing proof-critical fields are rejected instead of defaulting to offset
`0`, `Void`, or `Any`. Manifest ABI method offsets used by `analyze` and `verify` must point
to a decoded instruction boundary; offsets into operand bytes are reported as incomplete
stale-manifest coverage instead of being JIT-decoded as proof entrypoints. Declared ABI events must include a non-empty `name` and typed
parameters, and duplicate event names are rejected before event-shape or `Runtime.Notify`
manifest proofs run.
Explicitly invalid Neo manifest metadata, including non-empty `features`, an explicit empty
`name`, duplicate `groups`, duplicate `supportedstandards`, duplicate permission descriptors,
duplicate `trusts`, or duplicate ABI method selectors with the same method name and parameter
count, or duplicate ABI event names, is also rejected before analysis. Security-relevant manifest arrays such as
`supportedstandards`, `trusts`, and permission method lists must contain strings; explicit null or
wrong-typed scalar fields are normalized to `FormatException` instead of leaking parser/runtime
exceptions. NEF bytes fail closed on truncation or trailing data after the checksum, and NEF
MethodToken metadata is decoded strictly: method names must be strict UTF-8, `hasReturnValue`
must be encoded as `0` or `1`, and call flags must not set bits outside Neo N3 `CallFlags.All`.
ABI `Array`, `Struct`, and `Map` inputs use open symbolic models: representative elements keep common
C# paths executable, while unknown runtime length or key-set facts remain proof obligations.
ABI `Any` parameters used by analyze and verification are explored across representative `Null`,
`Boolean`, `Integer`, `ByteString`, `Buffer`, `Array`, `Struct`, `Map`, and
`InteropInterface` method-entry states while reports still mark the surface non-exhaustive
where a proof needs every possible collection length or nested compound shape.
External ABI maps use an open symbolic model so C# methods that call `PICKITEM`, `HASKEY`,
`KEYS`, or `VALUES` on a runtime-supplied map continue through useful paths instead of being
treated as unsupported byte strings. Unknown open-map `PICKITEM` reads record a key-exists
fault condition, and `HASKEY` emits that same predicate so guarded C# map reads can be proved.
`ASSERT`, `JMPIF`, and `JMPIFNOT` path conditions are
normalized through NeoVM truthiness before SMT solving, so successful integer and byte-string
guards contribute non-zero constraints to proofs. Common Runtime environment syscalls such as
`Platform`, `GetTrigger`, `GasLeft`, `GetInvocationCounter`, `GetNetwork`,
`GetAddressVersion`, `GetTime`, and `BurnGas` are modeled without marking proof surface unknown.
`Contract.Call` and NEF `CALLT` calls to the native StdLib `serialize`, `deserialize`,
`jsonSerialize`, and `jsonDeserialize` methods are modeled for concrete single-argument
stack items; `serialize`/`deserialize` and the supported `jsonSerialize`/`jsonDeserialize`
shapes also round-trip closed symbolic StackItem summaries, so common C# serialization flows
can be proved without losing manifest-permission telemetry.
Concrete StdLib scalar conversions such as `itoa`, `atoi`, `strLen`, `stringSplit`, `base64Encode`,
`base64Decode`, `base64UrlEncode`, `base64UrlDecode`, `base58Encode`,
`base58Decode`, `base58CheckEncode`, `base58CheckDecode`, `hexEncode`, and `hexDecode`
are also modeled, including two-argument `itoa`/`atoi` base-10/base-16 calls and
concrete `memoryCompare` / `memorySearch` byte utilities. Concrete invalid decode text for
base64/base64Url, base58/base58Check, and hex decode methods is reported as a reachable VM
fault, and concrete invalid `atoi` text or unsupported concrete `itoa`/`atoi` bases fault
instead of becoming unknown native-call surface. Concrete invalid strict-UTF8 strings, `atoi`
results outside NeoVM's integer range, out-of-bounds `memorySearch` starts, and concrete StdLib
inputs over 1024 bytes are also reported as VM faults rather than opaque native returns.
Native CryptoLib `sha256`, `ripemd160`, `keccak256`, and `murmur32` calls with concrete
ByteString arguments return concrete digests; symbolic ByteString hash inputs return stable
fixed-length digest expressions, including proof-grade 32-byte `sha256`/`keccak256`, 20-byte
`ripemd160`, and 4-byte `murmur32` results when the seed is concrete. `verifyWithEd25519`
calls with concrete message/public-key/signature arguments, `verifyWithECDsa` calls over Neo's
secp256k1/secp256r1 SHA256/Keccak256 `NamedCurveHash` combinations with concrete arguments
or proof-grade symbolic message/public-key/signature inputs, concrete invalid `murmur32`
seeds and unsupported ECDSA curve hashes reported as VM faults, plus `recoverSecp256K1`
calls with concrete 32-byte message hashes and 65-byte signatures whose recovery id is encoded
as 0..3 or 27..30, EIP-2098 64-byte signatures, or symbolic ByteString inputs constrained to
a 32-byte message hash and 64/65-byte signature, concrete BLS12-381
deserialize/serialize/equal/add/mul/pairing operations over G1/G2/Gt values with invalid
deserialize length/encoding and invalid `mul` scalar length/encoding reported as reachable VM faults, and guarded
symbolic BLS12-381 deserialize/serialize round trips with valid compressed G1/G2/Gt encoding fault obligations, same-kind equal/add/mul results with valid scalar fault obligations for symbolic `mul`, and
G1-by-G2 pairing results for 48-byte G1, 96-byte G2, or 576-byte Gt payload shapes, are modeled through
both `Contract.Call` and NEF `CALLT`, returning the exact native hash bytes, verification result, proof-grade
33-byte recovered compressed public key, BLS serialization, or nullable recovery failure instead of an opaque external symbol.
Native NEO/GAS NEP-17 read-only calls to `symbol`, `decimals`, `totalSupply`, and `balanceOf`, plus NEO `getGasPerBlock()`, `unclaimedGas(account,end)`, `getRegisterPrice()`, `getCandidateVote(pubkey)`, `getCandidates()`, `getAccountState(account)`, `getCommitteeAddress()`, `getCommittee()`, and `getNextBlockValidators()`,
are modeled through both `Contract.Call` and NEF `CALLT`; fixed token metadata returns concrete
values, while chain-state-backed supplies, balances, account-state balance/height/last-gas-per-vote fields, and governance prices return stable non-negative symbolic
integers, `unclaimedGas(account,end)` enforces `end == Ledger.currentIndex + 1` and returns stable non-negative symbolic GAS, `getCandidateVote(pubkey)` enforces valid ECPoint public-key arguments and returns a stable integer bounded below by Neo's missing-candidate sentinel `-1`, `getCandidates()` returns an open array of candidate tuples with valid ECPoint keys and non-negative vote counts, `getAccountState(account)` returns null or Neo's four-field NeoAccountState struct with nullable valid-ECPoint `VoteTo` and non-negative `LastGasPerVote`, the committee address returns a stable UInt160 witness principal, and committee/validator reads return open arrays of valid ECPoint public keys instead of opaque external symbols. Stable native read keys include a structural expression fingerprint for symbolic arguments, so derived UInt160 or ECPoint arguments do not alias unrelated chain-state symbols. The model only applies when the effective call flags
include `ReadStates`; missing flags produce a reachable NeoVM fault and dynamic flags remain
conservative incomplete surface instead of a proved native read.
NEO/GAS `transfer(from,to,amount,data)` is modeled separately as a write-capable sensitive native
call: it requires `CallFlags.All`, enforces UInt160 sender/recipient arguments and a non-negative
NeoVM integer amount within the 32-byte input limit, forks symbolic success/failure return paths, emits a proof-visible `Transfer(from,to,amount)` notification payload under the native token script hash only on success paths, returns a symbolic Boolean result that must still be checked by the caller, and remains a sensitive asset-moving call for access-control and manifest-permission proofs. Until native token balance changes and receiver callback side effects are modeled end to end, `neo-n3-security` treats paths that call native NEO/GAS `transfer` as incomplete VM surface rather than proof-grade native transfer semantics.
Ledger `currentIndex`, `currentHash`, `getBlockHash(index)`, `getBlock(hash/index)`, `getTransactionFromBlock(block,index)`, `getTransaction(hash)`, `getTransactionHeight(hash)`, `getTransactionSigners(hash)`, and `getTransactionVMState(hash)` read-only calls are modeled through both `Contract.Call`
and NEF `CALLT` as a stable UInt32 block index, stable 32-byte Hash256 value, nullable block structs with Hash256 links, non-negative timestamp/index fields, Int32-bounded transaction counts, UInt160 next-consensus hashes, native UInt32 block-index and Int32 transaction-index preconditions, nullable transaction structs from either transaction hashes or block/index lookups with UInt160 senders, non-negative fees, bounded scripts, stable transaction height in `[-1, currentIndex]`, nullable signer arrays with UInt160 account fields and bounded witness scopes, and stable VMState enum value with UInt256 hash preconditions.
ContractManagement `getMinimumDeploymentFee()` is modeled as a stable non-negative
chain-configuration integer; ContractManagement `hasMethod` is modeled as a stable boolean query
over a UInt160 target, strict UTF-8 method name, and non-negative Int32 parameter count, returning
false when path-local existence facts prove the target contract is missing, while a true
`hasMethod(target,...)` result proves target contract existence on that path;
`getContract` and `getContractById(id)` fork nullable contract interop results through both
`Contract.Call` and NEF `CALLT` after proving
the contract id fits Neo's native Int32 conversion, a non-null `getContract(target)` result
proves `isContract(target)` on that same path, and prior `isContract(target)` facts constrain
later `getContract(target)` results to null/non-null consistently. `isContract` forks stable
true/false existence results for the queried UInt160 target so token-transfer proofs can
distinguish receiver contracts from non-contract accounts; `getContractHashes()` returns a modeled
StorageIterator with Neo's `RemovePrefix` option and key/value pair results. ContractManagement `deploy(nef,manifest,data)` returns a
`Contract` interop result while remaining a write-capable sensitive external call with required
`CallFlags.All`, non-null NEF/manifest payload-shape checks, strict-UTF8 manifest validation, and
non-Void MethodToken stack semantics. ContractManagement `update(nef,manifest,data)` and
`destroy()` lifecycle calls are recognized as write-capable sensitive native calls with exact
call-flag, payload-shape, and Void MethodToken stack semantics; lifecycle calls do not count as
read-only modeled native calls, so security-profile proofs must still prove authorization and
manifest-permission posture before those lifecycle calls are considered safe. Policy `getFeePerByte`, `getExecFeeFactor`,
`getStoragePrice`, `getAttributeFee(attributeType)`, and Oracle `getPrice` numeric read-only calls are modeled as stable non-negative
chain-configuration integers; Policy `getAttributeFee(attributeType)` enforces valid `TransactionAttributeType` enum values, while
Policy `isBlocked(account)` is modeled as a stable boolean query with a UInt160 account precondition.
Oracle `request(url,filter,callback,userData,gasForResponse)` is recognized as a sensitive
write-capable no-return native call with required `States|AllowNotify` flags, strict-UTF8
URL/filter/callback checks, byte-size limits, public callback-name enforcement, serializable
512-byte userData bounds, the 10,000,000 datoshi response-gas floor, and Int64
`gasForResponse` conversion bounds.
RoleManagement `getDesignatedByRole(role, index)` enforces valid Role enum values and native UInt32 index conversion, then returns an open
designated-public-key array: the array may be empty, while representative elements carry 33-byte
valid ECPoint facts. Other recognized Neo N3 native contract methods, including
remaining unmodeled ContractManagement methods, Ledger methods outside the modeled set, unmodeled
RoleManagement methods, and unmodeled Policy/Oracle methods, are never treated as ordinary opaque external
returns when a method-specific proof model is missing; the VM surface is marked incomplete instead.
`CONVERT` preserves symbolic Boolean branches when converting to `Integer`, `ByteString`, or
`Buffer`; fixed-length symbolic `ByteString` values such as `Hash160` and `UInt160` can also
convert to mutable heap-backed `Buffer` objects with byte-cell range facts.
`ISTYPE` guards on unknown external returns refine subsequent `CONVERT` operations to the
checked NeoVM stack-item type on the assertion/branch success path.
Stable runtime values such as `GetNetwork` and `GetAddressVersion` reuse the same symbolic
value throughout one invocation. `GetInvocationCounter` is stable within one invocation and
increments across modeled same-contract self-calls.
`CallingScriptHash`, `ExecutingScriptHash`, and `EntryScriptHash` are modeled with Neo N3
runtime stability: `CallingScriptHash` may be `null` in entry context, while every non-null
runtime script hash carries Neo's 20-byte UInt160 shape. In proof-grade `.nef` runs with
`--deploy-sender-hash`, `Runtime.GetExecutingScriptHash` is bound to the computed deployed
contract hash instead of an unconstrained symbolic UInt160.
`Runtime.GetTrigger` defaults to `Application`; ABI `verify` methods run with the `Verification`
trigger, and verification artifacts record `default_runtime_trigger`. `Runtime.GetTime` requires
an Application-trigger persisting block: application methods receive a stable non-negative
symbolic timestamp, while `verify` methods that call `GetTime` produce a reachable VM fault unless
the specification excludes that path.
`Runtime.GetRandom` returns a fresh non-negative symbolic integer for each call, matching Neo's
unsigned BigInteger random value without incorrectly treating repeated calls as stable.
`CurrentSigners` exposes an open transaction-signer array with a modeled representative signer
shape, including a 20-byte account, scope, allowed-contract, allowed-group, and witness-rule
fields, and repeated reads return the same signer-array reference within one invocation.
`GetScriptContainer` / `Runtime.Transaction` returns a modeled transaction structure with hash,
version, nonce, 20-byte sender, non-negative fees, valid-until block, and script fields. The
transaction hash is modeled as 32 bytes, the script is a bounded byte string, and repeated reads
return the same transaction-container reference within one invocation.
`GetNotifications` returns the path-local invocation notification list for null/all-zero wildcard
filters and exact script-hash matches, using each recorded notification's own script hash instead
of the caller's current hash at query time. Concrete non-matching filters return an empty array,
while symbolic filters that cannot be proven to match or miss remain conservative unknown syscall
surface. This keeps event/notification assertions useful after `Notify` without proving filtered
queries from the wrong sender.
Unknown syscall hashes stop exploration conservatively at the `SYSCALL` instruction instead of
inventing a return value and executing following bytecode with an unreliable stack.
Direct `NativeOnPersist` and `NativePostPersist` use from user contracts faults because these
native lifecycle hooks require the matching system trigger.
`Runtime.LoadScript` executes concrete nested script payloads with their argument array,
effective read-only call flags, nested caller/executing script-hash context, nested VM fault
propagation, and NeoVM return-stack merging.
Dynamic payloads, open argument lists, and excessive nesting remain conservative incomplete proof
surface because the callee bytecode is not statically available to the verifier. For custom
specifications this `Runtime.LoadScript` completeness check is scoped by the property's
`requires`, so an infeasible or excluded dynamic-load path does not contaminate proofs about the
selected feasible paths.
Custom proofs execute concrete same-contract `Contract.Call` self-calls and same-contract NEF
`CALLT` MethodToken calls when the current script hash/token hash, method selector, effective call
flags, argument list, and unique manifest ABI target are statically resolved. Dynamic self-calls,
open argument arrays, ambiguous or missing ABI targets, excessive self-call depth, and
non-modeled-native external `Contract.Call` / NEF `CALLT` targets remain incomplete until the
callee implementation semantics, target contract existence, and ABI are covered by a dependency
proof summary that is explicitly trusted for this verification run. Manifest permissions authorize a call
but do not prove external callee semantics for fault-freedom or postcondition proofs. Pass
dependency summaries with `--dependency-proof-summary <path.json>`, bind every summary contract
to local audited artifacts with `--dependency-proof-artifact <hash=program,manifest>`, and use
`--trust-dependency-proof-summaries` only after checking the recorded callee artifacts; verify a
dependency NEF with `--emit-dependency-proof-summary <path.json>` after supplying
`--deploy-sender-hash` to produce a reusable v3 proof summary for methods whose `security.vm_surface` and
`security.vm_fault_free` and `security.abi_return_type` profile results are produced by the
built-in `neo-n3-security` profile and proved without assumptions under the fail-on-unproved
and unqualified-proof gates. Only a trusted dependency proof summary can close external callee
semantics. The artifact binding checks the recorded `program_sha256`, `manifest_sha256`, and
`nef_checksum_hex`, then recomputes the Neo N3 contract hash from the bound NEF, manifest, and
summary `deploy_sender_hash`; missing, duplicate, or unused dependency proof artifact bindings
are rejected with a structured `security.dependency_proof.input` verification result. Trusted summaries without local artifact bindings are rejected by default; pass
`--allow-unbound-dependency-proof-summaries` only for legacy/offline unbound summaries whose
artifacts were checked outside `neo-sym`. Unbound summaries are reported as
`unbound_dependency_proof_summary` assumption-backed proofs and fail the default unqualified-proof
gate unless the run explicitly opts into `--allow-assumption-backed-proofs`. Custom specs that reuse
`security.*` result ids cannot emit trusted dependency summaries, and `--allow-unproved`
verification reports cannot emit trusted dependency summaries; reusable dependency summaries also
cannot be emitted from reports that trusted unbound transitive dependency summaries. Dependency
summary methods record both the effective `initial_call_flags` and `initial_runtime_trigger`, so
Verification-trigger proofs for `verify` methods cannot close Application-trigger external calls.
If a summary claims `require_external_smt`, it must also record a
non-portable external solver version in `smt_solver_version`. The verifier records each
consumed summary's SHA-256 in `meta.inputs.dependency_proof_summaries` and each bound
artifact's contract hash, NEF/manifest paths, and SHA-256 values in
`meta.inputs.dependency_proof_artifacts`; `meta.inputs.dependency_proof_policy` records whether
summaries were trusted for external calls, whether artifact binding was required, and whether
legacy/offline unbound summaries were allowed. The legacy unbound v1
summaries, summaries with unknown schema fields, mismatched proof identity metadata,
assumption-backed proof metadata, invalid checksum/hash bindings, missing typed parameters for
non-zero-arity methods, missing or invalid `initial_runtime_trigger`, forged external-SMT claims,
or duplicate external-call selectors or contract hashes are rejected
instead of being treated as proof.
`CreateStandardAccount` and `CreateMultisigAccount` use deterministic symbolic account-hash
models, so repeated derivations from the same public-key inputs can be proved equal; multisig
account creation enforces Neo's `1 <= m <= publicKeys.Count <= 1024` precondition.
Current Neo call flags are modeled: `System.Contract.GetCallFlags` returns the active context
flags, and syscalls that require `ReadStates`, `WriteStates`, `AllowCall`, or `AllowNotify`
fault when the current context lacks the required flag.
Path-local `Storage.Put`, `Storage.Get`, `Storage.Delete`, and DevPack `Storage.Local.*`
operations update a concrete byte-equivalent symbolic storage model, so read-after-write proofs
do not rely only on telemetry. Values written through `Storage.Put`/`Storage.Local.Put` are
normalized to their persisted ByteString encoding before later path-local
`Storage.Get`/`Storage.Local.Get` reads observe them. Path-local entries with concrete prefixes
are also exposed through `Storage.Find`/`Storage.Local.Find` iterator branches while a separate
symbolic branch preserves unknown persisted storage and iterator exhaustion. Deletes leave a path-local tombstone, repeated unknown reads of
the same symbolic key are stable within a path, path-condition-proved byte-equality key aliases reuse the same
storage value, repeated unknown reads at the same opcode but with different keys receive distinct
symbols, numeric-equality branch guards are not treated as storage key byte aliases, and unknown present values carry Neo's `0 <= size <= 65535` storage-value bound.

## Layout

```
neo-symbolic-executor/
├── Neo.SymbolicExecutor.sln
├── Directory.Build.props
├── global.json                 — pin .NET 10
├── NuGet.Config                — NuGet.org package source
├── src/
│   ├── Neo.SymbolicExecutor/   — engine + decoder + IR + NEF/manifest parsers
│   ├── Neo.SymbolicExecutor.Detectors/  — 37 detectors + reports + gates
│   ├── Neo.SymbolicExecutor.Smt/        — SMT-LIB translator + Z3/portable backend
│   ├── Neo.SymbolicExecutor.Cli/        — `neo-sym` command-line tool
│   └── Neo.SymbolicExecutor.Fuzzer/     — coverage-guided fuzz harness (23 targets)
├── tests/Neo.SymbolicExecutor.Tests/    — xUnit + FluentAssertions
└── devpack-integration/        — MSBuild .props/.targets for DevPack contracts
```

## Build

```bash
dotnet restore Neo.SymbolicExecutor.sln --locked-mode
dotnet build
dotnet test
```

NuGet restore is lock-file based. Keep the per-project `packages.lock.json` files committed so
CI uses deterministic dependency resolution and fails if a package graph drifts unexpectedly.

## Install

```bash
dotnet tool install --global Neo.SymbolicExecutor.Cli
neo-sym --help
```

From a local checkout:

```bash
dotnet pack src/Neo.SymbolicExecutor.Cli -c Release -o ./artifacts/local-pack
dotnet tool install --global --add-source ./artifacts/local-pack Neo.SymbolicExecutor.Cli
```

## Run

```bash
# Disassemble
neo-sym decode contract.nef

# Symbolic exploration without detectors
neo-sym explore contract.nef

# Full analysis
neo-sym analyze contract.nef \
  --manifest contract.manifest.json \
  --source ./src \
  --format markdown \
  --out report.md

# With SMT path validation (external z3 when available, portable fallback otherwise)
neo-sym analyze contract.nef --manifest contract.manifest.json --smt --smt-drop-unsat

# Formal verification from a property spec
neo-sym verify contract.nef \
  --manifest contract.manifest.json \
  --spec contract.neo-sym.json \
  --require-external-smt \
  --format json \
  --out verify.json

# Built-in Neo N3 security proof profile
neo-sym verify contract.nef \
  --manifest contract.manifest.json \
  --profile neo-n3-security \
  --deploy-sender-hash 00112233445566778899aabbccddeeff00112233 \
  --format markdown \
  --out verify.md

# Emit a reusable proof summary after a dependency NEF verifies cleanly
neo-sym verify dependency.nef \
  --manifest dependency.manifest.json \
  --profile neo-n3-security \
  --deploy-sender-hash 00112233445566778899aabbccddeeff00112233 \
  --emit-dependency-proof-summary dependency.neo-sym.proof.json \
  --format json \
  --out dependency.verify.json

# Consume that dependency proof from a caller after binding the original artifacts
neo-sym verify bridge.nef \
  --manifest bridge.manifest.json \
  --profile neo-n3-security \
  --deploy-sender-hash 00112233445566778899aabbccddeeff00112233 \
  --dependency-proof-summary dependency.neo-sym.proof.json \
  --dependency-proof-artifact 0x1111111111111111111111111111111111111111=dependency.nef,dependency.manifest.json \
  --trust-dependency-proof-summaries \
  --format json \
  --out bridge.verify.json
```

`decode` and `explore` accept exactly one script/NEF path; unexpected trailing arguments fail
with usage output instead of being silently ignored.
`analyze --out`, `verify --out`, and `verify --emit-dependency-proof-summary` reject paths that
would overwrite input artifacts, symlink targets for input artifacts, or the sibling verification
output.

If `z3` is on `PATH`, the SMT layer uses it for full SMT-LIB queries. Without `z3`, it falls
back to a conservative in-process solver that proves scaled single-symbol linear constraints,
bounded two-symbol affine constraints, symbol-offset equalities, repeated opaque integer-expression bounds,
small finite integer intervals fully excluded by `!=` constraints,
OR branches whose every disjunct contradicts the current integer domain,
and concrete byte-pick facts for `first_byte` / `PICKITEM` expressions over concrete or spliced bytes,
plus ordinary integer bounds, then returns `Unknown`
for formulas it cannot prove safely. Integer arithmetic is translated as mathematical SMT `Int`
instead of wrapping bit-vectors; the VM and verifier then enforce NeoVM's 32-byte signed integer
result range as an explicit fault condition.

## Formal verification

`neo-sym verify` turns Neo N3 C# ABI methods into bounded formal proof obligations. It
runs symbolic execution per manifest method, then asks the SMT backend whether a successful
HALT path can satisfy `path_conditions AND no_implicit_vm_faults AND requires AND NOT(ensures)`.
If that query is UNSAT for every successful path, the postcondition is proved; if it is SAT, the
report marks the property `violated` and includes a concrete counterexample; if the solver or
engine cannot decide, the result is `unknown` or `incomplete`. Postconditions are never proved
vacuously: a property with `ensures` must have at least one successful HALT path to check, and at
least one successful HALT path must also be feasible under the full `requires` condition after
implicit VM fault preconditions are excluded, including return-scoped predicates such as
`{ "return": true }`.
Input-targeted `requires` are also checked against ABI method-entry constraints before proof,
so an empty ABI input domain is reported as `incomplete` instead of proving fault freedom
vacuously. Solver `Unknown` never counts as proof of path feasibility; profile obligations that
need a SAT witness, such as token true-return transfer success, become `incomplete` instead.
For NEF inputs, verification reports also include `meta.contract_identity`: the manifest name,
verified NEF checksum, and, when `--deploy-sender-hash` is supplied, the Neo N3 deployed contract
hash computed from the official `ABORT + sender + nef checksum + manifest name` identity script.
`--deploy-sender-hash` is a 20-byte little-endian UInt160 hex string matching manifest permission
descriptors and VM ByteString values. Without it, the report marks the identity as
`sender_required` because Neo N3 contract hashes depend on the deployment sender and cannot be
derived from `.nef + manifest` alone; `neo-n3-security` profile reports for such NEFs include
`security.contract_identity.*` as `incomplete` and fail the default proof gate until the deployed
contract hash is bound. Raw `.bin` scripts have no NEF checksum or deployed contract identity, so
they also receive `security.contract_identity.*` as `incomplete` under `neo-n3-security`; use raw
scripts for exploratory analysis, or verify the compiled `.nef` with `--deploy-sender-hash` for a
proof-grade Neo N3 result.

Minimal spec shape:

```json
{
  "version": 1,
  "properties": [
    {
      "id": "amount_non_negative",
      "description": "Successful transfer paths constrain amount to non-negative.",
      "method": "transfer",
      "requires": [
        { "return": true, "op": "==", "value": true }
      ],
      "ensures": [
        { "arg": "amount", "op": ">=", "value": 0 }
      ]
    }
  ]
}
```

Supported condition operators are `==`, `!=`, `>`, `>=`, `<`, and `<=` over ABI argument
symbols. A condition can target either an ABI parameter (`{ "arg": "amount", ... }`), an ABI
ByteString length metric (`{ "arg": "key", "metric": "size", "op": "<=", "value": 64 }`),
a first-byte metric (`{ "arg": "method", "metric": "first_byte", "op": "!=", "value": 95 }`),
an exact ByteString-like value (`{ "arg": "to", "op": "!=", "value": "0x0000000000000000000000000000000000000000" }`),
a storage-read byte metric (`{ "storage_read": 42, "metric": "size", "op": "<=", "value": 32 }`),
a storage-write value invariant (`{ "storage_put": 64, "op": ">=", "value": 0 }`),
an emitted-notification count (`{ "notification": "Transfer", "metric": "count", "op": ">=", "value": 1 }`),
a concrete notification payload field (`{ "notification_arg": "Transfer", "index": 2, "op": "==", "value_arg": "amount" }`),
an external-call count (`{ "external_call": "onNEP17Payment", "metric": "count", "op": ">=", "value": 1 }`),
an external-call count scoped to a callee (`{ "external_call": "transfer", "external_call_contract": "gas", "metric": "count", "op": "==", "value": 1 }`),
an external-call target binding (`{ "external_call_target": "onNEP17Payment", "op": "==", "value_arg": "to" }`),
an external-call payload argument (`{ "external_call_arg": "onNEP17Payment", "index": 1, "op": "==", "value_arg": "amount" }`),
an external-call ordering predicate (`{ "external_call_after_notification": "onNEP17Payment", "notification_before": "Transfer", "op": "==", "value": true }`),
a proof-grade enforced witness count (`{ "witness": "owner", "metric": "enforced_count", "op": ">=", "value": 1 }`),
a proof-grade direct-caller authorization count (`{ "caller_hash": "owner", "metric": "enforced_count", "op": ">=", "value": 1 }`),
a proof-grade enforced `CheckSig` / `CheckMultisig` count (`{ "signature_check": "pubkey", "metric": "enforced_count", "op": ">=", "value": 1 }`),
the method return value (`{ "return": true, ... }`), a ByteString-like return metric
(`{ "return": true, "metric": "size", "op": "==", "value": 20 }`), or a closed
`Array` / `Struct` / `Map` return count metric
(`{ "return": true, "metric": "count", "op": ">=", "value": 1 }`). Return-targeted Boolean
conditions are bound to the HALT state's top stack item using NeoVM truthiness, so specs can
state "only paths that return true are successful."
Before evaluating return-targeted predicates, non-return `requires` clauses filter HALT paths;
for example, an `amount >= 0` precondition can exclude a negative-amount path that returns a
different runtime StackItem type, while any remaining feasible return path must still satisfy
the ABI-compatible `$return` condition.
Exact ByteString-like spec values use the same byte-sequence equality model as symbolic VM
`EQUAL` path conditions, so `requires` clauses over concrete byte values can exclude or select
paths guarded by contract-level byte comparisons.
Condition right-hand sides can be either a literal `value` or another ABI parameter through
`value_arg`, for example `{ "return": true, "op": "==", "value_arg": "owner" }` for a
ByteString-like return and `{ "storage_put": 64, "op": "==", "value_arg": "amount" }` for a
storage write that must persist the ABI input. `value_arg` comparisons are type checked:
Integer-to-Integer comparisons support all numeric operators, Boolean-to-Boolean comparisons
support only `==` / `!=`, ByteString-like exact byte equality supports only `==` / `!=`, and
metric targets such as `size`, `first_byte`, `count`, or `enforced_count` must compare to an
Integer `value_arg`.
`storage_read` conditions must reference a `Storage.Get` / `Storage.Local.Get` offset that every
terminal path actually executed; unobserved storage-read offsets or ambiguous repeated reads at
the same offset are reported as `incomplete` instead of creating unconstrained synthetic storage
values.
`storage_put` conditions are postconditions for `ensures` and must reference a
`Storage.Put` / `Storage.Local.Put` offset that every successful HALT path satisfying
`requires` actually executed; unobserved write offsets or ambiguous repeated writes are reported
as `incomplete` instead of proving a synthetic storage write. This lets custom specs prove
storage-write invariants such as non-negative balances, owner slot shape, or bounded persisted
byte values.
`notification` count conditions are postconditions for `ensures` and prove that every successful
HALT path satisfying `requires` emits the expected concrete event count. They support exact,
minimum, maximum, and absence checks through ordinary integer operators; if a path emits a
`Runtime.Notify` with a dynamic or unknown event name, the property is reported as `incomplete`
instead of proving or disproving a concrete event count unsoundly.
`notification_arg` conditions are postconditions for `ensures` and prove that a unique concrete
`Runtime.Notify` event payload field is bound to a literal or ABI input. They support
Integer-to-Integer, Boolean-to-Boolean, ByteString-like exact byte equality, and ByteString-like
`size` / `first_byte` metrics. A missing event or missing payload index violates the condition;
dynamic event names, repeated matching events, or open symbolic payload arrays are reported as
`incomplete` instead of guessing which event argument the spec meant.
`notification`, `notification_arg`, and `external_call_after_notification` can add
`"notification_emitter": "current"`, `"gas"`, `"neo"`, or a 20-byte `0x...` / `hex:...`
script hash, with `"notification_script_hash"` accepted as an exact-hash alias. This scopes
same-name events such as native GAS/NEO `Transfer` notifications versus a user contract's own
`Transfer` event.
`external_call` count conditions are also postconditions for `ensures` and count successful-path
non-inlined `Contract.Call`, NEF `CALLT`, and `Runtime.LoadScript` telemetry by concrete method
selector. They can prove required callbacks, forbidden integration calls, or exact call counts
from the caller's execution trace. If a path contains a dynamic or unknown external-call method
selector, the condition is reported as `incomplete` instead of proving absence or exact counts
unsoundly. Occurrence-only properties that do not intend to prove external callee existence, ABI,
or implementation semantics can set `"require_external_call_completeness": false`; leaving it at
the default keeps fault-freedom and postcondition proofs conservative around unmodeled external
contracts.
`external_call`, `external_call_target`, `external_call_arg`, and
`external_call_after_notification` can add `"external_call_contract": "current"`, `"gas"`,
`"neo"`, or a 20-byte `0x...` / `hex:...` script hash, with
`"external_call_script_hash"` accepted as an exact-hash alias. This scopes same-method calls
across different callees, so a native GAS/NEO `transfer` does not satisfy a user-token
`transfer` obligation unless the spec explicitly targets that native contract. If a path has a
matching method and a dynamic or unresolved target that could equal the requested callee, the
condition is reported as `incomplete` instead of under-counting it.
`external_call_target` and `external_call_arg` conditions are postconditions for `ensures` and
prove external call targets and payload arguments are bound to literals or ABI inputs. This is
intended for callback-shape properties such as proving an NEP-17 transfer calls
`onNEP17Payment` on the `to` contract with `(from, amount, data)`-equivalent payload fields.
Target comparisons require ByteString-like values unless a byte metric such as `size` or
`first_byte` is used; argument comparisons support Integer-to-Integer, Boolean-to-Boolean,
ByteString-like equality, and ByteString metrics. A missing call or missing argument index
violates the condition; dynamic method selectors or repeated matching external calls are
reported as `incomplete` instead of guessing which invocation the spec meant.
`external_call_after_notification` conditions are postconditions for `ensures` and prove callback
ordering relative to emitted events. They require `notification_before`, a Boolean `value`, and
no metric; a true condition means at least one matching external call exists and every matching
external call is preceded on that path by the named concrete notification. Add
`notification_emitter` when the ordering must be relative to the current contract's event rather
than a same-name native NEO/GAS event. This lets custom specs prove ordering obligations such as
"emit `Transfer` before `onNEP17Payment`." Missing calls, missing prior notifications, dynamic
method selectors, or dynamic event names are handled conservatively as violations or `incomplete`
rather than proof.
`witness` enforced-count conditions can be used as state-scoped `requires` or as postconditions
for `ensures`, and count only `Runtime.CheckWitness` results that were consumed by an `ASSERT`
or a branch on the successful path. Calling `CheckWitness` and dropping the result does not
satisfy the condition. This lets custom specs scope proofs to paths where a Neo witness
authorization has already been enforced. The `witness` target may name a `Hash160`, `UInt160`,
`PublicKey`, `ByteString`, or `ByteArray` ABI parameter, or a `0x...` / `hex:...` constant hash
or public key; ABI values such as `Hash256` or `Signature` are rejected as witness targets.
`caller_hash` enforced-count conditions can be used as state-scoped `requires` or as
postconditions for `ensures`, and count only `Runtime.GetCallingScriptHash() == target` checks
consumed by `ASSERT` or a branch on the successful path. Reading the caller hash and dropping it
does not satisfy the condition. This lets custom specs scope fault-freedom, side-effect, and
return proofs to paths where a direct-caller authorization has already been enforced. The
`caller_hash` target may name a `Hash160`, `UInt160`, `ByteString`, or `ByteArray` ABI
parameter such as `owner` / `from`, or a `0x...` / `hex:...` constant UInt160 hash; `Hash256`,
`PublicKey`, and `Signature` ABI parameters are rejected as caller-hash targets.
`signature_check` enforced-count conditions can be used as state-scoped `requires` or as
postconditions for `ensures`, and count only `System.Crypto.CheckSig` /
`System.Crypto.CheckMultisig`, `CryptoLib.verifyWithECDsa`, or `CryptoLib.verifyWithEd25519`
results consumed by `ASSERT` or a branch on the successful path.
Calling `CheckSig` / `CheckMultisig` / CryptoLib verification and dropping the result does not satisfy the condition. This
lets custom specs scope proofs to paths where a signature or multisignature authorization has
already been enforced. The `signature_check` target may name a `PublicKey`, `ByteString`, or
`ByteArray` ABI parameter, or a `0x...` / `hex:...` constant valid ECPoint public key or
32-byte Ed25519 public key. Constant
public-key targets also match closed `CheckMultisig` public-key arrays only when the closed
signature array proves every listed public key is required; partial multi-signature arrays remain
conservative `incomplete` because array membership alone does not prove which public keys signed.
Open ABI `Array` inputs are also reported as dynamic `CheckMultisig` public-key lists that cannot
be exhaustively modeled at method entry.
Custom specs can also declare side-effect postconditions with
`"forbid_storage_mutation": true`, `"forbid_external_calls": true`, and
`"forbid_notifications": true`; these properties may use an empty `ensures` array when the
only obligation is "successful paths satisfying `requires` must be read-only / no-call /
no-notify." Verification checks successful HALT path reachability under `requires`; reachable
`Storage.Put` / `Storage.Delete`, remaining non-inlined `Contract.Call` / NEF `CALLT` /
`Runtime.LoadScript`, or `Runtime.Notify` events are reported as concrete violations, while
UNSAT paths are excluded and solver UNKNOWN is not counted as proof. Same-contract calls already
inlined by the verifier are treated as internal execution rather than forbidden external calls.
Known native write calls whose storage/notification semantics are not expanded end to end, such
as ContractManagement lifecycle calls, Oracle.request, and native NEO/GAS `transfer` balance
updates, are also treated as reachable native storage mutation and native notification effects
for these custom side-effect properties.
Argument conditions are ABI type checked: `Integer` parameters accept integer comparisons,
`Boolean` parameters accept only `==` / `!=` boolean comparisons, and ByteString-like
parameters such as `ByteString`, `ByteArray`, `String`, `Hash160`, `Hash256`, `PublicKey`, and `Signature`
may use a metric such as `size` or `first_byte` for integer comparisons, or exact
`0x...` / `hex:...` byte constants with `==` / `!=`. Exact byte comparison is modeled as
both byte length and byte content equality, which lets specs prove fixed `Hash160` /
`Hash256` values such as zero addresses, owner accounts, and known script hashes.
Custom specs must name a unique ABI method, or include `parameter_types` / `method_offset` to
select a specific manifest ABI entrypoint when C# overloads or display-name attributes produce
same-named methods with different parameter counts. Same-named methods with the same parameter
count are rejected as malformed because Neo N3 dispatches `Contract.Call` by method name and
parameter count, not by ABI parameter type. Manifests with multiple matching methods are reported
as `incomplete` instead of silently proving only the first entry. Methods with duplicate ABI
parameter names are also reported as `incomplete`, because name-based specifications cannot bind
ambiguous arguments soundly.
Argument conditions must use manifest ABI parameter names, not internal `arg_*` symbol names;
unknown or misspelled parameters make the property `incomplete`.
Return-targeted conditions require a non-`Void` manifest return type; a stray value left on the
NeoVM stack by a `Void` method is not treated as a proof-grade method return value.
Return-targeted conditions are currently proof-grade for manifest `Boolean`, `Integer`,
ByteString-like returns with metrics or exact byte-string values, and closed `Array` /
`Struct` / `Map` returns with `count` metrics. The JSON `value` kind must match the manifest return type;
for example, a `Boolean` return must compare against `true`/`false`, not an integer condition,
and `Hash160` / `Hash256` / `String` / `ByteString` returns must use a metric such as `size`
or `first_byte` for integer comparisons, or a byte-string value for `==` / `!=`.
For manifest `Integer` returns, successful HALT paths must also return an Integer StackItem;
Boolean, ByteString, or unknown runtime return values are reported as incomplete instead of being
coerced into numeric proof conditions.
For ByteString-like return metrics and byte-string values, successful HALT paths must return a ByteString StackItem;
runtime Integer, Boolean, compound, or unknown values are reported as incomplete instead of being
coerced into byte-shape proof conditions.
For `Array` / `Struct` / `Map` return count metrics, successful HALT paths must return a
closed heap-backed collection; open collection returns are reported as `incomplete` instead of
pretending an unknown runtime collection length is proof-grade.

Set `"forbid_faults": true` on a property to prove fault freedom under the declared `requires`
conditions. For each faulted path, verification checks `path_conditions AND requires`; SAT is
a concrete reachable VM fault, UNSAT means the precondition excludes that rejection path, and
UNKNOWN fails the default gate. A fault-freedom property may use an empty `ensures` array when
the only obligation is "inputs satisfying requires must not FAULT." Return-scoped `requires`
are evaluated only on successful HALT paths; faulted paths have no method return value, so
residual stack items cannot hide reachable VM faults. Fault and arithmetic-definedness
obligations are checked against the path-condition snapshot captured at the instruction that
recorded the obligation, so later `ASSERT` statements or branch refinements cannot retroactively
prove an earlier `PICKITEM`, native precondition, or arithmetic operation fault-free.
Fault-freedom also discharges implicit
definedness obligations recorded by the engine, such as proving a symbolic `DIV`/`MOD`
divisor cannot be zero under `requires`, symbolic arithmetic results stay inside NeoVM's 32-byte
signed integer range, symbolic `SQRT` inputs are non-negative,
symbolic ByteString/Buffer inputs consumed by NeoVM `GetInteger` receive at most NeoVM's 32-byte
integer input limit, including direct numeric opcodes, explicit ByteString-to-Integer
conversions, and storage-backed conversions when a `storage_read` size precondition declares
the storage integer encoding invariant; Array, Struct, Map, Pointer, and InteropInterface
operands are modeled as numeric-conversion VM faults,
symbolic ByteString/ByteArray `PICKITEM` indices stay within `0 <= index < size(value)` with
`HASKEY` modeled as that same bounds predicate,
open ABI `Array` and `Struct` `PICKITEM` reads prove `0 <= index < array_size` or
`0 <= index < struct_size`, with `HASKEY` modeled as the same open-sequence bounds predicate,
open ABI `Array` and `Struct` symbolic `SETITEM` writes update seeded same-sort prefixes with
finite ITE expressions, record write overlays for subsequent same-key reads, and prove the
selected index is within runtime length,
open ABI `Array` and `Struct` symbolic `REMOVE` operations shift seeded same-sort prefixes with
finite ITE expressions, fill the exposed prefix tail from an unknown runtime item, and prove the
removed index is within runtime length,
closed `Array` and `Struct` symbolic `PICKITEM` reads use finite same-sort ITE values while
proving `0 <= index < Count`, with `HASKEY` modeled as that same closed-sequence predicate,
closed `Array` and `Struct` symbolic `SETITEM` writes over same-sort slots update each slot with
finite ITE expressions while proving `0 <= index < Count`,
closed `Array` and `Struct` symbolic `REMOVE` operations over same-sort slots shrink the list
with finite ITE expressions while proving `0 <= index < Count`,
symbolic `Buffer` `PICKITEM` reads prove `0 <= index < buffer.Length`, with `HASKEY` modeled
as the same fixed-buffer bounds predicate,
symbolic `Buffer` `SETITEM` writes update each cell with finite ITE expressions while proving
`0 <= index < buffer.Length`,
closed `Map` symbolic `PICKITEM` reads over same-sort known entries use finite ITE values while
proving the selected key exists, with `HASKEY` modeled as that same known-key predicate,
concrete closed/open `Map` key lookup uses NeoVM StackItem equality so Boolean keys do not alias
Integer or ByteString keys with the same numeric encoding,
closed `Map` symbolic `SETITEM` writes under a proven known-key guard update same-sort values
with finite ITE expressions while preserving existing key identity,
closed `Map` symbolic `REMOVE` operations under a proven known-key guard shrink same-sort known
entries with finite ITE expressions while preserving Map no-op behavior outside that guard as
incomplete proof surface,
unknown open ABI `Map` `PICKITEM` reads prove the selected key exists, with `HASKEY` modeled
as the same open-map presence predicate, and dynamic expression keys receive distinct stable lookup symbols,
open ABI `Map` symbolic `SETITEM` writes record key/value overlays so same-key `PICKITEM`
returns the written value and same-key `HASKEY` is provably true,
open ABI `Map` symbolic `REMOVE` operations record ordered remove overlays so same-key
`HASKEY` is provably false and removes override prior same-key writes,
symbolic ByteString `SUBSTR`, `LEFT`, and `RIGHT` sources with concrete or symbolic slice
parameters return symbolic byte expressions while proving the requested range is within
`size(source)`; fixed-length splice results discharge ABI fixed-byte return and notification
argument proofs such as `Hash160`, and symbolic splice expressions can be sliced or copied again
without collapsing into unsupported VM surface,
symbolic ByteString `MEMCPY` sources with concrete or symbolic source/destination indexes and
concrete or symbolic copy counts update finite destination `Buffer` cells with byte-pick/ITE
expressions while proving source and destination ranges are in bounds,
symbolic `POW` exponents and `SHL`/`SHR` shift counts stay within NeoVM's configured 0..256 range,
concrete-base symbolic `POW` and `SHL` result overflows are checked across that finite range,
successful `MODMUL`/`MODPOW` returns carry NeoVM integer range facts,
symbolic `MODMUL`/`MODPOW` moduli are non-zero, and symbolic `MODPOW` exponents stay within
NeoVM's configured -1..256 range. `MODPOW` modular-inverse (`exp == -1`) paths use a positive base and modulus at least 2.
`Runtime.BurnGas` receives a positive gas amount, `Contract.Call` receives a 20-byte
UInt160 target hash, `Contract.Call` receives a method name that does not start with `_`,
symbolic method selectors remain fault obligations until the proof excludes the private-method
`_` prefix, and `Contract.Call` receives valid Neo call flags in the `0..0x0F` range.
The current execution context must also have the Neo-required call flags before invoking
restricted syscalls, such as `WriteStates` for storage writes, `AllowNotify` for notifications,
and `ReadStates | AllowCall` for `Contract.Call` / `CALLT`.
`Runtime.CheckWitness` receives either a 20-byte UInt160 hash or a valid 33-byte compressed
secp256r1 public key; constraining an arbitrary `ByteString` to 33 bytes is not enough to prove
that ECPoint decoding cannot fault. Manifest `PublicKey` ABI entry parameters carry
ECPoint-validity facts at method entry.
`Runtime.GetCallingScriptHash`, `Runtime.GetExecutingScriptHash`, and `Runtime.GetEntryScriptHash`
are stable within an invocation; `CallingScriptHash` covers both Neo's entry-context `null`
result and a contract-caller branch with a stable 20-byte UInt160 hash, while the non-null
runtime script hashes carry their UInt160 length facts for witness checks and self-call proofs.
`Runtime.GetTrigger` uses `Application` by default, and a manifest ABI method named `verify`
runs under the `Verification` trigger instead of the application trigger. `Runtime.GetTime`
faults under that verification-trigger context because Neo only exposes the current block
timestamp through an Application-trigger persisting block.
`Contract.Call` self-calls to the current executing script hash and same-contract NEF `CALLT`
MethodToken calls must resolve to a manifest ABI method with matching arity and argument types.
The manifest parser rejects duplicate same-name/same-arity ABI methods up front, matching Neo N3's
name-plus-parameter-count dispatch key.
When the target hash is the stable current executing hash or the MethodToken hash equals the
current script hash, the method selector and call flags are concrete, the argument list is closed,
and the manifest resolves a unique same-arity ABI target, the verifier executes the self-call
callee body with nested caller/executing script-hash context and includes nested faults, state
changes, and return-stack results in the caller proof. `Contract.Call` pushes a result value
(`null` for manifest `Void` callees), while NEF `CALLT` follows the MethodToken `HasReturnValue`
stack effect and dependency summaries for return-valued CALLT calls must prove a non-Void callee
return shape. Dynamic method selectors or target hashes, open argument arrays, ambiguous or
missing ABI targets, and excessive self-call depth remain `incomplete`. Custom `requires`
predicates scope self-call ABI, callee-execution completeness, and
`Runtime.Notify` manifest checks, so paths excluded by the specification do not cause false
violations while solver-unknown reachability remains unproved.
External `Contract.Call` and external NEF `CALLT` targets that are not modeled native contract methods
make custom properties `incomplete`, even when `manifest.permissions` covers the dispatch, unless
a dependency proof summary is supplied with `--dependency-proof-summary` and explicitly trusted
with `--trust-dependency-proof-summaries`. The trusted summary must cover the concrete target hash,
method name, parameter count,
declared parameter ABI types, caller argument compatibility, ABI `return_type` compatibility,
effective call flags, and `fault_free: true` callee proof. If an external return is consumed by
an `ASSERT`, branch, Boolean comparison, or type-sensitive `EQUAL` / `NOTEQUAL` path condition,
the dependency summary return type must match the caller-inferred return expectation, not merely
declare any non-`Void` return. Dependency proof argument compatibility follows ABI entry runtime
types strictly: an `Array` parameter proof does not cover a caller that passes a `Struct`, and a
`Struct` parameter proof does not cover a caller that passes an `Array`. When a
`Contract.Call` result slot is not consumed, a dependency summary with `return_type: "Void"` can
cover the callee ABI shape. External target hashes can be concrete byte literals or path-constrained
symbols, for example after `ASSERT(to == knownReceiverHash)`. If the current run uses `--require-external-smt`, consumed
dependency summaries must also have been generated with `--require-external-smt`. The v3 summary
format emitted by
`--emit-dependency-proof-summary` is:

```json
{
  "version": 3,
  "contracts": [
    {
      "hash": "0x1111111111111111111111111111111111111111",
      "proof": {
        "tool": "Neo.SymbolicExecutor.Verify",
        "tool_version": "0.8.0",
        "source_profile": "neo-n3-security",
        "gate_passed": true,
        "require_external_smt": false,
        "require_unqualified_proofs": true,
        "assumption_backed_proofs": 0,
        "program_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "manifest_sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "contract_hash": "0x1111111111111111111111111111111111111111",
        "deploy_sender_hash": "0102030405060708090a0b0c0d0e0f1011121314",
        "nef_checksum_hex": "0x00000000",
        "smt_solver_version": "z3 4.15.0"
      },
      "methods": [
        {
          "name": "balanceOf",
          "parameter_count": 1,
          "parameters": [
            { "name": "account", "type": "Hash160" }
          ],
          "return_type": "Integer",
          "initial_call_flags": 15,
          "initial_runtime_trigger": 64,
          "fault_free": true
        }
      ]
    }
  ]
}
```

Only concrete 20-byte target hashes and concrete method selectors can be discharged this way;
dynamic targets/selectors and dynamic or mismatched call flags or runtime triggers remain incomplete. Summaries are
strict-schema proof artifacts and external trust roots. The CLI and public `DependencyProofSummarySet` construction default to untrusted summaries; SDK callers must
explicitly set `TrustedForExternalCalls` only after binding or otherwise reviewing the underlying
callee artifacts. When summaries are consumed, repeat
`--dependency-proof-artifact <hash=program,manifest>` once for every summary contract. The
consumer verifies the bound NEF and manifest against `program_sha256` and `manifest_sha256`,
checks the NEF checksum against `nef_checksum_hex`, and recomputes the Neo N3 contract hash from
the bound artifacts and `deploy_sender_hash`; missing bindings, duplicate bindings, and unused
dependency proof artifact bindings fail closed so a mistyped contract hash is not silently
ignored; the CLI exits with the verification gate failure code and records the reason in
`security.dependency_proof.input`. `--allow-unbound-dependency-proof-summaries` is an explicit legacy/offline escape hatch
for pre-checked summaries and should not be used for proof-grade CI; any proof result closed this
way carries the `unbound_dependency_proof_summary` assumption and fails the default
`--require-unqualified-proofs` gate unless `--allow-assumption-backed-proofs` is selected. Reports produced with that
escape hatch cannot be repackaged as reusable dependency proof summaries. Without
`--trust-dependency-proof-summaries`, imported summaries are still parsed and listed in
`meta.inputs.dependency_proof_summaries`, but they do not close external-call proof obligations:
legacy v1/v2 summaries, unknown fields, mismatched `proof.contract_hash`, invalid
`program_sha256` / `manifest_sha256` / `nef_checksum_hex` bindings, failed gates, disabled
unqualified-proof policy, missing typed parameters for non-zero-arity methods, missing or invalid
`initial_call_flags`, missing or invalid `initial_runtime_trigger`, `require_external_smt` claims
without a real external solver version, and non-zero `assumption_backed_proofs` are rejected
instead of ignored.
Emission also binds the requested summary contract hash to the verification report's
`contract_identity.contract_hash`; a passed report cannot be re-packaged as proof for a different
contract hash through the library API.
Summary parameter and return ABI
types are validated against the supported Neo ABI vocabulary on both read and emission paths
(`Void` is valid only for returns), so misspelled or fabricated types fail closed. Emitted
summaries are generated only from unqualified `neo-n3-security` built-in
`security.vm_surface.<method>`, `security.vm_fault_free.<method>`, and
`security.abi_return_type.<method>` profile results; a custom verification spec with matching
`security.*.<method>` ids is not trusted for summary generation. A summary with a
missing method, mismatched arity, caller argument incompatible with the declared parameter ABI
types, mismatched ABI `return_type`, mismatched effective call flags, duplicate contract hash,
duplicate method selector, or `fault_free: false` does not close the proof gap.
Custom properties may set `"require_external_call_completeness": false` to limit verification to
local NeoVM/syscall fault obligations and explicit postconditions; that mode is useful for
precondition-shape checks but is not a proof of dynamic self-call or external callee semantics.
Native StdLib `serialize`/`deserialize` calls through `Contract.Call` or NEF `CALLT` with
concrete single-argument stack items use the same BinarySerializer model as iterator
`DeserializeValues`. Closed symbolic primitive, Buffer, Array, Struct, and Map StackItems
are summarized for `serialize`/`deserialize` round-trips, and symbolic byte lengths emit
NeoVM item-size fault conditions instead of being silently assumed safe. Iterator
`DeserializeValues`/`PickField0`/`PickField1` consume the same symbolic BinarySerializer
summaries when path-local storage values come from `StdLib.serialize`. Native StdLib
`jsonSerialize`/`jsonDeserialize` calls cover concrete Null, Boolean, Integer, strict-UTF8
ByteString/Buffer, closed Array/Struct, and strict-UTF8 string-key Map shapes. Closed symbolic
Null, Boolean, Integer, strict-UTF8 ByteString, Array/Struct-as-Array, and concrete-string-key
Map shapes are summarized for `jsonSerialize`/`jsonDeserialize` round-trips; symbolic string
values emit strict-UTF8 and JSON output-size fault conditions. Unsupported symbolic values,
invalid UTF-8 bytes, malformed JSON, or unsupported shapes remain conservative incomplete surface.
Native StdLib `itoa`/`atoi`, `strLen`, `stringSplit`, base64/base64Url, base58/base58Check,
hex encode/decode, `memoryCompare`, and `memorySearch` calls are modeled for concrete arguments that satisfy
Neo's supported bases, checksums, search bounds, strict UTF-8 string requirements, and input limits.
Concrete invalid decode text for base64/base64Url, base58/base58Check, and hex decode methods is
reported as a reachable VM fault. Concrete invalid `atoi` text and unsupported concrete
`itoa`/`atoi` bases are also reported as reachable VM faults, as are concrete invalid strict-UTF8
strings, concrete `atoi` results outside NeoVM's integer range, out-of-bounds `memorySearch`
starts, and concrete StdLib inputs over 1024 bytes; symbolic inputs and checksum-failing symbolic
inputs remain incomplete rather than being treated as proof.
Native CryptoLib `sha256`, `ripemd160`, `keccak256`, and `murmur32` calls are modeled for
concrete ByteString arguments through both `Contract.Call` and NEF `CALLT`, and symbolic
ByteString inputs produce stable fixed-length digest expressions (`sha256`/`keccak256` 32 bytes,
`ripemd160` 20 bytes, `murmur32` 4 bytes with a concrete uint32 seed). `verifyWithEd25519`
is modeled for concrete message/public-key/signature arguments and symbolic ByteString
message/public-key/signature inputs that satisfy Neo's Ed25519 32-byte public-key and
64-byte signature requirements, returning a stable `signature_check` authorization result
for symbolic verification paths. `verifyWithECDsa` is modeled for concrete
message/public-key/signature/curve-hash arguments using Neo's secp256k1SHA256,
secp256r1SHA256, secp256k1Keccak256, and secp256r1Keccak256 `NamedCurveHash` values; symbolic
ByteString message, PublicKey, and Signature inputs with a concrete supported curve hash return
a stable `signature_check` authorization result that can be consumed by `ASSERT`, branch guards,
custom specs, the Neo N3 security profile, `Contract.Call`, and NEF `CALLT`. Concrete invalid
`murmur32` seeds and unsupported ECDSA curve hashes are reported as reachable VM faults instead
of unknown native-call surface.
`recoverSecp256K1` is modeled for concrete 32-byte message hashes and 65-byte signatures
whose recovery id is encoded as 0..3 or 27..30, or EIP-2098 64-byte signatures, returning
either the recovered compressed public key or concrete null. Symbolic ByteString recovery inputs
that satisfy the 32-byte message-hash and 64/65-byte signature shape are modeled through
both `Contract.Call` and NEF `CALLT` as a nullable result: non-null paths return a proof-grade
33-byte compressed secp256k1 public key, while null recovery paths remain visible to `ISNULL`,
branch, and `ASSERT` guards.
Concrete BLS12-381 `deserialize`, `serialize`, `equal`, `add`, `mul`, and `pairing` calls are
modeled for Neo's G1/G2/Gt interop values. Concrete `deserialize` rejects lengths other than
48-byte G1, 96-byte G2, or 576-byte Gt, and invalid encodings are reported as reachable VM
faults instead of unknown native-call surface. Concrete `bls12381Mul` rejects scalar lengths other
than 32 bytes, and invalid scalar encodings are reported as reachable VM faults instead of
unknown native-call surface. Symbolic BLS12-381 `deserialize` preserves a guarded
ByteString payload as a BLS interop value, records valid compressed G1/G2/Gt encoding fault obligations so
`security.vm_fault_free` cannot be proved from byte length alone, and `serialize` returns that same symbolic payload so
custom specs can prove G1/G2/Gt byte-size round trips after a `SIZE`/`ASSERT` guard. Symbolic
`bls12381Equal` preserves a symbolic equality predicate for guarded same-kind operands instead of
collapsing unrelated symbolic points to `true`. Symbolic `bls12381Add` also preserves the guarded same-kind G1/G2/Gt shape, so serialized add results retain
the corresponding 48/96/576-byte proof shape. Symbolic `bls12381Mul` preserves the guarded G1/G2/Gt
shape when the scalar is proved to be a 32-byte ByteString, records a valid BLS12-381 scalar
fault obligation, and the negative flag is concrete.
Symbolic `bls12381Pairing` preserves the guarded G1-by-G2-to-Gt shape, so serialized pairing
results retain a 576-byte proof shape. Invalid Ed25519/ECDSA/recovery shapes or unsupported future CryptoLib methods remain
incomplete until a method-specific model proves their Neo N3 semantics; symbolic BLS inputs require concrete validity facts or trusted preconditions before fault-free proofs discharge.
Native NEO/GAS read-only token calls are modeled for `symbol`, `decimals`, `totalSupply`,
`balanceOf`, and NEO `getGasPerBlock()` / `unclaimedGas(account,end)` / `getRegisterPrice()` / `getCandidateVote(pubkey)` / `getCandidates()` / `getAccountState(account)` / `getCommitteeAddress()` / `getCommittee()` / `getNextBlockValidators()`: NEO metadata and total supply are concrete,
GAS metadata is concrete, and state-backed GAS supply, NEO/GAS balances, NEO account-state balance/height/last-gas-per-vote fields, plus NEO gas-per-block and register-price configuration
are stable non-negative symbolic integers, while `unclaimedGas(account,end)` enforces `end == Ledger.currentIndex + 1` and returns stable non-negative symbolic GAS, `getCandidateVote(pubkey)` enforces a valid ECPoint public key and returns a stable integer in `[-1, +inf)` to preserve Neo's missing-candidate sentinel, `getCandidates()` returns open candidate tuples with valid ECPoint keys and non-negative votes, `getAccountState(account)` returns null or Neo's four-field NeoAccountState struct whose `VoteTo` field is null or a valid ECPoint and whose `LastGasPerVote` field is non-negative, the committee address is a stable UInt160 witness principal, and `getCommittee()` / `getNextBlockValidators()` return open arrays with representative valid ECPoint public keys. UInt160 account preconditions apply where applicable, and stable native read keys include a structural expression fingerprint for symbolic arguments so derived accounts, targets, and public keys do not alias unrelated chain-state symbols. These native token read models require effective `ReadStates`
call flags through both `Contract.Call` and NEF `CALLT`; missing flags are faulted and dynamic
flags are treated as incomplete rather than proved. NEO/GAS `transfer(from,to,amount,data)` is modeled as a sensitive write-capable native call requiring `CallFlags.All`; it enforces UInt160 sender/recipient arguments and a non-negative NeoVM integer amount within the 32-byte input limit, forks symbolic success/failure return paths, emits a proof-visible `Transfer(from,to,amount)` notification payload under the native token script hash only on success paths, returns a symbolic Boolean success value, and still participates in access-control, manifest-permission, and external-return checks. Because native balance changes and receiver callback side effects are not yet modeled end to end, `neo-n3-security` marks native NEO/GAS `transfer` paths as incomplete VM surface. Ledger `currentIndex`, `currentHash`,
`getBlockHash(index)`, `getBlock(hash/index)`, `getTransactionFromBlock(block,index)`, `getTransaction(hash)`, `getTransactionHeight(hash)`, `getTransactionSigners(hash)`, and `getTransactionVMState(hash)` read models return stable UInt32 heights,
32-byte hash values, nullable block structs with Hash256 links, non-negative timestamp/index fields, Int32-bounded transaction counts, UInt160 next-consensus hashes, native UInt32 block-index and Int32 transaction-index preconditions, nullable transaction structs from either transaction hashes or block/index lookups with UInt160 senders, non-negative fees, bounded scripts, stable transaction heights in `[-1, currentIndex]`, nullable open signer arrays with UInt160 accounts and bounded witness scopes, and stable VMState enum values
with UInt256 hash preconditions. ContractManagement
`getMinimumDeploymentFee()` returns a stable non-negative chain-configuration integer;
`hasMethod` returns a stable boolean query result with UInt160, strict UTF-8 method-name, and
non-negative Int32 parameter-count preconditions, and returns false when path-local existence
facts prove the target contract is missing; true `hasMethod(target,...)` results make same-path
`isContract(target)` and `getContract(target)` existence checks provable; `getContract` and `getContractById(id)` return forked
nullable contract interop results through both `Contract.Call` and NEF `CALLT` after proving the id fits Neo's native Int32 conversion, and
non-null `getContract(target)` results make same-path `isContract(target)` checks provably true;
prior true/false `isContract(target)` facts make same-path `getContract(target)` return
non-null/null consistently;
`isContract` returns forked stable true/false results with path-local existence facts for the
target UInt160; `getContractHashes()` returns a modeled `StorageIterator` with
`FindOptions.RemovePrefix`, so `Iterator.Next` / `Iterator.Value` proofs see key/value pair
results rather than opaque native surface. ContractManagement `deploy(nef,manifest,data)` returns a contract
interop result with required `CallFlags.All`, non-null NEF/manifest payload checks,
strict-UTF8 manifest validation, and non-Void MethodToken stack behavior. ContractManagement
`update(nef,manifest,data)` and `destroy()` lifecycle calls are recognized as sensitive
write-capable native calls with required flags, payload-shape checks, and Void MethodToken stack
behavior, while remaining external-call obligations keep deploy/upgrade/destroy authorization and
manifest permissions proof-visible. Policy `getFeePerByte`, `getExecFeeFactor`,
`getStoragePrice`, `getAttributeFee(attributeType)`, and Oracle `getPrice` read models return stable non-negative
chain-configuration integers; Policy `getAttributeFee(attributeType)` requires a valid `TransactionAttributeType`;
Policy `isBlocked(account)` returns a stable boolean result after
proving the account argument is UInt160. Oracle
`request(url,filter,callback,userData,gasForResponse)` is modeled as a sensitive no-return native
call with `States|AllowNotify`, URL/filter/callback strict-UTF8 and size preconditions, callback
private-method rejection, serializable userData size checks, and the 10,000,000 datoshi
`gasForResponse` minimum plus Int64 conversion bounds, while remaining authorization and
manifest-permission proof-visible.
RoleManagement `getDesignatedByRole(role, index)` enforces valid Role enum values and native UInt32 index conversion, then returns an open
array with a possible empty path and representative 33-byte valid ECPoint public keys for non-empty
paths, so guarded role-key account and witness checks can be proved. Calls to recognized Neo N3
native contracts, including remaining unmodeled ContractManagement methods, unmodeled Ledger methods,
unmodeled RoleManagement methods, and unmodeled Policy/Oracle methods, outside the modeled method set are marked as incomplete proof surface instead of being
treated as ordinary opaque external returns.
NEF `CALLT` method-token names are parsed as strict UTF-8 and cannot target `_`-prefixed private methods.
`Runtime.Log` messages stay within Neo's 1024-byte notification payload limit, and
`Runtime.Notify` event names stay within Neo's 32-byte event-name limit. `Runtime.Notify` events must be declared in the manifest ABI and must pass the declared number of event arguments.
`Runtime.Log` messages, `Runtime.Notify` event names, and `Contract.Call` method names must be valid strict UTF-8; symbolic ByteString inputs remain fault obligations unless the proof carries an ABI `String` or equivalent UTF-8 fact.
`Runtime.Notify` payloads must serialize within Neo's 1024-byte notification payload limit.
`Runtime.Notify` event arguments must match Neo's manifest ABI type checks, including strict
UTF-8 for `String`, `Struct` compatibility for `Array`, and proof of fixed byte lengths for
`Hash160`, `Hash256`, `PublicKey`, and `Signature` parameters.
`CreateStandardAccount` and `CreateMultisigAccount` receive ECPoint public keys encoded as
valid secp256r1 33-byte compressed or 65-byte uncompressed points. `CreateMultisigAccount` receives valid
`1 <= m <= publicKeys.Count <= 1024` parameters. `CheckSig` receives an ECPoint public key
and 64-byte signature; `CheckMultisig` receives non-empty public-key and signature arrays with
`signatures.Count <= publicKeys.Count`, and each item must satisfy the same public-key/signature
curve and shape checks. `Storage.Find`/`Storage.Local.Find` receive only Neo-supported `FindOptions`
bits and legal flag combinations. `Iterator.Value` is valid only after a successful
`Iterator.Next`; the engine forks true/false iterator-advance paths instead of assuming an
element exists. Once advanced, `Iterator.Value` follows the active `FindOptions`: default
iteration returns a key/value `Struct` pair, while `KeysOnly` and plain `ValuesOnly` return
ByteString items. `DeserializeValues` and `PickField0`/`PickField1` decode concrete path-local values
and closed symbolic `StdLib.serialize` StackItem summaries that use Neo's BinarySerializer for
Null, Boolean, Integer, ByteString, Buffer, Array, Struct, and Map stack items. Unsupported
symbolic values, unknown persisted-storage branches, malformed payloads, or unsupported shapes
remain conservative incomplete surface instead of being treated as proof.
Concrete path-local writes can appear as iterator candidates without suppressing unknown
persisted-storage branches. Storage keys are non-null; `Storage.Put`/`Storage.Local.Put`
keys additionally stay within Neo N3's 64-byte write limit, and Storage values are non-null and stay within
Neo N3's 65535-byte limit. Integer and Boolean storage values use their NeoVM serialized byte
lengths when proving these storage-value limits. Concrete or symbolic unknown
`Storage.Get`/`Storage.Local.Get` reads cover both present byte values and Neo's missing-key
`null` result; present unknown values carry the `0 <= size <= 65535` domain, repeated unknown
reads of the same key are path-stable, path-condition-proved byte-equality key aliases reuse the
same value, numeric-equality branch guards do not alias storage keys, deletes produce path-local tombstones, and arithmetic over `null` operands is modeled as a VM fault. Modular-inverse existence checks prove simple safe cases such as
base `1`, search for reachable non-coprime witnesses, and report remaining symbolic
non-coprime uncertainty conservatively through solver/model incompleteness rather than treating
it as a proved fact.
Storage syscalls that take a context require a proof-grade StorageContext produced by
`Storage.GetContext`, `Storage.GetReadOnlyContext`, or `Storage.AsReadOnly`; null or known
non-storage interop objects are modeled as VM faults, while arbitrary `InteropInterface`
parameters remain incomplete rather than being accepted as writable storage contexts.

Verification defaults to `--fail-on-unproved`, so CI fails on `violated`, `unknown`, or
`incomplete` properties; pass `--allow-unproved` only when collecting exploratory reports.
Verification specs are bounded external inputs: files are capped at 1 MiB, with at most 16
profiles, 256 properties, and 128 conditions per property condition list. Specs also fail
closed on unknown fields, unsupported versions, and wrong-typed scalar fields such as `version`,
`id`, `method`, `arg`, `metric`, or `op`; those inputs produce `FormatException` diagnostics
instead of parser/runtime exceptions or unconstrained proof symbols.
Custom specs targeting unknown ABI types, missing ABI parameters, or `Any`/compound/
`InteropInterface` ABI inputs that require exhaustive input coverage are marked `incomplete`:
`Any` is explored across
representative `Null`, `Boolean`, `Integer`, `ByteString`, `Buffer`, `Array`, `Struct`, `Map`,
and `InteropInterface` entry states, but the verifier does not claim every collection length,
map key set, nested compound object graph, or concrete interop object kind has been enumerated.
For non-standard methods, the built-in `neo-n3-security` profile records the same entrypoint
coverage gap as `security.coverage.<method>` while still running best-effort security obligations
for the method, so deterministic violations are not hidden by the coverage warning. Exact-standard
NEP-17 and NEP-11 `transfer` `data: Any` payloads also report the finite representative-shape
coverage gap as `security.coverage.transfer` while still running the dedicated token-profile
obligations; non-standard overloads still report their own entrypoint coverage gaps.
Manifest-declared `supportedstandards` outside the profile's dedicated proof set (`NEP-17`,
`NEP-11`, `NEP-24`, `NEP-27`, and `NEP-26`) produce
`security.standard_coverage.<standard>` `incomplete` results: generic VM/method obligations still
run, but `neo-n3-security` does not claim proof-grade coverage of that unsupported standard's
semantics.
The detector `analyze` lane also distinguishes full token coverage from ABI-only standard
coverage: `NEP-24`, `NEP-27`, and `NEP-26` emit Info `standard-coverage` / `abi-only`
findings because that lane checks manifest ABI rules only. Proof-grade behavior checks live
in `verify`: NEP-26/NEP-27 receiver callbacks prove the passive no-side-effect receiver
obligation when every feasible successful path is fault-free and avoids storage mutation,
notifications, and external calls; NEP-24 `royaltyInfo` proves its returned royalty-entry
array shape and returned-amount salePrice dependence, and methods that emit concrete
`RoyaltiesTransferred` events prove the observed payload binds to the method inputs
`royaltyToken`, `royaltyRecipient`, `buyer`, `tokenId`, and `amount`. Marketplace payment
ordering, native token transfers, and external `royaltyInfo` call semantics still require custom
specs or future end-to-end payment modeling.
ABI method offsets must point to decoded instruction boundaries; in-range offsets into operand
bytes are stale manifest coverage and remain `incomplete` instead of being proved from a
JIT-decoded entrypoint.
Token balance-delta arithmetic exemptions are likewise limited
to manifest-declared standard NEP-17/NEP-11 transfer methods; non-standard `transfer` methods keep
the generic unchecked-overflow obligations.
Methods with duplicate ABI parameter names make profile entrypoint coverage `incomplete`, because
name-based method-entry symbols would otherwise collide and make per-parameter proof obligations
ambiguous.

Built-in profile:

```json
{
  "version": 1,
  "profiles": ["neo-n3-security"],
  "properties": []
}
```

`--profile neo-n3-security` or the JSON `profiles` entry adds detector-backed formal safety
obligations for every manifest ABI method:

- `security.contract_identity.*`: NEF profile proofs must be bound to the deployed Neo N3
  contract hash. If a NEF is verified without `--deploy-sender-hash`, the profile remains
  `incomplete` because the manifest name and NEF checksum do not determine the final contract
  hash without the deployment sender. Raw `.bin` scripts are also `incomplete` for this obligation
  because they do not carry a NEF checksum or deployed contract identity.
- `security.manifest_permissions.*`: the manifest must avoid full wildcard
  `permissions`, non-standard partial wildcard `permissions`, wildcard `trusts`, and
  invalid `trusts` or permission contract descriptors. Hash descriptors must be 20-byte UInt160
  values, group descriptors must be valid secp256r1 ECPoint encodings, and group entries must not
  contain empty/wildcard or malformed group public keys/signatures. Group public keys must be valid
  secp256r1 ECPoint encodings, group signatures must decode to 64 bytes, and, when a
  `--deploy-sender-hash`-derived contract hash is available, group signatures must verify that
  exact Neo N3 contract hash. Manifests with groups are reported as `incomplete` until the
  verifier can compute the contract hash. Method-pinned
  `contract="*"` grants are accepted only for standard receiver callbacks required by complete
  exact-standard manifest-declared token ABIs, including the matching standard `transfer` ABI
  (`onNEP17Payment` for `NEP-17`, `onNEP11Payment` for `NEP-11`).
- `security.manifest_call_permissions.<method>`: every reachable
  `System.Contract.Call` or NEF `CALLT` external call must be covered by
  `manifest.permissions`, including modeled native contract calls whose return values are otherwise
  precise, even if a later `ASSERT`/`ABORT` rejects the path. Target hashes may be concrete byte
  literals or path-constrained dynamic symbols, for example after `ASSERT(to == knownReceiverHash)`;
  manifest hash descriptors match the VM target UInt160 byte-for-byte, so reversed-byte
  descriptors are not accepted as permission coverage. Unresolved dynamic targets are provable only
  for the method-pinned standard receiver callback grants above, and other dynamic
  targets/selectors make the proof `incomplete`. Group-based contract descriptors are also `incomplete` for concrete
  targets because target group membership is not modeled. A proved permission result is
  not a proof of target contract existence, target ABI compatibility, or callee fault-freedom.
  Non-modeled external targets make `security.vm_fault_free.<method>` and
  `security.vm_surface.<method>` `incomplete` unless a matching dependency proof summary is
  supplied through `--dependency-proof-summary` and explicitly trusted with
  `--trust-dependency-proof-summaries`. The trusted summary must cover the concrete target hash, method,
  parameter count, declared parameter ABI types, caller argument compatibility, return shape, and
  exact effective call flags plus a `fault_free: true` callee proof. Such v3 summaries can be
  emitted from verified dependency NEFs with `--emit-dependency-proof-summary` when the Neo N3
  deployed contract hash is available through `--deploy-sender-hash`; legacy v1/v2 summaries,
  unknown schema fields, invalid proof identity/checksum bindings, assumption-backed proof
  metadata, missing typed parameters for non-zero-arity methods, duplicate contract hashes, and
  duplicate method selectors inside a summary are rejected as ambiguous proof input.
- `security.access_control.<method>`: every successful path reaching `Storage.Put`,
  `Storage.Delete`, or an external call must have proof-grade authorization first
  (`Runtime.CheckWitness` consumed by `ASSERT`/branch against a stable principal or a
  principal related to that sensitive operation, caller-hash check against a stable or
  operation-related principal, or stable/operation-related `CheckSig`/`CheckMultisig`/CryptoLib signature verification
  consumed by `ASSERT`/branch). Stable `CheckWitness` principals include 20-byte UInt160
  hashes, valid 33-byte compressed secp256r1 public keys, and `CreateStandardAccount` /
  `CreateMultisigAccount` account hashes derived from stable valid ECPoint public keys.
  Stable caller-hash principals include the current executing script hash for
  same-contract self-call gates such as `CallingScriptHash == ExecutingScriptHash`.
  Stable `CheckSig` / `CheckMultisig` / CryptoLib signature principals include valid
  33-byte compressed or 65-byte uncompressed secp256r1 public keys for ECPoint signatures,
  or 32-byte Ed25519 public keys for `CryptoLib.verifyWithEd25519`; stable `CheckMultisig`
  public-key arrays must be closed, non-empty, and contain only valid ECPoint public keys.
  CryptoLib signatures over an explicit message also require that signed message to be
  operation-bound (for example, sharing ABI data with the storage value, storage key, or external
  call arguments being protected); a valid signature over an unrelated message does not authorize
  the sensitive operation.
  Caller-provided signature keys or derived accounts that are unrelated to the mutation
  do not count as proof-grade authorization.
  Non-transfer methods do not get authorization credit merely because a parameter is named
  `from`; NEP-17/NEP-11 transfer sender semantics are handled by the dedicated token proofs.
  Caller-hash assertions made after a mutation do not retroactively authorize the earlier
  mutation.
- `security.entrypoint_reaches_halt.<method>`: each manifest ABI entrypoint must reach at
  least one successful HALT path; an entrypoint that only faults is `incomplete`, not a
  vacuous proof. Runtime profile properties that are defined over successful paths also
  report `incomplete`, not `proved`, when the entrypoint has no successful HALT path.
- `security.abi_return_type.<method>`: every successful HALT path must return a StackItem
  compatible with the manifest ABI `returntype`. `Void` methods must not leave a result item,
  `Boolean` and `Integer` returns must use the matching runtime StackItem type, fixed-size
  byte returns such as `Hash160` must prove their byte length, `PublicKey` returns must prove
  33-byte length and valid ECPoint encoding, and `String` returns must prove strict UTF-8
  validity. Runtime type mismatches are violations; unsupported or unprovable return shapes
  are `incomplete`.
- `security.manifest_safe.<method>`: methods declared `safe=true` in the manifest must not
  reach successful `Storage.Put`, `Storage.Delete`, or external-call paths.
- `security.external_returns.<method>`: every modeled non-void external call return value
  must be checked by `ASSERT`, comparison, nullable-return `ISNULL`, `ISTYPE`, or a
  conditional branch before success, and a proven false return must not still reach a
  successful Boolean result. Unknown external returns and precise modeled native
  returns keep their `ext_ret_*` provenance through `ISNULL`/`NOT` and `ISTYPE` checks.
  CALLT MethodToken `HasReturnValue` metadata is enforced for modeled native
  method return shapes and overrides the standard receiver-callback Void exemption. Standard
  `onNEP17Payment` / `onNEP11Payment` receiver callbacks are treated as `Void` on matching
  token `transfer` proofs only after the target contract existence and ABI proof surface is
  closed, either by built-in modeling or a matching dependency proof summary. Rejection must
  happen by FAULT/ABORT rather than returning false. When the receiver target or ABI is not
  proof-grade modeled, the callback also makes `security.external_returns.<method>`,
  `security.vm_fault_free.<method>`, and `security.vm_surface.<method>` `incomplete`.
- `security.arithmetic.<method>`: successful paths must avoid unchecked overflow and
  divide-by-zero hazards recorded by the engine.
- `security.vm_fault_free.<method>`: every ABI entrypoint path must avoid unexpected reachable
  NeoVM faults and satisfiable syscall precondition faults such as overlong `Storage.Put` keys
  or values. `Runtime.CheckWitness` targets must prove either a 20-byte UInt160 hash or a valid
  33-byte compressed public key; malformed witness targets are VM/syscall faults, not ordinary
  authorization rejections. Explicit rejection faults from `ASSERT` and `ABORT` paths are ignored
  by the built-in profile; use custom `forbid_faults` for absolute fault-freedom.
- `security.vm_surface.<method>`: proofs fail as `incomplete` if a path depends on an unknown
  opcode/syscall, non-modeled external receiver callback or other external target, a stopped
  path, truncation, budget/coverage loss, or native NEO/GAS `transfer` side effects that are
  not yet proof-grade modeled.
- `security.nep17.abi.*`: for manifests declaring `NEP-17`, the manifest must expose
  `symbol`, `decimals`, `totalSupply`, `balanceOf`, `transfer`, required safe flags,
  return types, standard parameter names by ordinal, and the
  `Transfer(Hash160 from, Hash160 to, Integer amount)` event shape.
- `security.nep17.symbol_value.symbol`: for manifests declaring `NEP-17`, `symbol()`
  must return one stable concrete non-empty ASCII token symbol on every successful path,
  without whitespace or control characters; symbolic, multi-valued, non-ASCII, or empty
  symbols are rejected as `violated` or `incomplete`.
- `security.nep17.decimals_value.decimals`: for manifests declaring `NEP-17`,
  `decimals()` must return one stable concrete integer precision value on every successful
  path, and that value must be C# byte-compatible (`0..255`); negative, over-255, symbolic,
  storage-backed, or multi-valued precision results are rejected as `violated` or
  `incomplete`.
- `security.nep17.transfer_success_feasible.transfer`: for manifests declaring `NEP-17`,
  `transfer` must have at least one feasible non-self successful path that returns true; a
  token that can only reject transfers or can only return true for `from == to` is treated as
  non-functional.
- `security.nep17.self_transfer_success.transfer`: for manifests declaring `NEP-17`,
  every valid `from == to` path with a non-zero account and non-negative amount must return
  true and emit `Transfer(from, to, amount)`; contracts that reject self-transfer by
  returning false or faulting are reported as non-standard.
- `security.nep17.sender_authorized.transfer`: for manifests declaring `NEP-17`, `transfer`
  paths that can return true must prove `Runtime.CallingScriptHash == from` or an enforced
  `CheckWitness(from)`; a witness for an owner/admin constant is not enough.
- `security.nep17.amount_non_negative.transfer`: for manifests declaring `NEP-17`, `transfer`
  paths that can return true must prove the `amount` parameter is non-negative.
- `security.nep17.zero_address.transfer`: for manifests declaring `NEP-17`, `transfer`
  paths that can return true must prove `from` and `to` are not `UInt160.Zero`.
- `security.nep17.failure_no_state_change.transfer`: for manifests declaring `NEP-17`,
  `transfer` paths that can return false must not reach `Storage.Put`, `Storage.Delete`,
  `Runtime.Notify`, or non-read-only external side-effect calls such as receiver callbacks.
- `security.nep17.insufficient_balance_false.transfer`: for manifests declaring
  `NEP-17`, every proven non-self `transfer` path with `from balance < amount` must
  return false without observable side effects, and at least one clean false-return
  witness must be feasible; implementations that return true or fault via `ASSERT`/`ABORT`
  instead of returning false are reported as non-standard.
- `security.nep17.total_supply_unchanged.transfer`: for manifests declaring `NEP-17`,
  `transfer` paths that can return true must not mutate concrete storage keys read by
  `totalSupply()`; fixed-length symbolic account-key expressions, including
  `LEFT(from, 20)`, `LEFT(to, 20)`, and other splice-derived 20-byte C# `Hash160`
  storage keys, are proved non-aliasing by length when `totalSupply()` uses a concrete
  storage key, while unresolved dynamic key aliases remain `incomplete`.
- `security.nep17.lifecycle_event.<mint|burn>`: for manifests declaring `NEP-17`,
  public `mint(to, amount)` / `burn(from, amount)` methods that mutate concrete storage
  keys read by `totalSupply()` must update supply by `+amount` / `-amount` and emit
  `Transfer(null, to, amount)` / `Transfer(from, null, amount)`.
- `security.nep17.lifecycle_amount_non_negative.<mint|burn>`: for manifests declaring
  `NEP-17`, public `mint(to, amount)` / `burn(from, amount)` methods that mutate
  concrete storage keys read by `totalSupply()` must prove `amount >= 0` before changing
  supply.
- `security.nep17.lifecycle_zero_address.<mint|burn>`: for manifests declaring
  `NEP-17`, public `mint(to, amount)` / `burn(from, amount)` methods that mutate
  concrete storage keys read by `totalSupply()` must prove the recipient/sender account
  is not `UInt160.Zero` before changing supply.
- `security.nep17.lifecycle_balance.<mint|burn>`: for manifests declaring `NEP-17`,
  public `mint(to, amount)` / `burn(from, amount)` methods that mutate concrete storage
  keys read by `totalSupply()` must update the `balanceOf(account)` storage template:
  mint credits the recipient by `amount`, while burn proves the sender balance is at
  least `amount` before debiting it by `amount`.
- `security.nep17.lifecycle_failure_no_state_change.<mint|burn>`: for manifests declaring
  `NEP-17`, public `mint(to, amount)` / `burn(from, amount)` methods that can return
  false must not reach `Storage.Put`, `Storage.Delete`, `Runtime.Notify`, or non-read-only
  external side-effect calls on the false-return path.
- `security.nep17.totalsupply_non_negative.totalSupply`: for manifests declaring
  `NEP-17`, every successful `totalSupply()` path must return a non-negative integer;
  negative constants or reachable negative symbolic returns are `violated`.
- `security.nep17.totalsupply_return_consistency.totalSupply`: for manifests declaring
  `NEP-17`, `totalSupply()` may be a fixed constant, but if it reads storage then it must
  return the supply storage value it reads rather than a constant or unrelated expression.
- `security.nep17.balanceof_non_negative.balanceOf`: for manifests declaring
  `NEP-17`, every successful `balanceOf(account)` path must return a non-negative integer;
  negative constants or reachable negative symbolic returns are `violated`.
- `security.nep17.balance_delta.transfer`: for manifests declaring `NEP-17`, non-self
  `transfer` paths that can return true must read/write direct, concrete-prefix, or
  full-length Hash160 slice account balance keys such as `LEFT(from, 20)` as
  `from' = from - amount` and `to' = to + amount`;
  must prove the from balance is at least `amount` before debit; must not overwrite
  those balance keys after the proved debit/credit; self-transfer paths must leave
  that account's balance storage unchanged; unsupported storage-key shapes remain
  `incomplete`.
- `security.nep17.balanceof_storage_consistency.balanceOf`: for manifests declaring
  `NEP-17`, `balanceOf(account)` must read the same direct, concrete-prefix, or
  full-length Hash160 slice account balance storage key template that successful
  `transfer` paths update.
- `security.nep17.balanceof_return_consistency.balanceOf`: for manifests declaring
  `NEP-17`, `balanceOf(account)` must return the balance storage value it reads rather
  than a constant or unrelated expression.
- `security.nep17.transfer_event.transfer`: for manifests declaring `NEP-17`, every
  `transfer` path that can return true must emit a concrete `Transfer(from, to, amount)`
  notification bound to the transfer arguments. The notification must be emitted by the current
  token contract; native NEO/GAS `Transfer` notifications with matching payloads do not satisfy
  this obligation.
- `security.nep17.callback_order_payload.transfer`: for manifests declaring `NEP-17`,
  observed `onNEP17Payment` calls on true-return `transfer` paths must target `to`, occur
  after `Transfer(from, to, amount)`, and pass `(from, amount, data)`; dynamic selectors
  remain `incomplete`. A true-return path with no observed receiver callback is also
  `incomplete` unless a modeled `ContractManagement.getContract(to) == null` guard proves the
  receiver is not a contract on that path.
- `security.nep11.abi.*`: for manifests declaring `NEP-11`, the manifest must expose
  `symbol`, `decimals`, `totalSupply`, `tokensOf`, the required non-divisible or divisible
  `balanceOf` / `ownerOf` / `transfer` method shapes, required safe flags, return types,
  standard parameter names by ordinal, and the `Transfer(Hash160 from, Hash160 to, Integer
  amount, ByteString tokenId)` event shape. Optional `properties(tokenId)` and `tokens()`
  methods are validated when declared but are not required for core NEP-11 compliance.
  Neo N3 C# contracts commonly use source-level `ByteString` token IDs that are emitted as
  manifest `ByteArray` ABI parameters/events, so proof-grade NEP-11 ABI checks accept either
  spelling for tokenId fields and report when the C# manifest `ByteArray` form was used.
- `security.nep24.abi.*`: for manifests declaring `NEP-24`, the manifest must expose
  `royaltyInfo(ByteString tokenId, Hash160 royaltyToken, Integer salePrice): Array safe=true`,
  the `RoyaltiesTransferred(Hash160 royaltyToken, Hash160 royaltyRecipient, Hash160 buyer,
  ByteString tokenId, Integer amount)` event shape, and a declared, complete NEP-11 base NFT
  ABI (`symbol`, `decimals`, `totalSupply`, `tokensOf`, the required `balanceOf` / `ownerOf`
  / `transfer` shape, and `Transfer`). As with NEP-11, manifest `ByteArray` tokenId fields
  are accepted for Neo N3 C# source-level `ByteString` compatibility.
- `security.nep24.behavior.royaltyInfo`: for manifests declaring `NEP-24`, every successful
  `royaltyInfo` path must return a closed Array/Struct of royalty entries, where every entry is
  `[recipient, amount]`, `recipient` is Hash160-compatible, and `amount` is a non-negative
  Integer. Malformed entries are `violated`; open symbolic entry arrays remain `incomplete`.
- `security.nep24.behavior.sale_price.royaltyInfo`: for manifests declaring `NEP-24`, every
  returned royalty amount must depend on the `salePrice` argument, matching the standard's
  `royaltyInfo() MUST NOT ignore salePrice` requirement. Constant returned royalty amounts are
  `violated`; empty royalty arrays discharge the returned-amount dependency obligation
  vacuously.
- `security.nep24.behavior.royalties_transferred.<method>`: for methods that emit a concrete
  `RoyaltiesTransferred` notification, the observed payload must be a closed five-field array
  whose fields bind to method inputs `royaltyToken`, `royaltyRecipient`, `buyer`, `tokenId`, and
  `amount` in the NEP-24 event order. Mismatched or symbolic payloads are not accepted as proved;
  marketplace payment ordering, native token balance effects, and cross-contract `royaltyInfo`
  calls remain outside this built-in proof and should be supplied as custom specs until full
  payment-flow modeling lands.
- `security.nep27.abi.*`: for manifests declaring `NEP-27`, the manifest must expose
  `onNEP17Payment(Hash160 from, Integer amount, Any data): Void` so receiver contracts can
  be called by NEP-17 token contracts using the standard payment callback surface.
- `security.nep27.behavior.onNEP17Payment`: NEP-27 receiver callbacks prove the built-in
  passive receiver obligation when every feasible successful `onNEP17Payment` path is
  fault-free and performs no `Storage.Put` / `Storage.Delete`, `Runtime.Notify`, or
  external contract call. Stateful receiver acceptance policies and post-callback business
  invariants should be supplied as custom specs when a contract intentionally does more than
  passive acceptance.
- `security.nep26.abi.*`: for manifests declaring `NEP-26`, the manifest must expose
  `onNEP11Payment(Hash160 from, Integer amount, ByteString tokenId, Any data): Void` so
  receiver contracts can be called by NEP-11 NFT contracts using the standard payment
  callback surface. Manifest `ByteArray` tokenId is accepted for Neo N3 C# source-level
  `ByteString` compatibility, and manifest `String` tokenId is accepted for released
  Neo.SmartContract.Framework INEP26 interface compatibility.
- `security.nep26.behavior.onNEP11Payment`: NEP-26 receiver callbacks prove the built-in
  passive receiver obligation when every feasible successful `onNEP11Payment` path is
  fault-free and performs no `Storage.Put` / `Storage.Delete`, `Runtime.Notify`, or
  external contract call. Stateful tokenId/data handling, acceptance policies, and
  post-callback business invariants should be supplied as custom specs when a contract
  intentionally does more than passive acceptance.
- `security.nep11.symbol_value.symbol`: for manifests declaring `NEP-11`, `symbol()`
  must return one stable concrete non-empty ASCII token symbol on every successful path,
  without whitespace or control characters; symbolic, multi-valued, non-ASCII, or empty
  symbols are rejected as `violated` or `incomplete`.
- `security.nep11.iterator_returns.*`: for manifests declaring `NEP-11`, `tokensOf(owner)`,
  declared `tokens()`, and divisible `ownerOf(tokenId)` methods must actually return
  Neo iterator `InteropInterface` values on every successful HALT path, not just declare
  `InteropInterface` in the manifest ABI or return another interop object such as a storage
  context. `tokensOf(owner)` must additionally return an owner-scoped `Storage.Find` iterator
  rooted in a concrete owner-token namespace before the owner bytes, with concrete options
  including `KeysOnly | RemovePrefix`; declared `tokens()` must return a key-only `Storage.Find`
  iterator over a non-empty concrete token namespace with `RemovePrefix`; divisible
  `ownerOf(tokenId)` must return a tokenId-scoped key-only `Storage.Find` iterator rooted in a
  concrete owner namespace before tokenId with `RemovePrefix`, so raw-parameter or unrelated
  iterators are not treated as proof-grade NEP-11 enumeration.
- `security.nep11.decimals_consistency.decimals`: for manifests declaring `NEP-11`,
  non-divisible `decimals()` must return integer `0`; divisible `decimals()` must
  return a non-zero integer. Dynamic returns that cannot be ruled consistent by SMT remain
  `incomplete` rather than proved.
- `security.nep11.transfer_success_feasible.transfer`: for manifests declaring `NEP-11`,
  non-divisible and divisible `transfer` methods must have at least one feasible successful
  path that returns true; a token that can only reject transfers is treated as non-functional.
- `security.nep11.tokenid_length.*`: for NEP-11 non-transfer tokenId methods such as
  `ownerOf(tokenId)`, divisible `balanceOf(owner, tokenId)`, declared `properties(tokenId)`,
  and lifecycle mint/burn methods, every successful return path must prove `tokenId` length is
  at most 64 bytes.
- `security.nep11.tokenid_length.transfer`: for non-divisible and divisible NEP-11
  `transfer` methods, true-return paths must prove `tokenId` length is at most 64 bytes.
- `security.nep11.owner_authorized.transfer`: for non-divisible NEP-11 `transfer` methods,
  true-return paths must read the current owner from tokenId-indexed storage and prove
  `Runtime.CallingScriptHash == ownerOf(tokenId)` or enforce `CheckWitness(ownerOf(tokenId))`
  before mutating ownership.
- `security.nep11.sender_authorized.transfer`: for divisible NEP-11 `transfer` methods,
  true-return paths must prove `Runtime.CallingScriptHash == from` or enforce
  `CheckWitness(from)` before successful transfer completion.
- `security.nep11.amount_non_negative.transfer`: for divisible NEP-11 `transfer` methods,
  true-return paths must prove `amount >= 0`.
- `security.nep11.amount_lte_decimals.transfer`: for divisible NEP-11 `transfer` methods,
  true-return paths must prove `amount <= 10^decimals()` using the unique concrete
  `decimals()` value; symbolic or non-unique decimals remain `incomplete`.
- `security.nep11.total_supply_unchanged.transfer`: for non-divisible and divisible
  NEP-11 `transfer` methods, true-return paths must not mutate concrete storage keys
  read by `totalSupply()`; fixed-length symbolic owner/token-key expressions can be
  proved non-aliasing by length when `totalSupply()` uses a concrete storage key,
  while unresolved dynamic key aliases remain `incomplete`.
- `security.nep11.lifecycle_event.<mint|burn>`: for manifests declaring `NEP-11`,
  public `mint(to, tokenId)` / `burn(from, tokenId)` or divisible
  `mint(to, amount, tokenId)` / `burn(from, amount, tokenId)` methods that mutate
  concrete storage keys read by `totalSupply()` must update supply by `+1` / `-1`
  or `+amount` / `-amount` and emit the matching lifecycle `Transfer` payload.
- `security.nep11.lifecycle_amount_non_negative.<mint|burn>`: for divisible NEP-11
  public `mint(to, amount, tokenId)` / `burn(from, amount, tokenId)` methods that mutate
  concrete storage keys read by `totalSupply()` must prove `amount >= 0` before changing
  supply.
- `security.nep11.lifecycle_zero_address.<mint|burn>`: for non-divisible and divisible
  NEP-11 lifecycle methods that mutate concrete storage keys read by `totalSupply()` must
  prove the recipient/sender account is not `UInt160.Zero` before changing supply.
- `security.nep11.lifecycle_balance.<mint|burn>`: for non-divisible and divisible
  NEP-11 lifecycle methods that mutate concrete storage keys read by `totalSupply()` must
  update the `balanceOf(owner)` storage template: mint credits the recipient by `1` or
  `amount`, while burn proves the sender balance is sufficient before debiting it by `1`
  or `amount`.
- `security.nep11.lifecycle_failure_no_state_change.<mint|burn>`: for non-divisible and
  divisible NEP-11 lifecycle methods that can return false, rejection paths must not reach
  `Storage.Put`, `Storage.Delete`, `Runtime.Notify`, or non-read-only external side-effect
  calls.
- `security.nep11.lifecycle_index.<mint|burn>`: for non-divisible NEP-11 lifecycle
  methods that mutate concrete storage keys read by `totalSupply()`, successful mint paths
  must write the minted `tokenId` into declared `tokens()` and `tokensOf(to)` enumeration
  indexes, while successful burn paths must delete the burned `tokenId` from declared
  `tokens()` and `tokensOf(from)` enumeration indexes.
- `security.nep11.lifecycle_owner_storage.<mint|burn>`: for non-divisible NEP-11
  lifecycle methods that mutate concrete storage keys read by `totalSupply()`, successful
  mint paths must write `ownerOf(tokenId)` storage to the recipient, while successful burn
  paths must delete `ownerOf(tokenId)` storage for the burned token.
- `security.nep11.lifecycle_ownerof_index.<mint|burn>`: for divisible NEP-11 lifecycle
  methods that mutate concrete storage keys read by `totalSupply()`, successful mint/burn
  paths must keep the tokenId-scoped owner index used by `ownerOf(tokenId)` synchronized
  with final account/token balances.
- `security.nep11.totalsupply_non_negative.totalSupply`: for non-divisible and divisible
  NEP-11 contracts, every successful `totalSupply()` path must return a non-negative
  integer; negative constants or reachable negative symbolic returns are `violated`.
- `security.nep11.totalsupply_return_consistency.totalSupply`: for non-divisible and
  divisible NEP-11 contracts, `totalSupply()` may be a fixed constant, but if it reads
  storage then it must return the supply storage value it reads rather than a constant or
  unrelated expression.
- `security.nep11.balanceof_non_negative.balanceOf`: for non-divisible and divisible
  NEP-11 contracts, every successful `balanceOf(owner)` or `balanceOf(owner, tokenId)`
  path must return a non-negative integer; negative constants or reachable negative
  symbolic returns are `violated`.
- `security.nep11.owner_update.transfer`: for non-divisible NEP-11 `transfer` methods,
  true-return paths must write the same tokenId-indexed owner storage key to `to` and must
  not overwrite or delete that owner key before returning.
- `security.nep11.owner_balance_delta.transfer`: for non-divisible NEP-11 `transfer`
  methods, non-self true-return paths must read/write the same owner balance key template
  as `from' = from - 1` and `to' = to + 1`; they must prove the current owner balance is
  at least `1` before debit and preserve the final debited/credited balance keys.
- `security.nep11.tokensof_index.transfer`: for non-divisible NEP-11 `transfer`
  methods, non-self true-return paths must delete the previous owner/tokenId key and write
  the recipient/tokenId key for the concrete `tokensOf(owner)` `Storage.Find` index template,
  while self-transfer paths must leave that enumeration index unchanged.
- `security.nep11.ownerof_storage_consistency.ownerOf`: for non-divisible NEP-11
  contracts, `ownerOf(tokenId)` must read the same token owner storage key template that
  successful `transfer(to, tokenId, data)` paths update.
- `security.nep11.ownerof_return_consistency.ownerOf`: for non-divisible NEP-11
  contracts, `ownerOf(tokenId)` must return the token owner storage value it reads rather
  than a constant or unrelated expression.
- `security.nep11.failure_no_state_change.transfer`: for non-divisible NEP-11 `transfer`
  methods and divisible NEP-11 `transfer` methods, false-return rejection paths must not
  reach `Storage.Put`, `Storage.Delete`, `Runtime.Notify`, or non-read-only external
  side-effect calls such as receiver callbacks.
- `security.nep11.invalid_token_false.transfer`: for non-divisible NEP-11 `transfer`
  methods, every proven path where `tokenId` has no current owner must return false
  without observable side effects, and at least one clean false-return witness must be
  feasible; implementations that return true or fault via `ASSERT`/`ABORT` instead of
  returning false are reported as non-standard.
- `security.nep11.insufficient_balance_false.transfer`: for divisible NEP-11 `transfer`
  methods, every proven non-self path where `from` token balance is below `amount` must
  return false without observable side effects, and at least one clean false-return
  witness must be feasible; implementations that return true or fault via `ASSERT`/`ABORT`
  instead of returning false are reported as non-standard.
- `security.nep11.balance_delta.transfer`: for divisible NEP-11 `transfer` methods,
  non-self true-return paths must read/write the same tokenId-indexed from/to account
  balance key template as `from' = from - amount` and `to' = to + amount`; they must
  prove the from token balance is at least `amount` before debit and preserve the final
  debited/credited balance keys.
- `security.nep11.ownerof_index.transfer`: for divisible NEP-11 `transfer` methods,
  non-self true-return paths must keep the tokenId-scoped owner index used by
  `ownerOf(tokenId)` synchronized with final token balances: a sender whose balance reaches
  zero must have its sender/tokenId owner index entry deleted, a recipient with positive
  final balance must have its recipient/tokenId owner index entry written, and zero-balance
  recipients must not be added.
- `security.nep11.balanceof_storage_consistency.balanceOf`: for non-divisible NEP-11
  contracts, `balanceOf(owner)` must read the same owner balance key template updated by
  successful `transfer` paths; for divisible NEP-11 contracts, `balanceOf(owner, tokenId)`
  must read the same owner/tokenId balance storage key template.
- `security.nep11.balanceof_return_consistency.balanceOf`: for non-divisible NEP-11
  contracts, `balanceOf(owner)` must return that owner balance storage value rather than a
  constant or unrelated expression; for divisible NEP-11 contracts,
  `balanceOf(owner, tokenId)` must return that token balance storage value.
- `security.nep11.transfer_event.transfer`: for non-divisible NEP-11 `transfer` methods,
  every path that can return true must emit concrete `Transfer(owner, to, 1, tokenId)` bound
  to the observed owner, recipient argument, and tokenId argument; for divisible NEP-11
  methods, the event must be `Transfer(from, to, amount, tokenId)` bound to transfer
  arguments.
- `security.nep11.callback_order_payload.transfer`: for non-divisible NEP-11 `transfer`
  methods, observed `onNEP11Payment` calls on true-return paths must target `to`, occur after
  `Transfer(owner, to, 1, tokenId)`, and pass `(owner, 1, tokenId, data)`; for divisible
  NEP-11 methods, callback payloads must be `(from, amount, tokenId, data)` after
  `Transfer(from, to, amount, tokenId)`; dynamic selectors and true-return paths with no
  observed receiver callback remain `incomplete` unless a modeled
  `ContractManagement.getContract(to) == null` guard proves recipient contract absence.

The proof is bounded by the NeoVM/syscall model and the configured engine budgets. That is
intentional: unsupported VM surface, stale manifest offsets, path explosion, solver unknowns,
SMT concretization of symbolic runtime operands, and skipped entrypoints are reported as
`incomplete`/`unknown` and fail CI under the default `--fail-on-unproved` gate.

Verification JSON reports are reproducible proof artifacts: `meta.inputs` records the program,
manifest, optional spec, dependency proof summary paths plus SHA-256 hashes, and dependency proof artifact contract hashes plus bound program/manifest paths and SHA-256 hashes;
`meta.inputs.dependency_proof_policy` records whether dependency summaries were trusted to close
external-call proofs and whether local artifact binding was required; malformed or mismatched
dependency proof inputs are reported as `security.dependency_proof.input`;
`meta.smt_solver_version`,
`meta.smt_timeout_ms`, `meta.smt_bytes_bound`, and `meta.engine_options` record the
solver, trigger, effective method-entry call flags, and bounded-execution configuration; the
default method-entry call flags and runtime trigger are reported as
`meta.engine_options.initial_call_flags` and `meta.engine_options.default_runtime_trigger`.
Per-property verification results include the resolved
`method_offset` when a manifest ABI entrypoint was executed, so overload-specific proofs and
profile obligations remain auditable from the artifact. Built-in profile results also record
`source_profile: "neo-n3-security"`, which is required when emitting dependency proof summaries.
They also include a stable
`assumptions` array; profile proofs that discharge storage-backed NEP token integer conversions
under the NEP token storage integer encoding invariant list
`nep_token_storage_integer_encoding`, which means Storage.Get values used as NEP token integers
are assumed to be present and encoded as NeoVM integers within the 32-byte StackItem integer limit.
Non-divisible NEP-11 `ownerOf(tokenId)` ABI return-type proofs may list
`nep11_owner_storage_hash160_encoding`, which means Storage.Get values used as token owners are
assumed to be either missing/null or encoded as 20-byte UInt160 owner values.
These assumptions are limited to complete exact-standard NEP-17/NEP-11 ABI manifests and their
standard token storage methods such as `transfer`, `balanceOf`, `totalSupply`, and
non-divisible `ownerOf`; within those methods the integer-encoding invariant is limited to
recognized balance/account-token and returned `totalSupply()` storage reads, while auxiliary
storage integers keep the ordinary conversion fault obligations. Malformed same-name ABI methods keep
the ordinary conversion fault obligations. Results proved under explicit assumptions render as
`status: "proved_with_assumptions"` with `base_status: "proved"` and
`proved_under_assumptions: true`; summaries separately report
`proved_without_assumptions`, `proved_with_assumptions`, and
`all_proved_without_assumptions`. The default verification gate requires unqualified proofs:
assumption-backed profile results fail the gate even when `--allow-unproved` is used to collect
exploratory incomplete-property reports. Pass `--allow-assumption-backed-proofs` only when a CI
job intentionally accepts explicitly qualified proofs.
Markdown verification reports order
violated, unknown, and incomplete properties before proved properties so default human-readable
output surfaces failing proof obligations early. Markdown verification reports include each result's
per-property source profile, dependency proof artifact provenance from
`meta.inputs.dependency_proof_artifacts`, program, manifest, and spec input paths with SHA-256
values, SMT timeout/byte bounds, engine options, and the dependency proof trust policy from
`meta.inputs.dependency_proof_policy`, so human-reviewed reports show the same bound contract
hashes, program/manifest SHA-256 evidence, proof budgets, and trusted/unbound policy as JSON
reports. Pass `--require-external-smt` in proof-grade CI
to fail when `z3` is unavailable and the verifier would otherwise use the portable SMT fallback. The verify JSON
also includes `gate_evaluation`: `passed` records the actual CLI gate decision,
`policies.fail_on_unproved`, `policies.unproved_allowed`, and `policies.require_external_smt`
and `policies.require_unqualified_proofs`
record the selected gate policy, `assumption_backed_proofs` counts qualified proofs, and
`violations` explains why an artifact failed even when every
individual property was proved under a non-proof-grade solver or an exploratory run used
`--allow-unproved`.

## CLI exit codes

| Code | Meaning                                  |
|------|------------------------------------------|
| 0    | OK / gate passed                         |
| 1    | Analyzer error (parse failure, etc.)     |
| 2    | Bad arguments                            |
| 3    | Gate violation (analysis ok, gate fired) |

The default analyze gate fails on `high`/`critical` findings, incomplete manifest
coverage, and budget-exceeded runs. Use `--fail-on-max-severity <sev>` to tune the
severity threshold for a specific CI policy.

Budget-aware gating is on by default: the gate fires (exit 3) when the engine hit
`--max-paths`, `--max-steps`, `--max-visits-per-offset`,
`--max-queued-states`, or `--per-run-deadline-ms` on any manifest entrypoint. Useful in
CI to flag analyses that would otherwise pass silently with incomplete coverage; budget
stops are also surfaced through `budget_exceeded` and `budget_reason` metadata.

Coverage-integrity gating is on by default. If a manifest declares a method whose offset is
outside the script bytes or inside another instruction's operand bytes, or symbolic execution stops on a modeling limit before a path is fully
covered, the report records `coverage_incomplete`, the gate exits 3, and stderr/report metadata
name the skipped or stopped surface. Use `--allow-incomplete-coverage` only for exploratory
analysis of intentionally stale or partially modeled inputs.
Manifest-driven `analyze` and `verify --profile` also cap ABI entrypoint fanout with
`--max-entrypoints` (default 128, maximum 1024), so a large manifest cannot multiply per-run
symbolic execution budgets into an unbounded CI job; skipped methods are reported as incomplete
coverage/proof results rather than silently ignored.

## JSON output schema

`--format json` emits a stable, byte-deterministic document — CI consumers can SHA-256 it
as an artifact key. Top-level shape:

```jsonc
{
  "meta": {
    "tool": "Neo.SymbolicExecutor",
    "version": "0.8.0",                  // assembly InformationalVersion (no commit suffix)
    "states_explored": 168,
    "steps_executed": 12340,
    "budget_exceeded": false,
    "budget_reason": null,
    "coverage_incomplete": false,        // true when manifest-declared entrypoints were skipped
    "coverage_reason": null,
    "skipped_entrypoints": [],           // e.g. ["transfer@999"]
    "smt_available": true,               // true iff the external high-precision solver (z3) ran;
                                         // false when --smt fell back to the portable in-process solver
    "smt_engaged": true,                 // true iff the user passed --smt
    "smt_stats": {                       // present iff --smt was passed
      "queries": 42, "cache_hits": 12,
      "sat": 18, "unsat": 8, "unknowns": 4, "timeouts": 0,
      "opaque_translations": 0           // count of expressions translated as
                                         // unconstrained aux symbols (sound
                                         // over-approximation; >0 means SAT/UNSAT
                                         // verdicts may have lost precision)
    }
  },
  "risk_profile": {
    "overall_max_severity": "high",      // info|low|medium|high|critical
    "total_findings": 7,
    "weighted_score": 73,
    "confidence_weighted_score": 58,
    "severity_counts":            { "critical": 1, "high": 2, "medium": 3, "low": 1 },
    "detector_max_severity":      { "access_control": "high", "reentrancy": "critical" },
    "detector_average_confidence":{ "access_control": 0.85,   "reentrancy": 0.72 }
  },
  "gate_evaluation": {
    "passed": false,
    "policies":   { "fail-on-max-severity": "high" },
    "violations": [ "max severity high >= threshold high" ]
  },
  "findings": [
    {
      "detector": "reentrancy",
      "severity": "critical",
      "title": "External call before state write",
      "description": "...",
      "offset": 256,
      "confidence": 0.85,
      "confidence_reason": "path uncertainty=2, base 0.95 -> 0.81",
      "tags": [ "checks-effects-interactions" ],
      "path_satisfiable": true,           // null when --smt not engaged
      "witness": { "amount": "1000" }     // null absent SAT witness
    }
  ]
}
```

Severity-keyed dicts emit critical-first; detector-keyed dicts emit ordinal-sorted. Both
JSON and Markdown render numerics with InvariantCulture so reports diff cleanly across
machine locales.

## DevPack integration

See `devpack-integration/README.md` — provides MSBuild `.props` + `.targets`
that drop into a Neo DevPack contract project and run `neo-sym analyze` plus the default
`neo-n3-security` formal verification profile after build.

## Fuzzing

Multi-target multi-worker fuzzer for the engine, parsers, detectors, reports, and
SMT translator. Designed for days/weeks of continuous operation with persistent
corpus and unique-crash deduplication.

```bash
# Smoke run (60 seconds, all targets)
src/Neo.SymbolicExecutor.Fuzzer/bin/Release/net10.0/neo-sym-fuzz --seconds 60

# Long run with the wrapper (restarts daily, daily summaries, signal-handling)
nohup scripts/run-fuzzer-forever.sh ./fuzz-corpus 8 > /dev/null 2>&1 &
disown
```

See `src/Neo.SymbolicExecutor.Fuzzer/README.md` for target list, throughput baselines,
crash-artifact layout, and the systemd unit example. The first 90 seconds of fuzzing
surfaced 58 unique crashes covering two engine bug classes; both fixed and locked in
by `FuzzerRegressionTests`.

## Detectors

37 detectors are wired in `DefaultDetectorSet`:

- `reentrancy` — checks-effects-interactions with audit-driven amplification scoring
- `access_control` — missing / unenforced / late authorization, with `manifest.safe` respect
- `overflow` — symbolic-operand arithmetic + divide-by-zero
- `unchecked_return` — external call return value not consumed by ASSERT/branch
- `dynamic_call_target` — runtime-determined target hash and/or method selector
- `dangerous_call_flags` — CallFlags.All and bit-count >= 3 broad grants
- `dos` — recursion, iterator scans, excessive writes, capped-loop signals
- `gas_exhaustion` — paths over a configurable threshold
- `randomness` — timestamp-derived as HIGH; `Runtime.GetRandom` as INFO
- `timestamp` — INFO triage signal
- `storage_collision` — separator-aware prefix overlap detection
- `upgradeability` — `ContractManagement.Update`/`Destroy` reachability + auth posture
- `permissions` — manifest wildcards, partial wildcards, `trusts`, group misconfig
- `admin_centralization` — single-witness privileged ops (LOW)
- `nep17_compliance` — NEP-17 ABI / events / safe-flag conformance
- `nep11_compliance` — NEP-11 NFT ABI / required `ownerOf` / exact `Transfer` event conformance
- `nep24_compliance` — NEP-24 NFT royalty ABI / event / safe-flag conformance
- `nep27_compliance` — NEP-27 NEP-17 receiver callback ABI conformance
- `nep26_compliance` — NEP-26 NEP-11 receiver callback ABI conformance
- `callback_reentry` — onNEP17Payment / onNEP11Payment recipient-callback re-entry
- `crypto_verification_bypass` — CheckSig / CheckMultisig result not consumed
- `replay_attack` — signature-gated state change without an apparent nonce
- `taint_flow_upgrade` — `Contract.Update` with caller-supplied NEF / manifest
- `public_privileged_method` — manifest-exposed mint/burn/withdraw/upgrade-like entrypoints without early auth
- `defi_slippage_oracle` — swap-like or reserve/vault-mutating token flows lacking min-out/slippage or oracle freshness signals
- `nft_ownership_authorization` — NEP-11 ownership/approval or dynamic-key writes before owner/operator authorization
- `entry_script_auth` — `Runtime.GetEntryScriptHash` used for authorization (Neo analogue of the Ethereum tx.origin bug)
- `unsafe_deserialization` — `StdLib.deserialize` / `jsonDeserialize` on values derived from method arguments, storage, iterator yields, or prior external-call returns
- `unprotected_deploy` — `_deploy(data, update)` does not branch on the `update` flag, so contract upgrades re-run initialization (admin reset, re-mint) — see audit Iter-3
- `nep17_amount_validation` — NEP-17 `transfer` mutates state without first constraining the `amount` argument (negative-amount mint via balance debit/credit role flip)
- `signature_malleability` — raw ECDSA signature bytes used as a storage dedup key without low-S normalization
- `nep17_zero_address` — NEP-17 `transfer` mutates state without checking `from` / `to` against UInt160.Zero
- `nep17_transfer_to_self` — NEP-17 `transfer` body uses both `from` and `to` as storage keys without short-circuiting the from==to case (stale-state debit/credit)
- `oracle_response_validation` — `onOracleResponse`-shaped callback mutates state without branching on the `code` (OracleResponseCode) argument
- `supported_standards_coverage` — INFO notice when the manifest declares a standard without dedicated analyzer compliance coverage
- `toctou_storage` — Storage.Get-then-call-then-Storage.Put pattern where the write value depends on the prior read (lost-update window across the external call)
- `unknown_instructions` — coverage gap surface (INFO)

NEP compliance detectors scan every same-named ABI overload and accept the standard overload when
C# helper overloads appear first in the manifest. NEP-11/24 tokenId fields accept manifest
`ByteArray` for Neo N3 C# source-level `ByteString` compatibility, and NEP-26 also accepts the
released Neo.SmartContract.Framework `String` tokenId callback shape.

With `--source <file-or-dir>`, protocol detectors use method-local C# source hints to recover
intent that NEF bytecode does not preserve, such as reserve, amount-out, deadline, owner, and
approval naming. The source matcher uses Roslyn syntax trees so braces, comments, strings, raw
strings, attributes, and C# syntax variants are parsed without regex body slicing. It
disambiguates overloads by parameter arity, so a privileged ABI method can no longer be silently
exonerated by a benign same-named overload elsewhere in the project. `[DisplayName("foo")]`
attributes on methods are recognised, so an ABI-named entrypoint resolves to its underlying C#
implementation even when the source identifier differs. Generated and dependency directories
(`bin`, `obj`, `.git`, `.vs`, `.omx`, `node_modules`, `packages`) are skipped during enumeration.
Source hint loading is bounded to 2,048 files, 1 MiB per source file, 16 MiB total source text,
and 64 directory levels; reparse-point directories are skipped.

With `--smt`, each finding is validated for path satisfiability; infeasible findings are dropped
(or downgraded), and SAT findings include a concrete witness reproducer.

## Audit traceability

Every detector and every fix in this codebase carries a reference to the underlying audit
finding in its XML doc comments. Examples baked in from day one:

- PUSHA target=0 always uses resolved `Target` field (audit CRIT-1)
- Cross-type primitive equality via canonical bytes (audit HIGH-2)
- Witness-enforcement marker scoped to the branch that proceeds *because* the witness
  passed; the unauth branch stays unenforced (audit C8/C9)
- Direct `System.Contract.CallNative` use from user contracts faults instead of becoming an opaque proved call
- Reentrancy guard suppression hook + last-write-offset semantics (audit C1)
- Overflow false-positive cap + `INC`/`DEC`/`SHL`/`POW` tracked (audit overflow.py finding)
- `manifest.abi_methods.safe` consulted by access_control (audit detector audit #18)
- Native read-only allowlist (`Ledger`, `StdLib`, current `CryptoLib` hash/signature methods, etc.) used by reentrancy
  + access_control (audit detector audit #1, biggest precision win)
- 5 new detectors covering audit gaps: NEP-11, callback re-entry, replay, crypto bypass,
  taint-flow upgrade
- 3 Neo protocol-risk detectors:
  - `public_privileged_method` — manifest-exposed mint/burn/withdraw/upgrade-like entrypoints without early auth
  - `defi_slippage_oracle` — swap/vault token flows lacking min-out/slippage or oracle freshness signals
  - `nft_ownership_authorization` — NEP-11 ownership/approval writes before owner/operator authorization
- Method-local C# source hints (Roslyn syntax + arity-aware) used by the protocol-risk detectors

## License

MIT.
