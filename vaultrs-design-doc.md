# VaultRS — Design Document
### A cross-platform, self-hosted, zero-knowledge password manager + TOTP authenticator in Rust

---

## 1. Goals & Non-Goals

**Goals**
- Store arbitrary secrets: passwords, TOTP seeds, secure notes, card details, SSH keys, recovery codes — anything.
- Full parity with "Google Authenticator" for TOTP (RFC 6238), plus vault storage Authenticator doesn't have.
- Works identically on Arch Linux (i3) and Windows.
- Sync between your two machines over your existing Tailscale network.
- Server (if compromised) learns **nothing** — zero-knowledge architecture.
- Trustable enough for banking credentials. This means paranoid defaults everywhere, not just "good enough."

**Non-Goals (v1)**
- Browser extension / autofill — huge attack surface (extensions are a common malware vector, which is likely partly how you got hit). Do this last, if ever.
- Mobile app.
- Multi-user / team sharing.
- Biometric unlock (Windows Hello / fingerprint) — nice-to-have, phase 5+.

---

## 2. Threat Model

Define this explicitly before writing code — it drives every decision below.

| Threat | Defense |
|---|---|
| Vault file stolen (disk theft, backup leak) | Argon2id KDF + XChaCha20-Poly1305 AEAD. Brute-force must be computationally infeasible. |
| Sync server fully compromised | Server only ever sees ciphertext. No key material, no plaintext, ever touches the server. |
| Malware/keylogger on your machine while unlocked | Out of scope for the vault itself — this is what stealer malware exploits (likely what hit you). Mitigate via `zeroize`, memory locking, short auto-lock timers. No software fixes a keylogger; OS hygiene does. |
| Memory dump / swap file leak | `mlock`/`VirtualLock` to prevent secrets swapping to disk; `zeroize` on drop. |
| Network MITM during sync | TLS + Tailscale (WireGuard) as transport; app-layer AEAD makes MITM moot even if transport somehow fails. |
| Weak master password | Argon2id with strong parameters (tuned to ~500ms-1s on your hardware) + optional passphrase strength check client-side. |
| Replay of old sync data | Per-entry monotonic version counter + timestamp, signed. |
| You losing the master password | **No recovery by design.** Zero-knowledge means no backdoor. Document this clearly — it's a real tradeoff you're choosing. |

---

## 3. High-Level Architecture

```
┌─────────────────────┐         ┌─────────────────────┐
│   Linux Client       │         │   Windows Client      │
│  (CLI, later GUI)    │         │  (CLI, later GUI)     │
│                       │         │                       │
│  vaultrs-core crate   │         │  vaultrs-core crate   │
│  (shared, identical)  │         │  (shared, identical)  │
└──────────┬────────────┘         └──────────┬────────────┘
           │  encrypted blobs only            │
           │  (over Tailscale/WireGuard)       │
           └────────────┬──────────────────────┘
                         │
                ┌────────▼─────────┐
                │  vaultrs-server    │
                │  (axum, on your    │
                │   home box / VPS)  │
                │                    │
                │  Stores ciphertext │
                │  only. No keys.    │
                └────────────────────┘
```

**Workspace layout (Cargo workspace, single repo):**

```
vaultrs/
├── Cargo.toml                # workspace root
├── vaultrs-core/             # crypto + vault logic + TOTP — zero UI/IO deps
│   ├── src/
│   │   ├── crypto.rs         # KDF, AEAD wrappers
│   │   ├── vault.rs          # entry model, encrypt/decrypt
│   │   ├── totp.rs           # RFC 6238 implementation
│   │   ├── store.rs          # on-disk format read/write
│   │   └── lib.rs
├── vaultrs-cli/               # your daily driver
├── vaultrs-server/            # axum sync server
├── vaultrs-sync-protocol/     # shared types between client/server (serde structs)
└── vaultrs-gui/                # tauri/egui — phase 5, not v1
```

Splitting `core` out matters: it's the security-critical part, so it should be the most tested, the most reviewed, and have **zero** dependency on UI, networking, or CLI parsing. Every crypto bug lives in one small, auditable place.

---

## 4. Cryptography Spec

Do not deviate from audited crates. Do not implement primitives yourself. Your job is correct *composition*, not inventing crypto.

| Purpose | Crate | Notes |
|---|---|---|
| Key derivation from master password | `argon2` (Argon2id variant) | Params: memory ≥ 64 MB, iterations ≥ 3, parallelism = your core count. Tune so unlock takes 500ms–1s on your Ryzen 7700X. |
| Symmetric encryption | `chacha20poly1305` (XChaCha20-Poly1305) | 24-byte random nonce per entry — XChaCha's large nonce space means you can use `rand` safely without nonce-reuse anxiety. |
| Memory hygiene | `zeroize` (+ `zeroize_derive`) | Every struct holding plaintext secrets implements `ZeroizeOnDrop`. |
| Secure random | `rand` (`OsRng`) | For nonces, salts. |
| TOTP | `totp-rs` or hand-rolled HMAC-SHA1/256 via `hmac` + `sha1`/`sha2` crates | Hand-rolling is a good learning exercise; verify against RFC 6238 Appendix B test vectors before trusting it. |
| Memory locking | `region` crate (cross-platform mlock/VirtualLock wrapper) | Prevents secrets from being paged to disk. |
| Serialization | `serde` + `bincode` or `serde_json` | JSON for human-debuggable dev builds, bincode for production compactness. |

### Key hierarchy

```
Master Password
      │  Argon2id(password, per-vault random salt)
      ▼
Master Key (32 bytes, held only in memory, zeroized on lock)
      │  used to encrypt/decrypt a random-generated
      │  "Vault Key" stored (encrypted) in the vault header
      ▼
Vault Key (32 bytes) — actually encrypts each entry
```

**Why the extra indirection (Master Key wraps Vault Key, rather than Master Key encrypting entries directly)?**
This lets you change your master password later **without re-encrypting every entry** — you just re-wrap the Vault Key. Standard pattern used by Bitwarden/1Password internally. Worth doing from day one; retrofitting it later means a painful migration.

### On-disk vault format (per entry, conceptually)

```rust
struct VaultHeader {
    kdf_salt: [u8; 16],
    kdf_params: Argon2Params,
    wrapped_vault_key: Vec<u8>,   // Vault Key encrypted under Master Key
    wrapped_vault_key_nonce: [u8; 24],
}

struct Entry {
    id: Uuid,
    entry_type: EntryType,        // Password | Totp | Note | Card | SshKey
    ciphertext: Vec<u8>,          // encrypted serialized entry data
    nonce: [u8; 24],
    version: u64,                 // for sync conflict resolution
    modified_at: i64,             // unix timestamp
}
```

Each entry encrypted **independently** — a corrupted or lost entry never takes down the whole vault, and it's what makes sync sane (you sync individual entries, not a monolithic blob).

---

## 5. TOTP Module (RFC 6238)

This is genuinely the simplest correct-by-construction piece, and a good first milestone.

**Algorithm summary:**
1. Decode the base32 secret (the "seed" you get when scanning a QR code).
2. Compute `T = floor(current_unix_time / 30)` (30-second step is standard).
3. `HMAC = HMAC-SHA1(secret, T as 8-byte big-endian)`.
4. Dynamic truncation → 6-digit code (RFC 4226 §5.3).
5. Regenerate every 30s; display with a countdown.

**Test against RFC 6238 Appendix B vectors before trusting your implementation against a real account** — it gives you known secret/time/code triples so you can unit-test deterministically.

**Storage:** the TOTP seed (base32 secret) is just another `Entry` type in your vault — same encryption path as passwords. No special-casing needed in the crypto layer.

**QR code import:** `otpauth://` URI parsing (what QR codes for 2FA encode) — a simple `otpauth-uri` parser. Use `image` + `rqrr` crates if you want to scan QR codes from screenshots rather than typing 32-char secrets by hand.

---

## 6. Sync Protocol (Zero-Knowledge)

**Core rule: the server is a dumb encrypted key-value store. It never sees plaintext, never sees keys.**

```
Client                              Server
  │  POST /entries/{id}                │
  │  { ciphertext, nonce, version,     │
  │    modified_at, hmac }             │
  ├────────────────────────────────────►
  │                                     │  stores blob, checks version
  │                                     │  is newer, rejects stale writes
  │  GET /entries?since={timestamp}     │
  ├────────────────────────────────────►
  │◄────────────────────────────────────┤
  │  [ encrypted entries changed        │
  │    since last sync ]                │
```

- **Auth to the server itself**: separate from your vault password. Use a device-specific keypair (`ed25519`) generated on first setup, registered with the server. Server never sees your master password — that's purely local.
- **Transport**: server bound only to your Tailscale interface (`tailscale0` / the 100.x.x.x address) — never exposed publicly. This alone eliminates most realistic attack surface, and you already have the Tailscale infra from the Minecraft server project.
- **Conflict resolution**: last-write-wins per entry, using `modified_at`. Fine for a single-user, two-device setup — don't over-engineer with CRDTs.
- **Integrity**: HMAC over each ciphertext blob using a key derived from your Vault Key, so a compromised server can't tamper with entries undetected (it can delete/withhold, but not silently modify).

---

## 7. Build Phases

Work through these in order. Each phase should have passing tests before you move to the next — this is the one project where "ship fast and fix later" is the wrong instinct.

### Phase 1 — Core crypto primitives (`vaultrs-core::crypto`)
- Argon2id key derivation wrapper
- XChaCha20-Poly1305 encrypt/decrypt wrapper
- Zeroize integration on all secret-holding types
- Unit tests with known test vectors

### Phase 2 — Vault storage (`vaultrs-core::vault`, `store`)
- Entry model + on-disk format (serde)
- Master key ↔ Vault key wrapping
- Add/read/update/delete entry (local only, no sync yet)
- Vault file save/load round-trip tests

### Phase 3 — TOTP (`vaultrs-core::totp`)
- RFC 6238 implementation
- Validate against RFC test vectors
- `otpauth://` URI parsing for QR import

### Phase 4 — CLI (`vaultrs-cli`)
- `vaultrs init` — create new vault, set master password
- `vaultrs unlock` — derive key, hold session (with timeout)
- `vaultrs add/get/list/rm`
- `vaultrs totp <name>` — print current code + countdown
- Auto-lock after N minutes idle

### Phase 5 — Sync server (`vaultrs-server`)
- axum server, entry storage (sqlite backend fine)
- Device registration (ed25519 keypairs)
- Push/pull endpoints with version checks
- Bind to Tailscale interface only

### Phase 6 — Client sync integration
- `vaultrs sync` command
- Conflict resolution logic
- End-to-end test: add entry on Linux, sync, read on Windows

### Phase 7 — Hardening pass
- Memory locking (`region` crate)
- Fuzz testing the parsers (`cargo-fuzz`) — especially the `otpauth://` URI parser and vault file deserialization, since those parse untrusted/external input
- Dependency audit (`cargo audit`)
- Threat model re-review

### Phase 8 — GUI (optional, later)
- Tauri app wrapping `vaultrs-core`
- Only after CLI + sync are solid and battle-tested by your own daily use

---

## 8. Key Design Decisions Worth Locking In Early

1. **Per-entry encryption, not whole-vault encryption.** Enables partial sync and limits blast radius of corruption.
2. **Key wrapping (Master Key wraps Vault Key).** Enables password changes without full re-encryption.
3. **Zero-knowledge sync server.** Non-negotiable given your stated goal (bank-account-level trust).
4. **No recovery mechanism.** Document this loudly in your own README — zero-knowledge means if you forget the master password, the vault is unrecoverable by design. That's the cost of the security model.
5. **Tailscale-only server exposure.** Free, and you already have it running — don't build a public-facing auth system when you don't need one.

---

## 9. Recommended Reading Before You Start

- RFC 6238 (TOTP) and RFC 4226 (HOTP) — short, precise, worth reading directly rather than trusting a summary.
- Argon2 RFC 9106 — for parameter selection guidance.
- Bitwarden's published security whitepaper — a good real-world reference for the key-wrapping pattern above.
- `zeroize` crate docs — the `Zeroize`/`ZeroizeOnDrop` derive macros, use them liberally.

---

## 11. VPS Hardening (Server Host, Not Just the App)

Zero-knowledge sync means a compromised server can't read your secrets — but it can still serve stale/malicious data, deny access, log metadata (sync timing, source IPs, blob sizes), or get used as a pivot point. Harden the host itself:

1. **No public exposure.** Bind the server to the Tailscale interface (`100.x.x.x`) only, never `0.0.0.0`. This alone removes almost all realistic attack surface.
2. **SSH hardening.** Key-based auth only, `PermitRootLogin no`, ideally SSH itself only reachable over Tailscale too.
3. **Firewall.** Default-deny inbound (`ufw`/`nftables`); allow only Tailscale (+ SSH if not already Tailscale-only).
4. **Automatic security updates** (`unattended-upgrades` on Debian/Ubuntu) — OS-level CVEs are the realistic attack path, not your Rust code.
5. **Run as unprivileged user.** Dedicated `vaultrs` user or `systemd` `DynamicUser=yes`, never root.
6. **Systemd sandboxing.** `ProtectSystem=strict`, `PrivateTmp=yes`, `NoNewPrivileges=yes` — limits blast radius of any bug in the axum server itself.
7. **Disk encryption (LUKS).** Mostly protects against physical/hypervisor snapshot theft — cheap insurance given data's already ciphertext.
8. **Back up the encrypted blob store regularly.** No password recovery by design (section 8) — losing server data with no local copy means losing everything. Safe to back up as ciphertext.
9. **Rate limit sync endpoints** — blunts abuse if a device key ever leaks.
10. **Monitoring.** `journalctl`/`auditd` for anomalies — unexpected login times or source IPs, even within the tailnet.

**Recommendation:** keep the server on a small, cheap VPS (e.g. Hetzner/Contabo, ~$4–6/mo), physically separate from your daily-driver desktop — not on the same machine you browse/game on. That separation is a real security property: if your desktop gets compromised again, the sync server isn't on the same blast radius.

---

## 13. Mobile Client (Phase 9 — after desktop + sync are solid)

Full vault access + TOTP codes on your phone, same as desktop — standard for password managers (Bitwarden, 1Password, KeePass all work this way). `vaultrs-core` is already platform-agnostic Rust, so mobile becomes a **fourth client** talking to the same core logic and sync server, alongside Linux/Windows.

**Two paths to get the Rust core onto a phone:**

| Approach | How it works | Tradeoff |
|---|---|---|
| **Tauri Mobile** | `vaultrs-core` wrapped in a Tauri app targeting Android/iOS, UI in web tech or `egui` | Newer, less battle-tested on mobile than desktop Tauri; keeps everything in one Rust codebase |
| **UniFFI bindings** | Compile `vaultrs-core` as a static lib, generate Kotlin/Swift bindings via Mozilla's `uniffi-rs`, native UI in Kotlin (Android) / Swift (iOS) | More work (two native UIs), but native UI feels better day-to-day; this is what Mozilla/Signal use in production for exactly this pattern |

**Recommendation: UniFFI.** Native UI matters for something opened multiple times a day, and `uniffi-rs` is purpose-built for "share Rust core, write native UI per platform" — a proven pattern, not experimental.

**QR scanning for new TOTP entries:** camera access (`android.hardware.camera2` / `AVFoundation`) + a QR decode library (or `rqrr`/`zbar` routed through Rust), parse the `otpauth://` URI, hand it to `vaultrs-core` to store. Same flow as any authenticator app's "add account."

**Mobile secure storage:** Android Keystore / iOS Keychain — a different security model than the desktop vault file. This needs its own design pass; don't assume the desktop on-disk format ports 1:1. At minimum, the Master Key (section 4) should be backed by hardware-backed keystore APIs where available, not just app-sandboxed file storage.

**Why this is sequenced last, not first:**
- Mobile secure storage is a different model than desktop — needs dedicated design, not a straight port.
- Core crypto/sync logic should be proven correct on desktop before debugging two additional mobile platforms on top of it.
- Realistically another 3–4 weeks minimum, given learning UniFFI plus at least one of Kotlin/Swift, on top of everything else.

---

## 14. References

**Core crypto (Phase 1)**
- RFC 9106 (Argon2) — read the parameter selection section closely
- `argon2` and `chacha20poly1305` crate docs (docs.rs) — note `XChaCha20Poly1305` vs `ChaCha20Poly1305`, use the X variant
- `zeroize` crate docs — the `ZeroizeOnDrop` derive macro
- RustCrypto project (github.com/RustCrypto) — README context often better than docs.rs alone

**TOTP (Phase 3)**
- RFC 6238 (TOTP) and RFC 4226 (HOTP, dynamic truncation in Appendix D)
- RFC 6238 Appendix B — test vectors, use directly in unit tests

**Server/sync (Phase 5)**
- axum docs + examples repo (github.com/tokio-rs/axum/tree/main/examples) — `sqlite` and `jwt` examples are close analogues
- `ed25519-dalek` crate docs — device keypair auth
- Tailscale docs on ACLs and Serve/Funnel (tailscale.com/kb) — binding the server to the tailnet only

**Real-world reference architecture**
- Bitwarden Security Whitepaper (bitwarden.com/help/bitwarden-security-white-paper) — closest real-world match to this design's key-wrapping pattern
- KeePass KDBX format spec — comparison point for on-disk vault format
- 1Password Security design docs (1password.com/security) — "Secret Key" architecture, good even though not implementing that exact scheme

**Rust-specific**
- The Rust Book, ch. 14 (Cargo workspaces) — doc.rust-lang.org/book
- `cargo-fuzz` book (rust-fuzz.github.io/book) — Phase 7 fuzzing
- RustSec Advisory Database (rustsec.org) — what `cargo audit` checks against

**VPS hardening**
- Mozilla OpenSSH guidelines (infosec.mozilla.org/guidelines/openssh)
- Tailscale "securing your tailnet" docs (kb.tailscale.com) — ACLs, key expiry, device approval

**Mobile (Phase 9)**
- `uniffi-rs` documentation and Mozilla's usage examples (Firefox Sync, Application Services)
- Android Keystore system docs (developer.android.com)
- Apple Keychain Services docs (developer.apple.com)

---

## 15. Additional Considerations

Things that matter in practice beyond the core phases — some belong in v1, some are deliberate later additions, flagged accordingly.

### 15.1 Clipboard handling (v1)
Copied passwords sit in the OS clipboard in plaintext until overwritten — Windows clipboard history (Win+V) can persist them indefinitely otherwise. Auto-clear the clipboard ~20-30 seconds after a copy. The `arboard` crate handles this cross-platform.

### 15.2 Password generator (v1)
Storing existing passwords isn't enough — you need to *generate* strong ones, or you're back to reuse. Configurable charset/length via `rand`. Build alongside the CLI in Phase 4, not bolted on later.

### 15.3 Master password change / key rotation flow (v1, design explicitly)
Section 4's Master Key → Vault Key wrapping makes rotation *cheap*, but the flow itself still needs explicit design:
- Verify old password before allowing a change
- Derive new Master Key, re-wrap Vault Key under it
- Decide behavior if sync happens mid-rotation (safest: block sync until rotation completes and is confirmed written to disk)

### 15.4 Session / auto-lock details (v1)
"Auto-lock after N minutes idle" needs to also cover:
- Lock on system sleep/suspend (hook OS sleep events)
- Lock on lid close
- Manual `vaultrs lock` command for stepping away immediately

### 15.5 Hardware key support — YubiKey/FIDO2 (Phase 7/8, plan the hook now)
An optional second factor to unlock the vault *itself* (distinct from TOTP codes stored inside it) meaningfully raises the bar for bank-account-level trust. `yubikey` crate or generic FIDO2/WebAuthn via `ctap-hid-fido2`. Not v1, but worth designing the Master Key derivation so a hardware-backed factor can be folded in later without reworking the format.

### 15.6 Secure backup / export (v1)
A way to export an encrypted vault copy independent of the sync server (USB drive, etc.) — so a server loss with no local copy doesn't mean total loss. Ties into section 11's server-side backup point, but this is the client-side half of the same problem.

### 15.7 Testing strategy beyond unit tests (v1, especially crypto path)
Property-based testing (`proptest` crate) for encrypt/decrypt round-trips and vault serialization — catches edge cases fixed-input unit tests miss. Apply specifically to the crypto and store modules, since that's the security-critical path.

### 15.8 Supply chain hygiene (Phase 7)
~15-20 dependency crates for this project. Beyond `cargo audit` (section on Phase 7): pin the lockfile (`Cargo.lock` committed, not gitignored) and consider `cargo vendor` so a compromised crate update doesn't silently pull in malicious code between builds. Directly relevant given the Discord/Steam compromise was likely a supply-chain-adjacent or stealer-malware vector.

### 15.9 An honest note on realistic risk
An unaudited, solo-built crypto tool — however carefully designed — is **not** provably safer than Bitwarden or KeePassXC (both open-source, audited, battle-tested by many hostile eyes) for actual bank account credentials, at least not until it's been running and reviewed for a long while. Treat VaultRS as the daily driver for learning and lower-stakes secrets first. Graduate it to bank-level trust only after it's been solid for months — ideally after someone else has reviewed the crypto code, not just yourself.

---

## 16. Immediate Next Step

Start Phase 1. Build `vaultrs-core::crypto` in isolation — a `Vault` struct isn't needed yet, just:

```rust
pub fn derive_master_key(password: &[u8], salt: &[u8]) -> Result<[u8; 32], Error>
pub fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<(Vec<u8>, [u8; 24]), Error>
pub fn decrypt(key: &[u8; 32], ciphertext: &[u8], nonce: &[u8; 24]) -> Result<Vec<u8>, Error>
```

Get these three functions correct and thoroughly tested first. Everything else in the project builds on top of them being right.
