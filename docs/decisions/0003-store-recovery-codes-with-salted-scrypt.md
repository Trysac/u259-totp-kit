# Store recovery codes with per-entry salted scrypt

Status: accepted (generated, pending human review)

## Context

A recovery code carries only 40 bits of entropy because it is derived from five random bytes. Storing a single unsalted SHA-256 digest of the normalized code makes the whole code space enumerable offline in minutes, and because there is no salt a table can be precomputed once and reused against every user or every leaked backup. Serialized data (`to_json()`) can leak through backups, logs, replicated databases or snapshots, so the stored representation must be expensive to attack.

## Decision

Each recovery code is stored as a self-contained 32-byte value encoded as 64 hex characters: a random 16-byte per-entry salt followed by a 16-byte tag from `hashlib.scrypt(n=2**14, r=8, p=1, dklen=16)` over the normalized code. The existing 64-character JSON shape is preserved, but the value is no longer a fast digest. `consume` derives the candidate with each entry's salt and compares all entries with `hmac.compare_digest`. `from_codes` and `from_json` also accept an optional server-side `pepper`, mixed in with HMAC-SHA-256, for callers that can keep a secret outside the datastore.

## Consequences

Serializing and consuming a code is intentionally slower, which is acceptable because recovery codes are used rarely. The 40-bit code space is still small in absolute terms, so applications must rate-limit recovery attempts and protect backups; the KDF and per-entry salt make offline enumeration of a leaked set impractical rather than merely inconvenient.
