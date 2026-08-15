# Crypto Options for Fixed-Volume Cellization

Status: advisory dependency/security evaluation

Owner: `crypto_options` lane
Scope: standard/reviewed cryptographic constructions and Linux software for fixed-volume cells between Vision and the Tofino onboard CPU, with no P4 cryptography and no live state changes.

## Recommendation

Use a small fixed-record cell layer whose cryptographic primitive is a reviewed AEAD API, not a hand-written cipher or MAC. For S3 offline work and the first live shim prototype, the best default is:

- record format and padding policy owned by the Defense 4 shim;
- AEAD from `cryptography` if both endpoints have Python >=3.9 and the package is present or can later be installed;
- ChaCha20-Poly1305 as the default software cipher unless local CPU checks prove AES-GCM acceleration on both endpoints;
- per-direction session keys, monotonic counters as nonces, replay windows, and explicit epoch/rekey rules in the record layer;
- optional WireGuard only as an outer peer-authenticated transport after S2, not as the size-hiding mechanism by itself.

Reason: WireGuard and IPsec solve peer authentication, key exchange, replay protection, and packet confidentiality, but they do not by themselves make the DNP3 transcript constant length. The size-normalization property still comes from the shim emitting exactly the same fixed cell count and fixed cell size per protected epoch. A normal tunnel around variable inner packets would still leak size through variable ciphertext packet sizes.

For the defined TCP-aware passive observer on the Vision-to-Tofino stream, the accept/reject rule is strict: the observer must see a fixed outer cell transcript before any parseable DNP3/TCP byte count is available. Software AEAD is acceptable only if the observed stream carries opaque fixed cells, not the original DNP3 TCP stream. A tunnel is acceptable only if the plaintext fed into it is already fixed-size fixed-count cells and tunnel control packets are excluded from, or made constant within, the protected epoch.

## Candidate Comparison

| Candidate | Maintenance / license evidence | Security fit | Size-hiding fit | Endpoint and CPU fit | Verdict |
| --- | --- | --- | --- | --- | --- |
| Fixed records using `cryptography` AEAD (`ChaCha20Poly1305` or `AESGCM`) | PyPI lists `cryptography` 49.0.0 released 2026-06-12, owned by Python Cryptographic Authority, license `Apache-2.0 OR BSD-3-Clause`, Python >=3.9. Downloads/week are not published by PyPI, so I did not use third-party counters under the primary-source-only constraint. | Good if nonce uniqueness and rekey are specified. The docs expose AEAD APIs; ChaCha20-Poly1305 is tied to the RFC construction. AES-GCM is a NIST-specified AEAD mode but IV uniqueness must be enforced. | Excellent. The shim can encrypt true length/type/index and random padding inside a constant-size plaintext record, then emit fixed-size ciphertext records. | Likely enough for DNP3 rates. Needs local verification of Python version, package presence, OpenSSL support, and CPU flags. | Primary choice for S3/S4 if endpoint software supports it. |
| Fixed records using PyNaCl/libsodium AEAD (`Aead` / XChaCha20-Poly1305) | PyPI lists PyNaCl 1.6.2 released 2026-01-01, Apache-2.0, Python >=3.8; libsodium releases show 1.0.22 released 2026-04-10 and ISC license. | Good. PyNaCl `Aead` uses XChaCha20-Poly1305, supports AAD, and documents nonce uniqueness/replay-counter use. XChaCha makes random nonces safer, but a deterministic per-direction counter is still better for replay and trace debugging. | Excellent, same fixed-record pattern as above. | Better if endpoints are stuck on Python 3.8. Bundled/native dependency must be verified on the Tofino CPU architecture and OS. | Strong fallback if `cryptography` is unavailable or Python 3.8 compatibility dominates. |
| Fixed-size plaintext records inside WireGuard | Official WireGuard protocol uses Noise_IK, ChaCha20-Poly1305, counters, replay window, and periodic rekey; official install page lists current Linux tools packages. WireGuard kernel components and tools are GPLv2. | Very good for tunnel security and replay/rekey semantics. | Good only if the shim sends constant-size inner packets into the tunnel and the evaluation accounts for handshake/keepalive/rekey packets. WireGuard data packets otherwise reveal encapsulated packet length plus overhead/padding. | Requires root/network configuration and verified `wg`/kernel support on Vision and Tofino CPU. Kernel path likely faster than user-space AEAD, if available. | Secondary transport option, not sufficient alone. |
| Fixed-size plaintext records inside IPsec ESP / strongSwan | ESP is an IETF standard with anti-replay and TFC padding support in RFC 4303. strongSwan lists current release 6.0.7 from 2026-06-07, GPLv2/commercial license, and Linux support. | Strong if configured correctly; IKEv2 handles keying and SAs. | Potentially good, but ESP padding/TFC support and dummy traffic behavior must be verified locally. Standard ESP padding alone is alignment padding, not a fixed-epoch transcript guarantee. | More complex than WireGuard, higher configuration risk, root/network state required. | Keep as fallback if WireGuard is unavailable or IPsec is already provisioned. |
| Hardware offload / inline crypto | No local proof in this lane that the Vision NIC, Tofino CPU NIC, Tofino ASIC, or switch OS exposes usable IPsec/TLS/MACsec offload for this path. | Only acceptable if the actual hardware/software reports the feature and it can be driven with standard APIs. P4 must not implement crypto. | Unknown until verified; offload usually encrypts variable packets unless fixed records are still emitted. | Could improve CPU cost, but DNP3 rate likely does not need it. | Reject for S2 selection unless live read-only audit proves a specific offload path. |

## Record-Layer Requirements

The fixed-cell record should be specified independently of the chosen AEAD library:

- Each direction has a distinct session key and nonce/counter namespace.
- Nonce format is deterministic and unique, for example `direction_id || epoch_id || uint64 cell_counter`, with exact byte layout matched to the AEAD nonce size.
- `epoch_id`, protected transaction type, true inner length, cell index, total fixed policy parameters, and padding boundary are encrypted or authenticated as appropriate. Public AAD should be limited to values already fixed across the policy domain, such as protocol version and declared cell size.
- Receiver keeps a replay window per direction/epoch and rejects duplicate or stale counters after tag verification.
- Rekey occurs before counter exhaustion and on explicit epoch rollover. Counters must never roll back after restart under the same key; the simpler rule is fresh ephemeral/session keys for each test run and zeroed counters.
- Loss/reordering behavior is part of the security design: either fixed cells are transported over a reliable channel whose retransmissions are outside the protected observation point, or the observed transcript includes the same retransmission/timing policy for all protected messages. Variable retransmission counts visible to the observer would break the size transcript claim.
- Cover cells are cryptographically valid records with encrypted type/length fields; they must be indistinguishable from data cells to anyone without the key.

## AEAD Choice Notes

ChaCha20-Poly1305 is the safest software default when CPU acceleration is unknown. RFC 8439 defines the AEAD construction and warns that nonce reuse under a key exposes plaintext relationships and enables forgery risk. It performs well without AES-specific CPU instructions.

AES-GCM is attractive only if both endpoints expose AES and carry-less multiplication acceleration. NIST SP 800-38D specifies GCM/GMAC; NIST also notes the critical importance of IV uniqueness. If either endpoint lacks AES acceleration, ChaCha20-Poly1305 is usually the lower-risk implementation choice for a userspace shim.

PyNaCl/libsodium is attractive if Python 3.8 compatibility is needed on the Tofino CPU. Its `Aead` API uses XChaCha20-Poly1305 and supports AAD. The downside is that it introduces a native/bundled libsodium dependency that must be proven on the switch CPU OS before making it the selected live path.

## Tunnel Choice Notes

WireGuard is useful if the design wants standard peer authentication, key exchange, replay windows, and rekeying without implementing those parts in the shim. Its official protocol describes ChaCha20-Poly1305 data packets, a 64-bit counter, replay window handling, and timed/message-count rekeying. However, the same protocol describes encrypted encapsulated packet length as a function of the encapsulated packet, so fixed-size inner packets are still mandatory. Handshake, keepalive, and rekey packets are separate visible events; S2 must either exclude them from the measured protected epoch or schedule/account for them.

IPsec ESP is useful if the lab already has strongSwan/XFRM support or if an evaluator prefers standards-track IPsec. RFC 4303 includes anti-replay services and Traffic Flow Confidentiality features, including dummy traffic and extra payload padding, but also notes TFC effectiveness depends on sufficient masking traffic and gateway/tunnel placement. Because Linux/strongSwan TFC behavior can be distribution- and configuration-dependent, it should not be selected without a local proof.

## Local Verification Needed

Run only read-only checks during S1/S2:

- On Vision and Tofino CPU: `python3 --version`; import `cryptography`, `ChaCha20Poly1305`, and `AESGCM`; print `cryptography.__version__` and OpenSSL backend version.
- If Python <3.9 or `cryptography` is absent: import `nacl.secret.Aead`, print `nacl.__version__`, and confirm libsodium version if exposed.
- Check CPU suitability: `lscpu` flags for `aes`, `pclmulqdq`, `avx`, and architecture; if benchmarked later, use a non-live synthetic buffer outside S0-S2.
- Check tunnel availability without changing state: `wg --version`, `ip link help` support for `wireguard`, kernel module presence if allowed; for IPsec, `ip xfrm state`, `swanctl --version`, and `ipsec --version`.
- Check hardware offload without enabling it: `ethtool -k <candidate-iface>`, `ethtool --show-priv-flags <candidate-iface>`, driver/firmware via `ethtool -i`, and any vendor-exposed IPsec/TLS/MACsec offload flags.
- Confirm the Tofino CPU port path separately. Crypto feasibility is irrelevant unless fixed cells can cross the observed link and be decapsulated at the relay edge using only the existing switch/control CPU.

## Dependency Risk

- `cryptography` latest requires Python >=3.9, while older repo harness notes mention CPython 3.8 for existing DNP3 tooling. This is not a blocker for a new shim, but it is a live endpoint compatibility check.
- PyNaCl supports Python >=3.8 but adds a libsodium/native packaging surface.
- WireGuard/IPsec require privileged network configuration and will alter routing/interface state during S4+, so they belong after the S2 approval gate.
- Any approach with visible variable-length TCP retransmissions, tunnel handshakes inside measurement windows, or adaptive retransmission counts cannot support the stated `I(L; ObsSize) ~= 0` claim without a fixed schedule model.

## Sources

- `cryptography` AEAD docs: https://cryptography.io/en/stable/hazmat/primitives/aead/
- `cryptography` PyPI metadata: https://pypi.org/project/cryptography/
- RFC 8439, ChaCha20-Poly1305 AEAD: https://www.rfc-editor.org/info/rfc8439/
- NIST SP 800-38D, AES-GCM/GMAC: https://csrc.nist.gov/pubs/sp/800/38/d/final
- PyNaCl docs: https://pynacl.readthedocs.io/en/latest/secret/
- PyNaCl PyPI metadata: https://pypi.org/project/PyNaCl/
- libsodium AEAD docs: https://doc.libsodium.org/secret-key_cryptography/aead/chacha20-poly1305
- libsodium releases/license: https://github.com/jedisct1/libsodium/releases and https://github.com/jedisct1/libsodium
- WireGuard protocol: https://www.wireguard.com/protocol/
- WireGuard repositories/license: https://www.wireguard.com/repositories/ and https://www.wireguard.com/
- WireGuard install versions: https://www.wireguard.com/install/
- RFC 4303, IPsec ESP and TFC: https://www.rfc-editor.org/rfc/rfc4303.html
- strongSwan release/license/docs: https://strongswan.org/download.html, https://www.strongswan.org/license.html, https://docs.strongswan.org/docs/latest/index.html
