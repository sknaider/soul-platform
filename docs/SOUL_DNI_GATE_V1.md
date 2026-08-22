# SOUL Platform DNI Gate v1

SOUL Platform 0.7 consumes the fail-closed verifier from SOUL Core 0.5.
Bootstrap no longer creates `machine_soul_id` with `uuid4()`. It requires a
credential already emitted by the SOUL Identity Authority, verifies it, copies
the public credential/trust bytes into the private SOUL root, and derives the
machine identity from those signed bytes.

Both the DNI credential and the trust/revocation snapshot are signed by SOUL.
Core additionally pins the SIA public-key fingerprint in its package bytes;
an installer-controlled trust file or digest cannot introduce a new issuer.

Every production entry point loads `ProxySettings.from_toml()`, which verifies
the DNI before proxy, MCP, doctor, autostart, living-profile, or model wiring can
touch the persistent soul. The proxy passes the same credential and trust pin
into Core, so Platform cannot validate one identity while Core opens another.

Required bootstrap inputs (arguments or installer-provided environment):

- `SOUL_DNI_CREDENTIAL`
- `SOUL_DNI_TRUST_STORE`
- `SOUL_DNI_TRUST_STORE_SHA256`

Missing, forged, revoked, expired, wrong-audience, wrong-machine, or copied DNI
credentials fail before `MachineSoul.db` is created.

The installer also supports online issuance with the inseparable pair
`SOUL_DNI_SIA_ENDPOINT` + `SOUL_DNI_ENROLLMENT_TOKEN_FILE` (or
`--sia-endpoint` + `--sia-enrollment-token-file` on Unix, and `-SiaEndpoint` +
`-SiaEnrollmentTokenFile` on Windows). The one-use secret never appears in a
process argument. It generates a device-only Ed25519 key,
proves possession to SIA and obtains the three public bootstrap inputs. A
remote endpoint must use HTTPS except the pinned SOUL authority IP
`100.75.201.110`, whose HTTP transport exists only inside the encrypted
Tailscale overlay. Redirects are never followed, and no other remote HTTP IP
or DNS hostname is accepted. Preissued and online enrollment are mutually
exclusive.

## Thirty-day renewal contract

The SOUL identity is permanent, but its signed operating credential and signed
trust/revocation snapshot are valid for at most 30 days. Core revalidates the
credential before every persistent database operation (with a five-minute
verification cache bounded by expiry). Platform revalidates it on every HTTP
and MCP request. If renewal has not landed before expiry, Core stops touching
the database and Platform returns a fail-closed disconnected response.

The SIA renewal must keep the same `soul_dni`, `soul_id`,
`machine_soul_id`, machine binding, and authorized audiences while increasing
the signed sequence. `soul-machine renew-dni` verifies those invariants,
installs the public signed documents atomically, updates the trust digest, and
restarts the local descriptor. It never opens or rewrites `MachineSoul.db`.
An old sequence, another identity, invalid signature, revoked document, or
credential longer than 30 days is rejected.

Online installations additionally keep `soul-dni-authority.json` and the
private `soul-dni-device.pem` inside the canonical SOUL root. Proxy startup,
every MCP session, and a six-hour proxy watcher attempt renewal during the
seven-day safety window. A transient outage before expiry does not erase the
valid credential. At expiry, both Core and Platform disconnect until a signed
renewal succeeds; the model cannot bypass that decision.
