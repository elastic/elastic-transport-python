# AGENTS.md

Node behavior changes cover sync and async.

- Sync: `Urllib3HttpNode`, `RequestsHttpNode`
- Async: `AiohttpHttpNode`, `HttpxAsyncHttpNode`
- `HttpxHttpNode` is the sync httpx node. Update its guard when a feature cannot be expressed there.

Tests: `nox -s test`. Lint: `nox -s lint`.

## TLS and `ssl_assert_fingerprint`

Shared logic lives in `elastic_transport/_node/_ca_fingerprint.py`. Keep these invariants:

- The pin must verify signatures. A digest match alone is never enough: the pinned cert is the only trust anchor of a `CERT_REQUIRED` context. A forged leaf that names the real CA as its issuer must fail.
- Fail closed. Before the pin exists, no request may reach the server without it. This covers `RequestsHttpNode`'s `_UnpinnedAdapter` and the aiohttp https-context assert. Never fall back to `ssl=False`, `CERT_NONE`, or a default adapter.
- The probe handshake sends the client cert on purpose, because mTLS servers reject a probe without it. `test_probe_presents_the_client_cert` covers this.
- `TlsError` is in `RERAISE_EXCEPTIONS`, so node `except Exception` blocks don't rewrap it.
- Python 3.10 is the floor. The private `_sslobj.get_unverified_chain` fallback is still needed below 3.13.
- Security tests use a real local TLS server. Assert `server.hits == 0` and no auth header on rejection, not only that an error was raised.
