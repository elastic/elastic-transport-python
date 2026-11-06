# AGENTS.md

Node behavior changes cover sync and async.

- Sync: `Urllib3HttpNode`, `RequestsHttpNode`
- Async: `AiohttpHttpNode`, `HttpxAsyncHttpNode`
- `HttpxHttpNode` is the sync httpx node. Update its guard when a feature cannot be expressed there.

Tests: `nox -s test`. Lint: `nox -s lint`.
