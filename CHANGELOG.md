# Changelog

## 8.11.0

- Always set default HTTPS port to 443 (#127)
- Drop support for Python 3.6 (#109)
- Include tests in sdist (#122, contributed by @parona-source)
- Fix `__iter__` return type to Iterator (#129, contributed by @altescy)

## 8.10.0

- Support urllib3 2.x in addition to urllib3 1.26.x ([#121](https://github.com/elastic/elastic-transport-python/pull/121))
- Add 409 to `NOT_DEAD_NODE_HTTP_STATUSES` ([#120](https://github.com/elastic/elastic-transport-python/pull/120))

## 8.4.1

- Fixed an issue where a large number of consecutive failures to connect to a node would raise an `OverflowError`.
- Fixed an issue to ensure that `ApiResponse` can be pickled.

## 8.4.0

### Added

- Added method for clients to use default ports for URL scheme.

## 8.1.2

### Fixed

- Fixed issue when connecting to an IP address with HTTPS enabled would result in a `ValueError` for a mismatch between `check_hostname` and `server_hostname`.

## 8.1.1

### Fixed

- Fixed `JsonSerializer` to return `None` if a response using `Content-Type: application/json` is empty instead of raising an error.

## 8.1.0

### Fixed

- Fixed `Urllib3HttpNode` and `RequestsHttpNode` to never require a valid certificate chain when using `ssl_assert_fingerprint`. Instead the internal HTTP client libraries will explicitly disable verifying the certificate chain and instead rely only on the certificate fingerprint for verification.

## 8.0.1

### Fixed

- Fixed `AiohttpHttpNode` to close TLS connections that aren't properly shutdown by the server instead of leaking them
- Fixed `Urllib3HttpNode` to respect `path_prefix` setting in `NodeConfig`

## 8.0.0

### Added

- Added support for asyncio with `AsyncTransport` and `AiohttpHttpNode`
- Added `JsonSerializer`, `NdjsonSerializer`
- Added `connections_per_node` parameter to `RequestsHttpNode`
- Added support for `ssl_assert_fingerprint` to `RequestsHttpNode`
- Added **experimental** support for pinning non-leaf certificates
  via `ssl_assert_fingerprint` when using CPython 3.10+
- Added support for node discovery via "sniffing" using the
  `sniff_callback` transport parameter
- Added ability to specify `ssl_version` via `ssl.TLSVersion` enum
  instead of `ssl.PROTOCOL_TLSvX` for Python 3.7+
- Added `elastic_transport.client_utils` module to help writing API clients
- Added `elastic_transport.debug_logging` method to enable all logging for debugging purposes
- Added option to set `requests.Session.auth` within `RequestsHttpNode` via `NodeConfig._extras['requests.session.auth']`

### Changed

- Changed `*Connection` classes to use `*Node` terminology
- Changed `connection_class` to `node_class`
- Changed `ConnectionPool` to `NodePool`
- Changed `ConnectionSelector` to `NodeSelector`
- Changed `NodeSelector(randomize_hosts)` parameter to `randomize_nodes`
- Changed `NodeSelector.get_connection()` method to `get()`
- Changed `elastic_transport.connection` logger name to `elastic_transport.node`
- Changed `Urllib3HttpNode(connections_per_host)` parameter to `connections_per_node`
- Changed return type of `BaseNode.perform_request()` to `NamedTuple(meta=ApiResponseMeta, body=bytes)`
- Changed return type of `Transport.perform_request()` to `NamedTuple(meta=ApiResponseMeta, body=Any)`
- Changed name of `Deserializer` into `SerializersCollection`
- Changed `ssl_version` to denote the minimum TLS version instead of the only TLS version
- Changed the base class for `ApiError` to be `Exception` instead of `TransportError`.
  `TransportError` is now only for errors that occur at the transport layer.
- Changed `Urllib3HttpNode` to block on new connections when the internal connection pool is exhausted

### Removed

- Removed support for Python 2.7
- Removed `DummyConnectionPool` and `EmptyConnectionPool` in favor of `NodePool`.

### Fixed

- Fixed a work-around with `AiohttpHttpNode` where `method="HEAD"` requests wouldn't mark the internal connection as reusable. This work-around is no longer needed when `aiohttp>=3.7.0` is installed.
- Fixed logic for splitting `aiohttp.__version__` when determining if `HEAD` bug is fixed.

## 7.15.0 (2021-09-20)

Release created to be compatible with 7.15 clients

## 7.14.0 (2021-08-02)

Release created to be compatible with 7.14 clients

## 7.13.0 (2021-05-24)

Release created to be compatible with 7.13 clients

## 7.12.0 (2021-03-22)

Release created to be compatible with 7.12 clients

## 7.11.0 (2021-02-10)

### Added

- Added the `X-Elastic-Client-Meta` HTTP header ([PR #4](https://github.com/elastic/elastic-transport-python/pull/4))
- Added HTTP response headers to `Response` and `TransportError`
  ([PR #5](https://github.com/elastic/elastic-transport-python/pull/5))
- Added the `QueryParams` data structure for representing
  an ordered sequence of key-value pairs for the URL query
  ([PR #6](https://github.com/elastic/elastic-transport-python/pull/6))

### Changed

- Changed `Connection.perform_request()` to take `target` instead of
  `path` and `params`. Instead `path` and `params` are created within
  `Transport.perform_request()` ([PR #6](https://github.com/elastic/elastic-transport-python/pull/6))

## 0.1.0b0 (2020-10-21)

- Initial beta release of `elastic-transport-python`
