# Changelog

## 8.0.0-alpha6

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
- Changed return type of `BaseNode.perform_request()` to `Tuple[ApiResponseMeta, bytes]`
- Changed return type of `Transport.perform_request()` to `Tuple[ApiResponseMeta, <deserialized>]`
- Changed name of `Deserializer` into `SerializersCollection`
- Changed `ssl_version` to denote the minimum TLS version instead of the only TLS version

### Removed

- Removed support for Python 2.7
- Removed `DummyConnectionPool` and `EmptyConnectionPool` in favor of `NodePool`.

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
