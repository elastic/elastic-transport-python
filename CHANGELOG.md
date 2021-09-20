# Changelog

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
