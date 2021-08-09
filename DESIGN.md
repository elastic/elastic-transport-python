# Design / Architecture

`elastic-transport-python` is designed with the following
separation of responsibilities between it and
client libraries that utilize it:

`elastic-transport-python` handles the following features:
- Connecting to a scheme, host, and port
- TLS and certificate config
- Connection pooling
- Failover and retries
- Sniffing (TODO)

Client libraries must handle the following:
- Authentication
- User-Agent
- Specific serialization patterns (datetimes, params, url path)
- Default ports, specific connection mechanisms (like Elastic Cloud ID)
- Acting on specific HTTP headers (e.g the `Warning` header)

Client libraries should document patterns that make
using `elastic-transport-python` simple, such as `node_class="requests"`
instead of `node_class=elastic_transport.RequestsHttpNode`.
Only power users should need to ever `import elastic_transport` while
using a client library.
