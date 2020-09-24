# elastic-transport-python

Transport classes and utilities shared among Python Elastic client libraries

## Architecture

This library was lifted from `elasticsearch-python`
and then transformed to be used across all Elastic services
rather than only Elasticsearch.

`elastic-transport` is designed with the following
separation of responsibilities between it and
client libraries that utilize it:

`elastic-transport` handles the following features:
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
using `elastic-transport` simple, such as `connection_class="requests"`
instead of `connection_class=elastic_transport.RequestsHttpConnection`.
Only power users should need to ever `import elastic_transport` while
using a client library.


## License

```
Copyright 2020 Elasticsearch B.V

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```
