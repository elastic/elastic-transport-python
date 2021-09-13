# elastic-transport-python

[![PyPI](https://img.shields.io/pypi/v/elastic-transport)](https://pypi.org/elastic-transport)
[![Python Versions](https://img.shields.io/pypi/pyversions/elastic-transport)](https://pypi.org/elastic-transport)
[![PyPI Downloads](https://pepy.tech/badge/elastic-transport)](https://pepy.tech/project/elastic-transport)
[![CI Status](https://img.shields.io/github/workflow/status/elastic/elastic-transport-python/CI/main)](https://github.com/elastic/elastic-transport-python/actions)

Transport classes and utilities shared among Python Elastic client libraries

This library was lifted from [`elasticsearch-py`](https://github.com/elastic/elasticsearch-py)
and then transformed to be used across all Elastic services
rather than only Elasticsearch.

### Installing from PyPI

```
$ python -m pip install elastic-transport
```

Versioning follows the major and minor version of the Elastic Stack version and
the patch number is incremented for bug fixes within a minor release.

## User Guide

For almost all use-cases you should not need this library.
The below use-cases are the common ones:

### Creating your own Node Class

If you need to have custom behavior for a `Node` you can subclass the
base node class you want and then pass the class in via `node_class`:

```python
from elastic_transport import Urllib3HttpNode
from elastic_enterprise_search import EnterpriseSearch


class CustomHttpNode(Urllib3HttpNode):
    def perform_request(
        self,
        method,
        target,
        body=None,
        request_timeout=DEFAULT,
        ignore_status=(),
        headers=None,
    ): ...  # Custom HTTP behavior


# Create the Client with 'node_class' defined
client = EnterpriseSearch(
    ...,
    node_class=CustomHttpNode
)
```

The above also works for `NodePool` (via `node_pool_class`) and `Transport` (via `transport_class`).

## Nodes

A node describes a single instance of a service within a potentially larger cluster.
`elastic-transport-python` supports two HTTP client libraries:

### `Urllib3HttpNode`

This is the default node class. This node class uses [urllib3](https://urllib3.readthedocs.io)
to issue requests.

### `RequestsHttpNode`

This node class requires the [Requests](https://github.com/psf/requests)
library to be installed to use:
 
```bash
$ python -m pip install requests
```

This class is often useful when using libraries that integrate with Requests.
Read more about [Requests on Read the Docs](https://requests.readthedocs.io).

### Supported Node Options

The two node classes support a variety of options, some node classes
only support a subset of the total options:

| Option                 | Description                                                                                             | Default   | Supported by urllib3 | Supported by requests |
|------------------------|---------------------------------------------------------------------------------------------------------|-----------|----------------------|-----------------------|
| host                   | TCP host to connect                                                                                     | localhost | ✓                    | ✓                     |
| port                   | TCP port to connect                                                                                     |           | ✓                    | ✓                     |
| use_ssl                | Should connect via TLS/SSL?                                                                             | False     | ✓                    | ✓                     |
| url_prefix             | Path prefix for all requests                                                                            | ""        | ✓                    | ✓                     |
| request_timeout        | Default request timeout                                                                                 | 10.0      | ✓                    | ✓                     |
| headers                | HTTP headers to add to every request                                                                    | {}        | ✓                    | ✓                     |
| user_agent             | Default User-Agent HTTP header                                                                          | None      | ✓                    | ✓                     |
| connections_per_node   | Number of HTTP connections per Node                                                                     | 10        | ✓                    |                       |
| verify_certs           | Whether to verify server certificate                                                                    | True      | ✓                    | ✓                     |
| ca_certs               | CA certificates to use with TLS/SSL                                                                     | certifi   | ✓                    | ✓                     |
| client_cert            | Client certificate to present during TLS/SSL handshake                                                  | None      | ✓                    | ✓                     |
| client_key             | Client certificate key that goes with client_cert                                                       | None      | ✓                    | ✓                     |
| ssl_version            | Version of TLS/SSL to use                                                                               | None      | ✓                    |                       |
| ssl_assert_hostname    | Host to verify on the server TLS certificate. Set to False to disable certificate hostname verification | None      | ✓                    |                       |
| ssl_assert_fingerprint | Checksum to verify against the server TLS certificate                                                   | None      | ✓                    |                       |
| ssl_context            | Preconfigured SSLContext instance                                                                       | None      | ✓                    |                       |

## License

`elastic-transport-python` is available under the Apache-2.0 license.
For more details see [LICENSE](https://github.com/elastic/elastic-transport-python/blob/main/LICENSE).
