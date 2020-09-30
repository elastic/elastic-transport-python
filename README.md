# elastic-transport-python

Transport classes and utilities shared among Python Elastic client libraries

This library was lifted from [`elasticsearch-py`](https://github.com/elastic/elasticsearch-py)
and then transformed to be used across all Elastic services
rather than only Elasticsearch.

## User Guide

For almost all use-cases you should not need this library.
The below use-cases are the common ones:

### Creating your own Connection Class

If you need to have custom behavior for a `Connection` you can subclass the
base connection class you want and then pass the class in via `connection_class`:

```python
from elastic_transport import Urllib3HttpConnection
from elastic_enterprise_search import EnterpriseSearch


class CustomHttpConnection(Urllib3HttpConnection):
    ... # Custom HTTP behavior


# Create the Client with 'connection_class' defined
client = EnterpriseSearch(
    ...,
    connection_class=CustomHttpConnection
)
```

The above also works for `ConnectionPool` (via `connection_pool_class`) and `Transport` (via `transport_class`).

## Connection Classes

`elastic-transport-python` supports two HTTP client libraries:

### `Urllib3HttpConnection`

This is the default connection class. This connection class uses urllib3` to issue requests.
Read more about [urllib3 on Read the Docs](https://urllib3.readthedocs.io).

### `RequestsHttpConnection`

This connection class requires the [Requests](https://github.com/psf/requests)
library to be installed to use:
 
```bash
$ python -m pip install requests
```

This class is often useful when using libraries that integrate with Requests.
Read more about [Requests on Read the Docs](https://requests.readthedocs.io).


## License

`elastic-transport-python` is available under the Apache-2.0 license.
For more details see [LICENSE](https://github.com/elastic/elastic-transport-python/blob/main/LICENSE).
