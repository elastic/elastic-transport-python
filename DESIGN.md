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

## Example use

```python
from elastic_transport import Transport, RequestOptions, HttpHeaders
from elastic_transport.client_utils import percent_encode, dataclasses


def to_path(value) -> str:
    return percent_encode(str(value))


def to_query(value) -> str:
    return percent_encode(str(value))


class Elasticsearch:
    def __init__(self, nodes="http://localhost:9200", node_class=None, headers=None, api_key=None, max_retries=None, _transport=None, _request_options=None):
        if _transport is not None:
            self._transport = _transport
            self._request_options = _request_options
        else:
            # Convert input options into NodeConfigs and transport options
            node_configs = ...(nodes)
            self._transport = Transport(node_configs, node_class=node_class)

            # Forward all the RequestOptions into the client __init__().
            headers = HttpHeaders(headers)
            if api_key:
                headers["authorization"] = f"ApiKey {api_key}"

            self._request_options = RequestOptions(
                headers=headers,
                max_retries=max_retries
            )

    def options(self, api_key=None, headers=None) -> "Elasticsearch":
        # Per-request options follow the builder pattern.
        changes = {}
        headers = HttpHeaders(headers)

        # Convert API-specific options into RequestOptions
        if api_key:
            headers["authorization"] = f"ApiKey {api_key}"
        if headers:
            changes["headers"] = headers

        if changes:
            request_options = dataclasses.replace(self._request_options, **changes)
        else:
            request_options = self._request_options
        return Elasticsearch(_transport=self._transport, _request_options=request_options)

    def search(self, index: str = None, ignore_unavailable: bool = None, query=None):
        if index is None:
            __path = "/_search"
        else:
            __path = f"/{to_path(index)}/_search"

        __query = []
        if ignore_unavailable is not None:
            query.append(("ignore_unavailable", to_query(ignore_unavailable)))
        __target = f"{__path}{'?' if __query else ''}{'&'.join(__query)}"

        __body = {}
        if query is not None:
            __body["query"] = query

        return self._transport.perform_request(
            "POST", target=__target, body=__body
        )

client = Elasticsearch()
resp = client.options(api_key="example-api-key").search(index="example-index", query={"match_all": {}})
```
