Logging
=======

.. py:currentmodule:: elastic_transport

Available loggers
-----------------

- ``elastic_transport.node_pool``: Logs activity within the :class:`elastic_transport.NodePool` like nodes switching between "alive" and "dead"
- ``elastic_transport.transport``: Logs requests and responses in addition to retries, errors, and sniffing.
- ``elastic_transport.node``: Logs all network activity for individual :class:`elastic_transport.BaseNode` instances. This logger is recommended only for human debugging as the logs are unstructured and meant primarily for human consumption from the command line.

Debugging requests and responses
--------------------------------

.. autofunction:: elastic_transport.debug_logging

.. warning::

    This method shouldn't be enabled in production as it's extremely verbose. Should only be used for debugging manually.

.. code-block:: python

    import elastic_transport
    from elasticsearch import Elasticsearch

    # In this example we're debugging an Elasticsearch client:
    client = Elasticsearch(...)

    # Use `elastic_transport.debug_logging()` before the request
    elastic_transport.debug_logging()

    client.search(
        index="example-index",
        query={
            "match": {
                "text-field": "value"
            }
        },
        typed_keys=True
    )

The following script will output these logs about the HTTP request and response:

.. code-block::

    [2021-11-23T14:11:20] > POST /example-index/_search?typed_keys=true HTTP/1.1
    > Accept: application/json
    > Accept-Encoding: gzip
    > Authorization: Basic <hidden>
    > Connection: keep-alive
    > Content-Encoding: gzip
    > Content-Type: application/json
    > User-Agent: elastic-transport-python/8.1.0+dev
    > X-Elastic-Client-Meta: es=8.1.0p,py=3.9.2,t=8.1.0p,ur=1.26.7
    > {"query":{"match":{"text-field":"value"}}}
    < HTTP/1.1 200 OK
    < Content-Encoding: gzip
    < Content-Length: 165
    < Content-Type: application/json;charset=utf-8
    < Date: Tue, 23 Nov 2021 20:11:20 GMT
    < X-Cloud-Request-Id: ctSE59hPSCugrCPM4A2GUQ
    < X-Elastic-Product: Elasticsearch
    < X-Found-Handling-Cluster: 40c9b5837c8f4dd083f05eac950fd50c
    < X-Found-Handling-Instance: instance-0000000001
    < {"hits":{...}}

Notice how the ``Authorization`` HTTP header is hidden and the complete HTTP request and response method, target, headers, status, and bodies are logged for debugging.
