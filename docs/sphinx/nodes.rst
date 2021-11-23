Nodes
=====

.. py:currentmodule:: elastic_transport

Configuring nodes
-----------------

.. autoclass:: elastic_transport::NodeConfig
   :members:


Node classes
------------

.. autoclass:: Urllib3HttpNode
   :members:

.. autoclass:: RequestsHttpNode
   :members:

.. autoclass:: AiohttpHttpNode
   :members:

Custom node classes
-------------------

You can define your own node class like so:

.. code-block:: python

   from typing import Optional
   from elastic_transport import Urllib3HttpNode, NodeConfig, ApiResponseMeta, HttpHeaders
   from elastic_transport.client_utils import DefaultType, DEFAULT

   class CustomHttpNode(Urllib3HttpNode):
      def perform_request(
         self,
         method: str,
         target: str,
         body: Optional[bytes] = None,
         headers: Optional[HttpHeaders] = None,
         request_timeout: Union[DefaultType, Optional[float]] = DEFAULT,
      ) -> Tuple[ApiResponseMeta, bytes]:
         # Define your HTTP request method here...

and once you have a custom node class you can pass the class to :class:`elastic_transport.Transport` or an API client like so:

.. code-block:: python

   # Example using a Transport instance:
   from elastic_transport import Transport

   transport = Transport(..., node_class=CustomHttpNode)

   # Example using an API client:
   from elasticsearch import Elasticsearch

   client = Elasticsearch(..., node_class=CustomHttpNode)
