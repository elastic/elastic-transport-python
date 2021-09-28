Exceptions
==========

.. py:currentmodule:: elastic_transport

Transport Errors
----------------

.. autoclass:: TransportError
   :members:

.. autoclass:: TlsError
   :members:

.. autoclass:: ConnectionError
   :members:

.. autoclass:: ConnectionTimeout
   :members:

.. autoclass:: SerializationError
   :members:


API Errors
----------

.. autoclass:: ApiError
   :members:
   :undoc-members: status

.. autoclass:: BadRequestError
   :members:
   :undoc-members: status

.. autoclass:: UnauthorizedError
   :members:
   :undoc-members: status

.. autoclass:: PaymentRequiredError
   :members:
   :undoc-members: status

.. autoclass:: ForbiddenError
   :members:
   :undoc-members: status

.. autoclass:: NotFoundError
   :members:
   :undoc-members: status

.. autoclass:: ConflictError
   :members:
   :undoc-members: status

.. autoclass:: PayloadTooLargeError
   :members:
   :undoc-members: status

.. autoclass:: UnprocessableEntityError
   :members:
   :undoc-members: status

.. autoclass:: TooManyRequestsError
   :members:
   :undoc-members: status

.. autoclass:: InternalServerError
   :members:
   :undoc-members: status

.. autoclass:: MethodNotImplementedError
   :members:
   :undoc-members: status

.. autoclass:: BadGatewayError
   :members:
   :undoc-members: status

.. autoclass:: ServiceUnavailableError
   :members:
   :undoc-members: status

.. autoclass:: GatewayTimeoutError
   :members:
   :undoc-members: status