#  Licensed to Elasticsearch B.V. under one or more contributor
#  license agreements. See the NOTICE file distributed with
#  this work for additional information regarding copyright
#  ownership. Elasticsearch B.V. licenses this file to you under
#  the Apache License, Version 2.0 (the "License"); you may
#  not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
# 	http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing,
#  software distributed under the License is distributed on an
#  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
#  KIND, either express or implied.  See the License for the
#  specific language governing permissions and limitations
#  under the License.

import pytest

from elastic_transport import ApiError, ApiResponseMeta, TransportError


def test_exception_repr_and_str():
    e = TransportError({"errors": [{"status": 500}]})
    assert repr(e) == "TransportError({'errors': [{'status': 500}]})"
    assert str(e) == "{'errors': [{'status': 500}]}"

    e = TransportError("error", errors=(ValueError("value error"),))
    assert repr(e) == "TransportError('error', errors={!r})".format(
        e.errors,
    )
    assert str(e) == "error"


def test_api_error_status_repr():
    e = ApiError(
        {"errors": [{"status": 500}]},
        body={},
        meta=ApiResponseMeta(
            status=500, http_version="1.1", headers={}, duration=0.0, node=None
        ),
    )
    assert (
        repr(e)
        == "ApiError({'errors': [{'status': 500}]}, meta=ApiResponseMeta(status=500, http_version='1.1', headers={}, duration=0.0, node=None), body={})"
    )
    assert str(e) == "[500] {'errors': [{'status': 500}]}"


def test_api_error_is_not_transport_error():
    with pytest.raises(ApiError):
        try:
            raise ApiError("", None, None)
        except TransportError:
            pass


def test_transport_error_is_not_api_error():
    with pytest.raises(TransportError):
        try:
            raise TransportError(
                "",
            )
        except ApiError:
            pass
