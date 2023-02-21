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

import pickle

import pytest

from elastic_transport import (
    ApiResponseMeta,
    BinaryApiResponse,
    HeadApiResponse,
    HttpHeaders,
    ListApiResponse,
    ObjectApiResponse,
    TextApiResponse,
)

meta = ApiResponseMeta(
    status=200, http_version="1.1", headers=HttpHeaders(), duration=0, node=None
)


@pytest.mark.parametrize(
    "response_cls",
    [TextApiResponse, BinaryApiResponse, ObjectApiResponse, ListApiResponse],
)
def test_response_meta(response_cls):
    resp = response_cls(meta=meta, body=None)
    assert resp.meta is meta

    assert resp == resp
    assert resp.body == resp
    assert resp == resp.body
    assert not resp != resp
    assert not (resp != resp.body)


def test_head_response():
    resp = HeadApiResponse(meta=meta)

    assert resp
    assert resp.body is True
    assert bool(resp) is True
    assert resp.meta is meta

    assert repr(resp) == "HeadApiResponse(True)"


def test_text_response():
    resp = TextApiResponse(body="Hello, world", meta=meta)
    assert resp.body == "Hello, world"
    assert len(resp) == 12
    assert resp.lower() == "hello, world"
    assert list(resp) == ["H", "e", "l", "l", "o", ",", " ", "w", "o", "r", "l", "d"]

    assert repr(resp) == "TextApiResponse('Hello, world')"


def test_binary_response():
    resp = BinaryApiResponse(body=b"Hello, world", meta=meta)
    assert resp.body == b"Hello, world"
    assert len(resp) == 12
    assert resp[0] == 72
    assert resp[:2] == b"He"
    assert resp.lower() == b"hello, world"
    assert resp.decode() == "Hello, world"
    assert list(resp) == [72, 101, 108, 108, 111, 44, 32, 119, 111, 114, 108, 100]

    assert repr(resp) == "BinaryApiResponse(b'Hello, world')"


def test_list_response():
    resp = ListApiResponse(body=[1, 2, 3], meta=meta)
    assert list(resp) == [1, 2, 3]
    assert resp.body == [1, 2, 3]
    assert resp[1] == 2

    assert repr(resp) == "ListApiResponse([1, 2, 3])"


def test_list_object_response():
    resp = ObjectApiResponse(body={"k1": 1, "k2": 2}, meta=meta)
    assert set(resp.keys()) == {"k1", "k2"}
    assert resp["k2"] == 2
    assert resp.body == {"k1": 1, "k2": 2}

    assert repr(resp) == "ObjectApiResponse({'k1': 1, 'k2': 2})"


@pytest.mark.parametrize(
    "resp_cls", [ObjectApiResponse, ListApiResponse, TextApiResponse, BinaryApiResponse]
)
@pytest.mark.parametrize(
    ["args", "kwargs"],
    [
        ((), {}),
        ((1,), {}),
        ((1,), {"raw": 1}),
        ((1,), {"body": 1}),
        ((1,), {"meta": 1}),
        ((), {"raw": 1, "body": 1}),
        ((), {"raw": 1, "body": 1, "meta": 1}),
        ((1,), {"raw": 1, "meta": 1}),
        ((1,), {"meta": 1, "body": 1}),
        ((1, 1), {"meta": 1, "body": 1}),
        ((), {"meta": 1, "body": 1, "unk": 1}),
    ],
)
def test_constructor_type_errors(resp_cls, args, kwargs):
    with pytest.raises(TypeError) as e:
        resp_cls(*args, **kwargs)
    assert str(e.value) == "Must pass 'meta' and 'body' to ApiResponse"


def test_constructor_allowed():
    resp = HeadApiResponse(meta)
    resp = HeadApiResponse(meta=meta)

    resp = ObjectApiResponse({}, meta)
    assert resp == {}

    resp = ObjectApiResponse(meta=meta, raw={})
    assert resp == {}

    resp = ObjectApiResponse(meta=meta, raw={}, body_cls=int)
    assert resp == {}

    resp = ObjectApiResponse(meta=meta, body={}, body_cls=int)
    assert resp == {}


@pytest.mark.parametrize(
    "response_cls, body",
    [
        (TextApiResponse, "Hello World"),
        (BinaryApiResponse, b"Hello World"),
        (ObjectApiResponse, {"Hello": "World"}),
        (ListApiResponse, ["Hello", "World"]),
    ],
)
def test_pickle(response_cls, body):
    resp = response_cls(meta=meta, body=body)
    pickled_resp = pickle.loads(pickle.dumps(resp))
    assert pickled_resp == resp
    assert pickled_resp.meta == resp.meta
