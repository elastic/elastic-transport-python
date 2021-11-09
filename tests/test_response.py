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
    resp = response_cls(meta=meta, raw=None)
    assert resp.meta is meta

    assert resp == resp
    assert resp.raw == resp
    assert resp == resp.raw
    assert not resp != resp
    assert not (resp != resp.raw)


def test_head_response():
    resp = HeadApiResponse(meta=meta)

    assert resp
    assert resp.raw is True
    assert resp.body is True
    assert bool(resp) is True
    assert resp.meta is meta

    assert repr(resp) == "HeadApiResponse(True)"


def test_text_response():
    resp = TextApiResponse(raw="Hello, world", meta=meta)
    assert resp.raw == "Hello, world"
    assert resp.body == "Hello, world"
    assert len(resp) == 12
    assert resp.lower() == "hello, world"
    assert list(resp) == ["H", "e", "l", "l", "o", ",", " ", "w", "o", "r", "l", "d"]

    assert repr(resp) == "TextApiResponse('Hello, world')"


def test_binary_response():
    resp = BinaryApiResponse(raw=b"Hello, world", meta=meta)
    assert resp.raw == b"Hello, world"
    assert resp.body == b"Hello, world"
    assert len(resp) == 12
    assert resp[0] == 72
    assert resp[:2] == b"He"
    assert resp.lower() == b"hello, world"
    assert resp.decode() == "Hello, world"
    assert list(resp) == [72, 101, 108, 108, 111, 44, 32, 119, 111, 114, 108, 100]

    assert repr(resp) == "BinaryApiResponse(b'Hello, world')"


def test_list_response():
    resp = ListApiResponse(raw=[1, 2, 3], meta=meta)
    assert list(resp) == [1, 2, 3]
    assert resp.raw == [1, 2, 3]
    assert resp[1] == 2

    with pytest.raises(NotImplementedError):
        _ = resp.body

    resp._body_cls = str
    assert resp.body == ["1", "2", "3"]

    assert repr(resp) == "ListApiResponse(['1', '2', '3'])"


def test_list_object_response():
    resp = ObjectApiResponse(raw={"k1": 1, "k2": 2}, meta=meta)
    assert set(resp.keys()) == {"k1", "k2"}
    assert resp["k2"] == 2
    assert resp.raw == {"k1": 1, "k2": 2}

    with pytest.raises(NotImplementedError):
        _ = resp.body

    assert repr(resp) == "ObjectApiResponse({'k1': 1, 'k2': 2})"

    resp._body_cls = set
    assert resp.body == {"k1", "k2"}

    # Sets are unordered
    assert (
        repr(resp) == "ObjectApiResponse({'k1', 'k2'})"
        or repr(resp) == "ObjectApiResponse({'k2', 'k1'})"
    )
