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

import json

import pytest

from elastic_transport.response import DictResponse, Headers, ListResponse, Response

resp_dict = DictResponse(status=200, headers={}, body={"key": "val"})
resp_list = ListResponse(status=404, headers={}, body=["a", 2, 3, {"k": "v"}])
resp_bool = Response(status=200, headers={}, body=False)
all_resps = pytest.mark.parametrize("resp", [resp_bool, resp_dict, resp_list])


@all_resps
def test_response_equals(resp):
    assert resp == resp
    assert resp.body == resp
    assert resp == resp.body
    assert resp != object()

    resp_content_alt = type(resp.body)()
    if resp_content_alt is False:
        resp_content_alt = True
    assert resp != resp_content_alt


def test_response_not_equals():
    assert resp_dict != resp_list


def test_response_attributes():
    assert resp_bool.status == 200
    assert resp_bool.body is False
    assert resp_bool.headers == {}


def test_response_len():
    assert len(resp_dict) == 1
    assert len(resp_list) == 4

    with pytest.raises(TypeError):
        len(resp_bool)


def test_response_truthiness():
    assert bool(resp_dict) is True
    assert bool(resp_list) is True
    assert bool(resp_bool) is False


def test_response_contains():
    assert "key" in resp_dict
    assert 4 not in resp_list

    with pytest.raises(TypeError):
        "k" in resp_bool


def test_response_getitem():
    assert resp_dict["key"] == "val"
    assert resp_list[2] == 3

    with pytest.raises(TypeError):
        resp_bool[0]


def test_response_iter():
    for _ in resp_dict:
        pass
    for _ in resp_list:
        pass
    with pytest.raises(TypeError):
        for _ in resp_bool:
            pass


def test_response_getattr():
    resp_list.index(2)
    resp_dict.keys()
    resp_bool.bit_length()


@all_resps
def test_response_repr_str(resp):
    assert str(resp) == str(resp.body)
    assert repr(resp) == repr(resp.body)


def test_response_json():
    assert json.dumps(resp_dict) == '{"key": "val"}'
    assert json.dumps(resp_list) == '["a", 2, 3, {"k": "v"}]'


def test_response_instance_checks():
    assert isinstance(resp_list, list)
    assert isinstance(resp_dict, dict)


def test_headers_empty():
    assert isinstance(resp_dict.headers, Headers)

    headers = Headers()

    assert len(headers) == 0
    with pytest.raises(KeyError) as e:
        headers["Content-Length"]
    assert str(e.value) == "'content-length'"
    with pytest.raises(KeyError) as e:
        headers[None]
    assert str(e.value) == "None"
    assert list(headers.items()) == []


@pytest.mark.parametrize(
    "initial", [{"Content-Length": "0"}, [("Content-Length", "0")]]
)
@pytest.mark.parametrize(
    "get_key", ["content-length", "Content-Length", "cOntent-length"]
)
def test_headers_with_items(initial, get_key):
    headers = Headers(initial)

    assert len(headers) == 1
    assert list(headers.keys()) == ["Content-Length"]
    assert list(headers.values()) == ["0"]
    assert list(headers.items()) == [("Content-Length", "0")]
    assert headers.get(get_key) == "0"
    assert headers[get_key] == "0"

    other_headers = dict(initial)
    assert headers == other_headers
    assert headers == Headers(other_headers)

    other_headers["content-type"] = "application/json"
    assert headers != other_headers
    assert headers != Headers(other_headers)

    assert isinstance(headers.copy(), dict)
    assert headers.copy() == headers
