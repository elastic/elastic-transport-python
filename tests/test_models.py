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

import dataclasses

import pytest

from elastic_transport import HttpHeaders, NodeConfig, QueryParams


@pytest.mark.parametrize(
    ["params", "expected"],
    [
        (QueryParams(), "QueryParams([])"),
        (QueryParams(()), "QueryParams([])"),
        (QueryParams([]), "QueryParams([])"),
        (QueryParams({}), "QueryParams([])"),
        (QueryParams((("key", "val"),)), "QueryParams([('key', 'val')])"),
        (QueryParams([("key", "val")]), "QueryParams([('key', 'val')])"),
        (QueryParams({"key": "val"}), "QueryParams([('key', 'val')])"),
        (
            QueryParams([("key", "val"), ("key2", 1)]),
            "QueryParams([('key', 'val'), ('key2', 1)])",
        ),
        (
            QueryParams([("key", ["val", True, 1]), ("key2", 1)]),
            "QueryParams([('key', ['val', True, 1]), ('key2', 1)])",
        ),
    ],
)
def test_query_params_repr(params, expected):
    assert repr(params) == str(params) == expected


def test_query_params_init_and_copy():
    params = QueryParams()
    params.add("k", "v")

    params2 = params.copy()
    assert params == params2
    assert params is not params2

    params3 = QueryParams(params)
    assert params2 == params3
    assert params2 is not params3

    with pytest.raises(TypeError) as e:
        QueryParams(set())
    assert str(e.value) == (
        "'params' must be of type Dict[str, Any] or Sequence[Tuple[str, Any]]"
    )


def test_query_params_extend():
    params = QueryParams({"key1": "val"})
    params.extend([("key1", 1), ("key2", [])])

    assert params == [("key1", "val"), ("key1", 1), ("key2", [])]
    assert len(params) == 3

    params.extend({"key3": True, "key4": False})
    assert params == [
        ("key1", "val"),
        ("key1", 1),
        ("key2", []),
        ("key3", True),
        ("key4", False),
    ]
    assert len(params) == 5


def test_query_params_len():
    params = QueryParams()
    assert len(params) == 0

    params.add("key", "value1")
    assert len(params) == 1

    params.add("key", "value2")
    assert len(params) == 2

    assert params.pop("key") == ["value1", "value2"]
    assert len(params) == 0

    assert len(QueryParams([("key", "value")])) == 1

    params = QueryParams({"key": [1, 2, 3], "key2": False})
    assert len(params) == 2

    assert len(QueryParams(params)) == 2


def test_query_params_equality():
    params = QueryParams()
    assert params == params
    assert params == []
    assert params == ()
    assert params == {}

    params.add("key", "value")
    assert params == params
    assert params == [("key", "value")]
    assert params == (("key", "value"),)
    assert params == {"key": "value"}

    assert params != []
    assert params != [("key", "vAlue")]
    assert params != [("kEy", "value")]
    assert params != [("key", "value"), ("key", "value")]
    assert params != {}
    assert params != {"key": "vAlue"}
    assert params != {"kEy": "value"}

    params.add("key2", "value2")
    assert params == params
    assert params == params.copy()
    assert params == [("key", "value"), ("key2", "value2")]
    assert params == (("key", "value"), ("key2", "value2"))

    assert params != [("key2", "value2"), ("key", "value")]
    assert params != (("key2", "value2"), ("key", "value"))

    # NOTE: When comparing against a dictionary order doesn't matter
    # On Python <3.7 these tests have a chance to pass even if this
    # *WASN'T* the case due to dictionary hash randomization but the
    # chance of that is very low *ALSO* we test on Python 3.7+ so we good.
    assert params == {"key": "value", "key2": "value2"}
    assert params == {"key2": "value2", "key": "value"}

    params.pop("key2")
    params.add("key", "value")

    # Duplicates matter for equality
    assert params == [("key", "value"), ("key", "value")]
    assert params != {"key": "value"}  # Multiple keys not representable with dict!


def test_query_params_keys_items():
    params = QueryParams()
    assert list(params.items()) == []

    params.add("key", "val")
    assert list(params.items()) == [("key", "val")]

    params.add("key2", "val2")
    assert list(params.items()) == [("key", "val"), ("key2", "val2")]
    assert list(params.keys()) == ["key", "key2"]

    params.pop("key")
    params["key3"] = "val3"
    assert list(params.items()) == [("key2", "val2"), ("key3", "val3")]
    assert list(params.keys()) == ["key2", "key3"]

    del params["key3"]
    assert list(params.items()) == [("key2", "val2")]
    assert list(params.keys()) == ["key2"]

    with pytest.raises(KeyError) as e:
        del params["key5"]
    assert str(e.value) == "'key5'"


def test_query_params_bool():
    params = QueryParams()
    assert not params
    assert bool(params) is False

    params.add("key", "val")
    assert params
    assert bool(params) is True

    params.pop("key")
    assert not params
    assert bool(params) is False


def test_query_params_contains():
    params = QueryParams()
    assert "key" not in params

    params.add("key", 1)
    assert "key" in params

    params.add("key", 2)
    assert "key" in params

    params.pop("key")
    assert "key" not in params


def test_query_params_keys_must_be_string():
    params = QueryParams()

    with pytest.raises(TypeError) as e:
        params.add(b"key", "value")
    assert str(e.value) == "Keys in 'params' must be type str not bytes"

    with pytest.raises(TypeError) as e:
        params[1] = "value"
    assert str(e.value) == "Keys in 'params' must be type str not int"

    with pytest.raises(TypeError) as e:
        QueryParams({(): "value"})
    assert str(e.value) == "Keys in 'params' must be type str not tuple"


def test_empty_node_config():
    config = NodeConfig(scheme="https", host="localhost", port=9200)

    assert dataclasses.asdict(config) == {
        "ca_certs": None,
        "client_cert": None,
        "client_key": None,
        "connections_per_node": 10,
        "headers": {},
        "host": "localhost",
        "http_compress": False,
        "path_prefix": "",
        "port": 9200,
        "request_timeout": 10,
        "scheme": "https",
        "ssl_assert_fingerprint": None,
        "ssl_assert_hostname": None,
        "ssl_context": None,
        "ssl_show_warn": True,
        "ssl_version": None,
        "verify_certs": True,
        "_extras": {},
    }

    # Default HttpHeaders should be empty and frozen
    assert len(config.headers) == 0
    assert config.headers.frozen


def test_headers_frozen():
    headers = HttpHeaders()
    assert headers.frozen is False

    headers["key"] = "value"
    headers.pop("Key")

    headers["key"] = "value"
    assert headers.freeze() is headers
    assert headers.frozen is True

    with pytest.raises(ValueError) as e:
        headers["key"] = "value"
    assert str(e.value) == "Can't modify headers that have been frozen"

    with pytest.raises(ValueError) as e:
        headers.pop("key")
    assert str(e.value) == "Can't modify headers that have been frozen"
    assert len(headers) == 1
    assert headers == {"key": "value"}

    assert headers.copy() is not headers
    assert headers.copy().frozen is False
