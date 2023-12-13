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

from platform import python_version

import pytest

from elastic_transport import Urllib3HttpNode, __version__
from elastic_transport.client_utils import (
    basic_auth_to_header,
    client_meta_version,
    create_user_agent,
    parse_cloud_id,
    url_to_node_config,
)


def test_create_user_agent():
    assert create_user_agent(
        "enterprise-search-python", "7.10.0"
    ) == "enterprise-search-python/7.10.0 (Python/{}; elastic-transport/{})".format(
        python_version(),
        __version__,
    )


@pytest.mark.parametrize(
    ["version", "meta_version"],
    [
        ("7.10.0", "7.10.0"),
        ("7.10.0-alpha1", "7.10.0p"),
        ("3.9.0b1", "3.9.0p"),
        ("3.9.pre1", "3.9p"),
        ("3.7.4.post1", "3.7.4"),
        ("3.7.4.post", "3.7.4"),
    ],
)
def test_client_meta_version(version, meta_version):
    assert client_meta_version(version) == meta_version


def test_parse_cloud_id():
    cloud_id = parse_cloud_id(
        "cluster:dXMtZWFzdC0xLmF3cy5mb3VuZC5pbyQ0ZmE4ODIxZTc1NjM0MDMyYmVk"
        "MWNmMjIxMTBlMmY5NyQ0ZmE4ODIxZTc1NjM0MDMyYmVkMWNmMjIxMTBlMmY5Ng=="
    )
    assert cloud_id.cluster_name == "cluster"
    assert cloud_id.es_address == (
        "4fa8821e75634032bed1cf22110e2f97.us-east-1.aws.found.io",
        443,
    )
    assert cloud_id.kibana_address == (
        "4fa8821e75634032bed1cf22110e2f96.us-east-1.aws.found.io",
        443,
    )


@pytest.mark.parametrize(
    ["cloud_id", "port"],
    [
        (
            ":dXMtZWFzdC0xLmF3cy5mb3VuZC5pbzo5MjQzJDRmYTg4MjFlNzU2MzQwMzJiZ"
            "WQxY2YyMjExMGUyZjk3JDRmYTg4MjFlNzU2MzQwMzJiZWQxY2YyMjExMGUyZjk2",
            9243,
        ),
        (
            ":dXMtZWFzdC0xLmF3cy5mb3VuZC5pbzo0NDMkNGZhODgyMWU3NTYzNDAzMmJlZD"
            "FjZjIyMTEwZTJmOTckNGZhODgyMWU3NTYzNDAzMmJlZDFjZjIyMTEwZTJmOTY=",
            443,
        ),
    ],
)
def test_parse_cloud_id_ports(cloud_id, port):
    cloud_id = parse_cloud_id(cloud_id)
    assert cloud_id.cluster_name == ""
    assert cloud_id.es_address == (
        "4fa8821e75634032bed1cf22110e2f97.us-east-1.aws.found.io",
        port,
    )
    assert cloud_id.kibana_address == (
        "4fa8821e75634032bed1cf22110e2f96.us-east-1.aws.found.io",
        port,
    )


@pytest.mark.parametrize(
    "cloud_id",
    [
        "cluster:dXMtZWFzdC0xLmF3cy5mb3VuZC5pbyQ0ZmE4ODIxZTc1NjM0MDMyYmVkMWNmMjIxMTBlMmY5NyQ=",
        "cluster:dXMtZWFzdC0xLmF3cy5mb3VuZC5pbyQ0ZmE4ODIxZTc1NjM0MDMyYmVkMWNmMjIxMTBlMmY5Nw==",
    ],
)
def test_parse_cloud_id_no_kibana(cloud_id):
    cloud_id = parse_cloud_id(cloud_id)
    assert cloud_id.cluster_name == "cluster"
    assert cloud_id.es_address == (
        "4fa8821e75634032bed1cf22110e2f97.us-east-1.aws.found.io",
        443,
    )
    assert cloud_id.kibana_address is None


@pytest.mark.parametrize(
    "cloud_id",
    [
        "cluster:dXMtZWFzdC0xLmF3cy5mb3VuZC5pbzo0NDMkJA==",
        "cluster:dXMtZWFzdC0xLmF3cy5mb3VuZC5pbzo0NDM=",
    ],
)
def test_parse_cloud_id_no_es(cloud_id):
    cloud_id = parse_cloud_id(cloud_id)
    assert cloud_id.cluster_name == "cluster"
    assert cloud_id.es_address is None
    assert cloud_id.kibana_address is None


@pytest.mark.parametrize(
    "cloud_id",
    [
        "cluster:",
        "dXMtZWFzdC0xLmF3cy5mb3VuZC5pbyQ0ZmE4ODIxZTc1NjM0MDMyYmVkMWNmMjIxMTBlMmY5NyQ=",
        "cluster:ā",
    ],
)
def test_invalid_cloud_id(cloud_id):
    with pytest.raises(ValueError) as e:
        parse_cloud_id(cloud_id)
    assert str(e.value) == "Cloud ID is not properly formatted"


@pytest.mark.parametrize(
    ["url", "node_base_url", "path_prefix"],
    [
        ("https://localhost", "https://localhost:443", ""),
        ("http://localhost:3002", "http://localhost:3002", ""),
        ("http://127.0.0.1:3002", "http://127.0.0.1:3002", ""),
        ("http://127.0.0.1:3002/", "http://127.0.0.1:3002", ""),
        (
            "http://127.0.0.1:3002/path-prefix",
            "http://127.0.0.1:3002/path-prefix",
            "/path-prefix",
        ),
        (
            "http://localhost:3002/url-prefix/",
            "http://localhost:3002/url-prefix",
            "/url-prefix",
        ),
        (
            "https://localhost/url-prefix",
            "https://localhost:443/url-prefix",
            "/url-prefix",
        ),
        ("http://[::1]:3002/url-prefix", "http://[::1]:3002/url-prefix", "/url-prefix"),
        ("https://[::1]:0/", "https://[::1]:0", ""),
    ],
)
def test_url_to_node_config(url, node_base_url, path_prefix):
    node_config = url_to_node_config(url)
    assert Urllib3HttpNode(node_config).base_url == node_base_url

    assert "[" not in node_config.host
    assert isinstance(node_config.port, int)
    assert node_config.path_prefix == path_prefix
    assert url.lower().startswith(node_config.scheme)


@pytest.mark.parametrize(
    "url",
    [
        "localhost:0",
        "[::1]:3002/url-prefix",
        "localhost",
        "localhost/",
        "localhost:3",
        "[::1]/url-prefix/",
        "[::1]",
        "[::1]:3002",
        "http://localhost",
        "localhost/url-prefix/",
        "localhost:3002/url-prefix",
        "http://localhost/url-prefix",
    ],
)
def test_url_to_node_config_error_missing_component(url):
    with pytest.raises(ValueError) as e:
        url_to_node_config(url)
    assert (
        str(e.value)
        == "URL must include a 'scheme', 'host', and 'port' component (ie 'https://localhost:9200')"
    )


@pytest.mark.parametrize(
    ["url", "port"],
    [
        ("http://127.0.0.1", 80),
        ("http://[::1]", 80),
        ("HTTPS://localhost", 443),
        ("https://localhost/url-prefix", 443),
    ],
)
def test_url_to_node_config_use_default_ports_for_scheme(url, port):
    node_config = url_to_node_config(url, use_default_ports_for_scheme=True)
    assert node_config.port == port


def test_url_with_auth_into_authorization():
    node_config = url_to_node_config("http://localhost:9200")
    assert node_config.headers == {}

    node_config = url_to_node_config("http://@localhost:9200")
    assert node_config.headers == {}

    node_config = url_to_node_config("http://user:pass@localhost:9200")
    assert node_config.headers == {"Authorization": "Basic dXNlcjpwYXNz"}

    node_config = url_to_node_config("http://user:@localhost:9200")
    assert node_config.headers == {"Authorization": "Basic dXNlcjo="}

    node_config = url_to_node_config("http://user@localhost:9200")
    assert node_config.headers == {"Authorization": "Basic dXNlcjo="}

    node_config = url_to_node_config("http://me@example.com:password@localhost:9200")
    assert node_config.headers == {
        "Authorization": "Basic bWUlNDBleGFtcGxlLmNvbTpwYXNzd29yZA=="
    }


@pytest.mark.parametrize(
    "basic_auth", ["", b"", ("",), ("", 1), (1, ""), ["", ""], False, object()]
)
def test_basic_auth_errors(basic_auth):
    with pytest.raises(ValueError) as e:
        basic_auth_to_header(basic_auth)
    assert (
        str(e.value)
        == "'basic_auth' must be a 2-tuple of str/bytes (username, password)"
    )
