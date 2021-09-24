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

"""Module of utilities for client implementations to use"""

import binascii
import dataclasses
import re
from collections import namedtuple
from platform import python_version
from typing import Union
from urllib.parse import quote as _quote

from ._version import __version__

__all__ = [
    "DEFAULT",
    "dataclasses",
    "create_user_agent",
    "client_meta_version",
    "CloudId",
    "parse_cloud_id",
    "to_str",
    "to_bytes",
    "percent_encode",
]

# Sentinel value used to highlight default values
# when 'None' has special meaning (like request_timeout)
# The only supported operation on this value is identity ('is DEFAULT')
DEFAULT = namedtuple("DEFAULT", ())()


def create_user_agent(name: str, version: str) -> str:
    """Creates the 'User-Agent' header given the library name and version"""
    return (
        f"{name}/{version} (Python/{python_version()}; elastic-transport/{__version__})"
    )


def client_meta_version(ver: str) -> str:
    """Converts a Python package version to a meta version.
    Meta version simply adds a 'p' suffix for all pre-releases
    """
    ver, ver_is_pre = re.match(r"^([0-9][0-9.]*[0-9]|[0-9])(.*)$", ver).groups()
    if ver_is_pre:
        ver += "p"
    return ver


def normalize_headers(headers):
    """Normalizes HTTP headers to be lowercase to ensure
    there are no case-collisions deeper within the stack.
    """
    if not headers:
        return {}
    return {
        k.lower(): v
        for k, v in (headers.items() if hasattr(headers, "items") else headers)
    }


@dataclasses.dataclass(frozen=True, repr=True)
class CloudId:
    cluster_name: str
    es_host: str
    es_port: int
    kibana_host: str
    kibana_port: int


def parse_cloud_id(cloud_id: str) -> CloudId:
    """Parses a Elastic Cloud ID into its components"""
    try:
        cloud_id = to_str(cloud_id)
        cluster_name, _, cloud_id = cloud_id.partition(":")
        parts = to_str(binascii.a2b_base64(to_bytes(cloud_id, "ascii")), "ascii").split(
            "$"
        )
        parent_dn = parts[0]
        if not parent_dn:
            raise ValueError()  # Caught and re-raised properly below
        try:
            es_uuid = parts[1]
        except IndexError:
            es_uuid = None
        try:
            kibana_uuid = parts[2] or None
        except IndexError:
            kibana_uuid = None
        port = None
        if ":" in parent_dn:
            parent_dn, _, parent_port = parent_dn.rpartition(":")
            if parent_port != "443":
                port = int(parent_port)
    except (ValueError, IndexError, UnicodeError):
        raise ValueError("Cloud ID is not properly formatted") from None

    es_host = f"{es_uuid}.{parent_dn}" if es_uuid else None
    kibana_host = f"{kibana_uuid}.{parent_dn}" if kibana_uuid else None

    return CloudId(
        cluster_name=cluster_name,
        es_host=es_host,
        es_port=port,
        kibana_host=kibana_host,
        kibana_port=port,
    )


def to_str(
    value: Union[str, bytes], encoding: str = "utf-8", errors: str = "strict"
) -> str:
    if type(value) == bytes:
        return value.decode(encoding, errors)
    return value


def to_bytes(
    value: Union[str, bytes], encoding: str = "utf-8", errors: str = "strict"
) -> bytes:
    if type(value) == str:
        return value.encode(encoding, errors)
    return value


# Python 3.7 added '~' to the safe list for urllib.parse.quote()
_QUOTE_ALWAYS_SAFE = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-~"
)


def percent_encode(string: str, safe: str = "/") -> str:
    """Percent-encodes a string so it can be used in an HTTP request target"""
    # Redefines 'urllib.parse.quote()' to always have the '~' character
    # within the 'ALWAYS_SAFE' list. The character was added in Python 3.7
    safe = "".join(_QUOTE_ALWAYS_SAFE.union(set(safe)))
    return _quote(string, safe)
