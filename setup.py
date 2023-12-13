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

import os
import re

from setuptools import find_packages, setup

base_dir = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(base_dir, "elastic_transport/_version.py")) as f:
    version = re.search(r"__version__\s+=\s+\"([^\"]+)\"", f.read()).group(1)

with open(os.path.join(base_dir, "README.md")) as f:
    long_description = f.read()

packages = [
    package
    for package in find_packages(exclude=["tests"])
    if package.startswith("elastic_transport")
]

setup(
    name="elastic-transport",
    description="Transport classes and utilities shared among Python Elastic client libraries",
    long_description=long_description,
    long_description_content_type="text/markdown",
    version=version,
    author="Elastic Client Library Maintainers",
    author_email="client-libs@elastic.co",
    url="https://github.com/elastic/elastic-transport-python",
    project_urls={
        "Source Code": "https://github.com/elastic/elastic-transport-python",
        "Issue Tracker": "https://github.com/elastic/elastic-transport-python/issues",
        "Documentation": "https://elastic-transport-python.readthedocs.io",
    },
    package_data={"elastic_transport": ["py.typed"]},
    packages=packages,
    install_requires=[
        "urllib3>=1.26.2, <3",
        "certifi",
        "dataclasses; python_version<'3.7'",
        "importlib-metadata; python_version<'3.8'",
    ],
    python_requires=">=3.7",
    extras_require={
        "develop": [
            "pytest",
            "pytest-cov",
            "pytest-mock",
            "pytest-asyncio",
            "pytest-httpserver",
            "trustme",
            "mock",
            "requests",
            "aiohttp",
            # Override Read the Docs default (sphinx<2)
            "sphinx>2",
            "furo",
            "sphinx-autodoc-typehints",
        ],
    },
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "License :: OSI Approved :: Apache Software License",
        "Intended Audience :: Developers",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: Implementation :: CPython",
        "Programming Language :: Python :: Implementation :: PyPy",
    ],
)
