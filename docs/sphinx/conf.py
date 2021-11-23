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

import datetime
import os
import sys

sys.path.insert(0, os.path.abspath("../.."))

from elastic_transport import __version__  # noqa

project = "elastic-transport"
copyright = f"{datetime.date.today().year} Elasticsearch B.V."
author = "Seth Michael Larson"
version = __version__
release = __version__

extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.intersphinx",
    "furo",
    "sphinx_autodoc_typehints",
]

pygments_style = "sphinx"

templates_path = []
exclude_patterns = []
html_theme = "furo"
html_static_path = []

intersphinx_mapping = {
    "python": ("https://docs.python.org/3", None),
    "requests": ("https://docs.python-requests.org/en/master", None),
}
