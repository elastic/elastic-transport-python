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

import nox

SOURCE_FILES = (
    "noxfile.py",
    "setup.py",
    "elastic_transport/",
    "utils/",
    "tests/",
    "docs/sphinx/",
)


@nox.session()
def format(session):
    session.install("black~=24.0", "isort", "pyupgrade")
    session.run("black", "--target-version=py37", *SOURCE_FILES)
    session.run("isort", *SOURCE_FILES)
    session.run("python", "utils/license-headers.py", "fix", *SOURCE_FILES)

    lint(session)


@nox.session
def lint(session):
    session.install(
        "flake8",
        "black~=24.0",
        "isort",
        "mypy==1.7.1",
        "types-requests",
        "types-certifi",
    )
    # https://github.com/python/typeshed/issues/10786
    session.run(
        "python", "-m", "pip", "uninstall", "--yes", "types-urllib3", silent=True
    )
    session.install(".[develop]")
    session.run("black", "--check", "--target-version=py37", *SOURCE_FILES)
    session.run("isort", "--check", *SOURCE_FILES)
    session.run("flake8", "--ignore=E501,W503,E203,E704", *SOURCE_FILES)
    session.run("python", "utils/license-headers.py", "check", *SOURCE_FILES)
    session.run("mypy", "--strict", "--show-error-codes", "elastic_transport/")


@nox.session(python=["3.8", "3.9", "3.10", "3.11", "3.12"])
def test(session):
    session.install(".[develop]")
    session.run(
        "pytest",
        "--cov=elastic_transport",
        *(session.posargs or ("tests/",)),
        env={"PYTHONWARNINGS": "always::DeprecationWarning"},
    )
    session.run("coverage", "report", "-m")


@nox.session(name="test-min-deps", python="3.8")
def test_min_deps(session):
    session.install("-r", "requirements-min.txt", ".[develop]", silent=False)
    session.run(
        "pytest",
        "--cov=elastic_transport",
        *(session.posargs or ("tests/",)),
        env={"PYTHONWARNINGS": "always::DeprecationWarning"},
    )
    session.run("coverage", "report", "-m")


@nox.session(python="3")
def docs(session):
    session.install(".[develop]")

    session.chdir("docs/sphinx")
    session.run(
        "sphinx-build",
        "-T",
        "-E",
        "-b",
        "html",
        "-d",
        "_build/doctrees",
        "-D",
        "language=en",
        ".",
        "_build/html",
    )
