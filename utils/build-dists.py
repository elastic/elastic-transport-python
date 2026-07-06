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

"""A command line tool for building and verifying releases
Can be used for building both 'elasticsearch' and 'elasticsearchX' dists.
Only requires 'name' in 'setup.py' and the directory to be changed.
"""

import contextlib
import os
import re
import shutil
import tempfile

base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
tmp_dir = None


def shlex_quote(s):
    # Backport of shlex.quote() to Python 2.x
    _find_unsafe = re.compile(r"[^\w@%+=:,./-]").search

    if not s:
        return "''"
    if _find_unsafe(s) is None:
        return s

    # use single quotes, and put single quotes into double quotes
    # the string $'b is then quoted as '$'"'"'b'
    return "'" + s.replace("'", "'\"'\"'") + "'"


@contextlib.contextmanager
def set_tmp_dir():
    global tmp_dir
    tmp_dir = tempfile.mkdtemp()
    yield tmp_dir
    shutil.rmtree(tmp_dir)
    tmp_dir = None


def run(argv, expect_exit_code=0):
    global tmp_dir
    if tmp_dir is None:
        os.chdir(base_dir)
    else:
        os.chdir(tmp_dir)

    cmd = " ".join(shlex_quote(x) for x in argv)
    print("$ " + cmd)
    exit_code = os.system(cmd)
    if exit_code != expect_exit_code:
        print(
            "Command exited incorrectly: should have been %d was %d"
            % (expect_exit_code, exit_code)
        )
        exit(exit_code or 1)


def test_dist(dist):
    with set_tmp_dir() as tmp_dir:
        # Build the venv and install the dist
        run(("python", "-m", "venv", os.path.join(tmp_dir, "venv")))
        venv_python = os.path.join(tmp_dir, "venv/bin/python")
        run((venv_python, "-m", "pip", "install", "-U", "pip"))
        run((venv_python, "-m", "pip", "install", dist))

        # Test out importing from the package
        run(
            (
                venv_python,
                "-c",
                "from elastic_transport import Transport, Urllib3HttpNode, RequestsHttpNode",
            )
        )

        # Uninstall the dist, see that we can't import things anymore
        run((venv_python, "-m", "pip", "uninstall", "--yes", "elastic-transport"))
        run(
            (venv_python, "-c", "from elastic_transport import Transport"),
            expect_exit_code=256,
        )


def main():
    run(("rm", "-rf", "build/", "dist/", "*.egg-info", ".eggs"))

    # Install and run python-build to create sdist/wheel
    run(("python", "-m", "pip", "install", "-U", "build"))
    run(("python", "-m", "build"))

    for dist in os.listdir(os.path.join(base_dir, "dist")):
        test_dist(os.path.join(base_dir, "dist", dist))

    # After this run 'python -m twine upload dist/*'
    print(
        "\n\n"
        "===============================\n\n"
        "    * Releases are ready! *\n\n"
        "$ python -m twine upload dist/*\n\n"
        "==============================="
    )


if __name__ == "__main__":
    main()
