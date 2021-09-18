#!/usr/bin/env python
import os
import re
from collections import defaultdict

from setuptools import find_packages, setup

import localstack
from localstack.plugin.entrypoint import find_plugins


def parse_requirements(lines):
    requirements = defaultdict(list)
    extra = "install"

    for line in lines:
        line = line.strip()
        if line.startswith("# extra="):
            # all subsequent lines are associated with this extra, until a new extra appears
            extra = line.split("=")[1]
            continue

        if line and line[0] == "#" and "#egg=" in line:
            line = re.search(r"#\s*(.*)", line).group(1)

        if line and line[0] != "#":
            lib_stripped = line.split(" #")[0].strip()
            requirements[extra].append(lib_stripped)

    return requirements


# determine version
version = localstack.__version__

# define package data
package_data = {
    "": ["Makefile", "*.md"],
    "localstack": [
        "package.json",
        "requirements*.txt",
        "dashboard/web/*.*",
        "dashboard/web/css/*",
        "dashboard/web/img/*",
        "dashboard/web/js/*",
        "dashboard/web/views/*",
        "utils/kinesis/java/cloud/localstack/*.*",
    ],
}

# load README.md as long description
if os.path.isfile("README.md"):
    with open("README.md", "r") as fh:
        long_description = fh.read()
else:
    # may happen in foreign build environments (like Docker)
    long_description = ""

# determine requirements
with open("requirements.txt") as f:
    req = parse_requirements(f.readlines())

install_requires = req["install"]

extras_require = {
    "cli": req["install"],
    "runtime": req["runtime"],
    "test": req["test"],
    "dev": req["dev"],
}
extras_require["full"] = extras_require["cli"] + extras_require["runtime"]  # deprecated

if __name__ == "__main__":
    setup(
        name="localstack",
        version=version,
        description="LocalStack - A fully functional local Cloud stack",
        long_description=long_description,
        long_description_content_type="text/markdown",
        author="Waldemar Hummer",
        author_email="waldemar.hummer@gmail.com",
        url="https://github.com/localstack/localstack",
        scripts=["bin/localstack", "bin/localstack.bat"],
        packages=find_packages(exclude=("tests", "tests.*")),
        package_data=package_data,
        install_requires=install_requires,
        extras_require=extras_require,
        entry_points=find_plugins(exclude=("tests", "tests.*")),
        test_suite="tests",
        license="Apache License 2.0",
        zip_safe=False,
        classifiers=[
            "Programming Language :: Python :: 3.6",
            "Programming Language :: Python :: 3.7",
            "Programming Language :: Python :: 3.8",
            "Programming Language :: Python :: 3.9",
            "License :: OSI Approved :: Apache Software License",
            "Topic :: Internet",
            "Topic :: Software Development :: Testing",
            "Topic :: System :: Emulators",
        ],
    )
