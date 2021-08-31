#!/usr/bin/env python

import re

from setuptools import find_packages, setup

import localstack

# marker for extended/ignored and basic libs in requirements.txt
IGNORED_LIB_MARKER = "#extended-lib"
BASIC_LIB_MARKER = "#basic-lib"

# parameter variables
install_requires = []
extra_requires = []
dependency_links = []
package_data = {}


# determine version
version = localstack.__version__


# determine requirements
with open("requirements.txt") as f:
    requirements = f.read()
for line in re.split("\n", requirements):
    if line and line[0] == "#" and "#egg=" in line:
        line = re.search(r"#\s*(.*)", line).group(1)
    if line and line[0] != "#":
        # include only basic requirements here
        if IGNORED_LIB_MARKER not in line:
            lib_stripped = line.split(" #")[0].strip()
            if BASIC_LIB_MARKER in line:
                install_requires.append(lib_stripped)
            else:
                extra_requires.append(lib_stripped)

# copy requirements file, to make it available inside the package at runtime
with open("localstack/requirements.copy.txt", "w") as f:
    f.write(requirements)


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


if __name__ == "__main__":

    setup(
        name="localstack",
        version=version,
        description="LocalStack - A fully functional local Cloud stack",
        author="Waldemar Hummer",
        author_email="waldemar.hummer@gmail.com",
        url="https://github.com/localstack/localstack",
        scripts=["bin/localstack", "bin/localstack.bat"],
        packages=find_packages(exclude=("tests", "tests.*")),
        package_data=package_data,
        install_requires=install_requires,
        extras_require={"full": extra_requires},
        dependency_links=dependency_links,
        test_suite="tests",
        license="Apache License 2.0",
        zip_safe=False,
        classifiers=[
            "Programming Language :: Python :: 2",
            "Programming Language :: Python :: 2.6",
            "Programming Language :: Python :: 2.7",
            "Programming Language :: Python :: 3",
            "Programming Language :: Python :: 3.3",
            "Programming Language :: Python :: 3.4",
            "Programming Language :: Python :: 3.6",
            "Programming Language :: Python :: 3.7",
            "Programming Language :: Python :: 3.8",
            "License :: OSI Approved :: Apache Software License",
            "Topic :: Software Development :: Testing",
        ],
    )
