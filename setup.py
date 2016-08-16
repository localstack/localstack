#!/usr/bin/env python
from __future__ import unicode_literals
import re
import subprocess
from setuptools import setup, find_packages

install_requires = []
dependency_links = []

with open('requirements.txt') as f:
    requirements = f.read()

for line in re.split('\n', requirements):
    if line and line[0] != '#':
        if '://' in line:
            dependency_links.append(line)
        else:
            install_requires.append(line)

out = subprocess.check_output('make install', shell=True)

setup(
    name='localstack',
    version='0.1',
    description='Provides an easy-to-use test/mocking framework for developing Cloud applications',
    author='Waldemar Hummer',
    author_email='waldemar.hummer@gmail.com',
    url='https://bitbucket.org/atlassian/localstack',
    entry_points={},
    packages=find_packages(exclude=("tests", "tests.*")),
    install_requires=install_requires,
    dependency_links=dependency_links,
    license="Apache",
    test_suite="tests",
    classifiers=[
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 2.6",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.3",
        "License :: OSI Approved :: Apache Software License",
        "Topic :: Software Development :: Testing",
    ],
)
