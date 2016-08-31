#!/usr/bin/env python

from __future__ import unicode_literals
import os
import re
import subprocess
import restricted_pkg
from restricted_pkg import setup
# from setuptools import setup
from setuptools import find_packages

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


class InstallCommand(object):

    def run(self):
        out = subprocess.check_output('make install', shell=True)


if __name__ == '__main__':

    setup(
        name='localstack',
        version='0.1.0',
        description='Provides an easy-to-use test/mocking framework for developing Cloud applications',
        author='Waldemar Hummer',
        author_email='waldemar.hummer@gmail.com',
        url='https://bitbucket.org/atlassian/localstack',
        private_repository='https://atlassian.artifactoryonline.com/atlassian/api/pypi/ai_pyp',
        custom_headers={
            'X-JFrog-Art-Api': os.environ['PYPI_REPO_PASSWORD'],
            'Authorization': None
        },
        packages=find_packages(exclude=("tests", "tests.*")),
        install_requires=install_requires,
        dependency_links=dependency_links,
        test_suite="tests",
        license="(C) Atlassian",
        cmdclass={
            'install': InstallCommand
        },
        classifiers=[
            "Programming Language :: Python :: 2",
            "Programming Language :: Python :: 2.6",
            "Programming Language :: Python :: 2.7",
            "Programming Language :: Python :: 3",
            "Programming Language :: Python :: 3.3",
            "License :: OSI Approved :: Apache Software License",
            "Topic :: Software Development :: Testing",
        ],
        entry_points={
            'distutils.setup_keywords': [
                'custom_headers = restricted_pkg.validators:validate_custom_headers'
            ],
        }
    )
