#!/usr/bin/env python

import os
import sys
import re
import subprocess
import setuptools
from setuptools import find_packages, setup
from setuptools.command.install_lib import install_lib

install_requires = []
dependency_links = []
package_data = {}

with open('requirements.txt') as f:
    requirements = f.read()


for line in re.split('\n', requirements):
    if line and line[0] == '#' and '#egg=' in line:
        line = re.search(r'#\s*(.*)', line).group(1)
    if line and line[0] != '#':
        if '://' in line:
            if '#egg=' in line and 'http://' in line and 'github.com' in line:
                dependency_links.append(line)
                package = re.search(r'http://github.com/[^/]*/([^/]*)/.*', line).group(1)
                version = re.search(r'.*#egg=.*-([^\-]*)$', line).group(1)
                install_requires.append('%s==%s' % (package, version))
        else:
            install_requires.append(line)


def do_make_install(workdir=None):
    if workdir:
        prev_workdir = os.getcwd()
        os.chdir(workdir)
    try:
        out = subprocess.check_output('make install', shell=True)
    except subprocess.CalledProcessError as e:
        print e.output
        raise e
    if workdir:
        os.chdir(prev_workdir)


class InstallLibCommand(install_lib):

    def run(self):
        install_lib.run(self)
        # prepare filesystem
        main_dir_name = 'localstack'
        target_dir = '%s/%s' % (self.install_dir, main_dir_name)
        # delete existing directory
        subprocess.check_output('rm -r %s' % (main_dir_name), shell=True)
        # create symlink
        subprocess.check_output('ln -s %s %s' % (target_dir, main_dir_name), shell=True)
        # run 'make install'
        do_make_install()


package_data = {
    '': ['Makefile', '*.md'],
    'localstack': [
        'package.json',
        'dashboard/web/*.*',
        'dashboard/web/css/*',
        'dashboard/web/img/*',
        'dashboard/web/js/*',
        'dashboard/web/views/*',
        'mock/src/main/java/com/atlassian/*',
        'utils/kinesis/java/com/atlassian/*'
    ]}


if __name__ == '__main__':

    setup(
        name='localstack',
        version='0.2.4',
        description='Provides an easy-to-use test/mocking framework for developing Cloud applications',
        author='Waldemar Hummer (Atlassian)',
        author_email='waldemar.hummer@gmail.com',
        url='https://bitbucket.org/atlassian/localstack',
        custom_headers={
            'Authorization': None
        },
        scripts=['bin/localstack'],
        packages=find_packages(exclude=("tests", "tests.*")),
        package_data=package_data,
        install_requires=install_requires,
        dependency_links=dependency_links,
        test_suite="tests",
        license="Apache License 2.0",
        cmdclass={
            'install_lib': InstallLibCommand
        },
        zip_safe=False,
        classifiers=[
            "Programming Language :: Python :: 2",
            "Programming Language :: Python :: 2.6",
            "Programming Language :: Python :: 2.7",
            "Programming Language :: Python :: 3",
            "Programming Language :: Python :: 3.3",
            "License :: OSI Approved :: Apache Software License",
            "Topic :: Software Development :: Testing",
        ]
    )
