import os

from setuptools import setup


# read the version from the VERSION file
def get_version():
    with open(os.path.join(os.path.dirname(__file__), "VERSION"), "r") as version_file:
        return version_file.read().strip()


# Set the version in the localstack/version.py file
def set_version_constant(version: str):
    with open(
        os.path.join(os.path.dirname(__file__), "localstack-core", "localstack", "version.py"), "w"
    ) as version_file:
        version_file.write(f'__version__ = "{version}"\n')


set_version_constant(get_version())

setup()
