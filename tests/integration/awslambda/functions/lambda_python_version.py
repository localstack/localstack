import sys


def handler(event, context):
    return {
        "version": "python{major}.{minor}".format(
            major=sys.version_info.major, minor=sys.version_info.minor
        )
    }
