"""
A simple script to generate a pip install command for all boto3-stubs packages we're currently using in LocalStack
"""

import os
import re

if __name__ == "__main__":
    with open(
        os.path.join(
            os.path.dirname(__file__), "../localstack-core/localstack/utils/aws/client_types.py"
        )
    ) as fd:
        content = fd.read()
        result = re.findall(r"\smypy_boto3_([a-z0-9_]+)\s", content)
        result = [r.replace("_", "-") for r in set(result)]
        result.sort()

        print(f'pip install "boto3-stubs[{",".join(result)}]"', end="")
