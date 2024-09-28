"""
A simple script to generate a pip install command for all boto3-stubs packages we're currently using in LocalStack
"""

import os
import re

if __name__ == "__main__":
    filepath = os.path.join(
        os.path.dirname(__file__), "../localstack-core/localstack/utils/aws/client_types.py"
    )

    if os.path.exists(filepath):
        with open(filepath) as fd:
            content = fd.read()

            result = re.findall(r"mypy_boto3_([a-z0-9_]+)", content)
            result = [r.replace("_", "-") for r in set(result)]
            result.sort()

            if result:
                print(f'pip install "boto3-stubs[{",".join(result)}]"', end="")
            else:
                print("No boto3-stubs packages found.")
    else:
        print(f"File not found: {filepath}")
