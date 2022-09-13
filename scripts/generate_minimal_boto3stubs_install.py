import os
import re

if __name__ == "__main__":
    with open(
        os.path.join(os.path.dirname(__file__), "../localstack/testing/pytest/fixtures.py")
    ) as fd:
        content = fd.read()
        result = re.findall(r"\smypy_boto3_([a-z]+)\s", content)
        result.sort()

        print(f'pip install "boto3-stubs[{",".join(result)}]"', end="")
