import os

# parent directory of this file
PARENT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OPENAPI_SPEC_PULUMI_JSON = os.path.join(PARENT_DIR, "files", "openapi.spec.pulumi.json")
