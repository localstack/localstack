import json
from pathlib import Path

from jsonpatch import JsonPatch

from localstack.services.cloudformation.autogen.specs import ResourceProviderDefinition

AUTOGEN_ROOT_DIR = Path(__file__).parent.resolve()


def apply_patch_for(original_schema: ResourceProviderDefinition) -> ResourceProviderDefinition:
    resource_name = original_schema["typeName"]
    _, service, resource = resource_name.lower().split("::")
    patch_path = AUTOGEN_ROOT_DIR / "data" / f"patch_{service}_{resource}.json"
    if not patch_path.is_file():
        return original_schema

    with patch_path.open() as infile:
        patch = JsonPatch(json.load(infile))

    return patch.apply(original_schema)
