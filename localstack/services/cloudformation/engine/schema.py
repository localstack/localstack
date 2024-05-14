import json
import zipfile
from pathlib import Path


# TODO: unify with scaffolding
class SchemaProvider:
    def __init__(self, zipfile_path: Path):
        self.schemas = {}
        with zipfile.ZipFile(zipfile_path) as infile:
            for filename in infile.namelist():
                with infile.open(filename) as schema_file:
                    schema = json.load(schema_file)
                    typename = schema["typeName"]
                    self.schemas[typename] = schema

    def schema(self, resource_type: str) -> dict:
        return self.schemas[resource_type]


SCHEMA_PROVIDER = SchemaProvider(zipfile_path=Path(__file__).parent / "CloudformationSchema.zip")


def resource_needs_replacement(schema: dict, properties_old: dict, properties_new: dict) -> bool:
    # get createOnly references from s chema
    create_only_properties = schema.get("createOnlyProperties", [])
    if not create_only_properties:
        return False

    for prop in create_only_properties:
        # for first level-only for now (TODO: explore!)
        last_part = prop.split("/")[-1]
        old_value = properties_old.get(last_part)
        new_value = properties_new.get(last_part)
        if old_value != new_value:
            return True
    return False
