import json
import os
import zipfile


# TODO: unify with scaffolding
class SchemaProvider:
    def __init__(self, zipfile_path: str | os.PathLike[str]):
        self.schemas = {}
        with zipfile.ZipFile(zipfile_path) as infile:
            for filename in infile.namelist():
                with infile.open(filename) as schema_file:
                    schema = json.load(schema_file)
                    typename = schema["typeName"]
                    self.schemas[typename] = schema
