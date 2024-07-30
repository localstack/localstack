import os
from typing import Final

from tests.aws.services.stepfunctions.templates.template_loader import TemplateLoader

_THIS_FOLDER: Final[str] = os.path.dirname(os.path.realpath(__file__))


class IntrinsicFunctionTemplate(TemplateLoader):
    FUNCTION_INPUT_KEY: Final[str] = "FunctionInput"
    FUNCTION_OUTPUT_KEY: Final[str] = "FunctionResult"

    # Array.
    ARRAY_0: Final[str] = os.path.join(_THIS_FOLDER, "statemachines/array/array_0.json5")
    ARRAY_2: Final[str] = os.path.join(_THIS_FOLDER, "statemachines/array/array_2.json5")
    UUID: Final[str] = os.path.join(_THIS_FOLDER, "statemachines/unique_id_generation/uuid.json5")
    ARRAY_PARTITION: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/array/array_partition.json5"
    )
    ARRAY_CONTAINS: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/array/array_contains.json5"
    )
    ARRAY_RANGE: Final[str] = os.path.join(_THIS_FOLDER, "statemachines/array/array_range.json5")
    ARRAY_GET_ITEM: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/array/array_get_item.json5"
    )
    ARRAY_LENGTH: Final[str] = os.path.join(_THIS_FOLDER, "statemachines/array/array_length.json5")
    ARRAY_UNIQUE: Final[str] = os.path.join(_THIS_FOLDER, "statemachines/array/array_unique.json5")

    # JSON Manipulation.
    STRING_TO_JSON: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/json_manipulation/string_to_json.json5"
    )
    JSON_TO_STRING: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/json_manipulation/json_to_string.json5"
    )
    JSON_MERGE: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/json_manipulation/json_merge.json5"
    )
    JSON_MERGE_ESCAPED_ARGUMENT: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/json_manipulation/json_merge_escaped_argument.json5"
    )

    # String Operations.
    STRING_SPLIT: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/string_operations/string_split.json5"
    )
    STRING_SPLIT_CONTEXT_OBJECT: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/string_operations/string_split_context_object.json5"
    )

    # Encode and Decode.
    BASE_64_ENCODE: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/encode_decode/base64encode.json5"
    )
    BASE_64_DECODE: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/encode_decode/base64decode.json5"
    )

    # Hash Calculations.
    HASH: Final[str] = os.path.join(_THIS_FOLDER, "statemachines/hash_calculations/hash.json5")

    # Math Operations.
    MATH_RANDOM: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/math_operations/math_random.json5"
    )
    MATH_RANDOM_SEEDED: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/math_operations/math_random_seeded.json5"
    )
    MATH_ADD: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/math_operations/math_add.json5"
    )

    # Generic.
    FORMAT_1: Final[str] = os.path.join(_THIS_FOLDER, "statemachines/generic/format_1.json5")
    FORMAT_2: Final[str] = os.path.join(_THIS_FOLDER, "statemachines/generic/format_2.json5")
    FORMAT_CONTEXT_PATH: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/generic/format_context_path.json5"
    )
    NESTED_CALLS_1: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/generic/nested_calls_1.json5"
    )
    NESTED_CALLS_2: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/generic/nested_calls_2.json5"
    )
    ESCAPE_SEQUENCE: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/generic/escape_sequence.json5"
    )
