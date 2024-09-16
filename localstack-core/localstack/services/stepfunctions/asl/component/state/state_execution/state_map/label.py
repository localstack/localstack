from itertools import chain
from typing import Final

from localstack.services.stepfunctions.asl.component.component import Component


class Label(Component):
    label: Final[str]

    def __init__(self, label: str):
        self.label = label.encode().decode("unicode-escape")

        if len(self.label) == 0:
            raise ValueError("Label cannot be empty")

        if len(self.label) > 40:
            raise ValueError("Label cannot exceed 40 characters")

        for invalid_char in list(' ?*<>{}[]:;,\\|^~$#%&`"') + [
            chr(i) for i in chain(range(0x00, 0x20), range(0x7F, 0xA0))
        ]:
            if invalid_char in self.label:
                escaped_char = invalid_char.encode("unicode-escape").decode()
                raise ValueError(f"Label contains invalid character: '{escaped_char}'")
