import enum
from typing import Final

from localstack.services.stepfunctions.asl.component.component import Component


class CSVHeaderLocationValue(enum.Enum):
    FIRST_ROW = "FIRST_ROW"
    GIVEN = "GIVEN"


class CSVHeaderLocation(Component):
    csv_header_location_value: Final[CSVHeaderLocationValue]

    def __init__(self, csv_header_location_value: str):
        self.csv_header_location_value = CSVHeaderLocationValue(
            csv_header_location_value
        )  # Pass error upstream.
