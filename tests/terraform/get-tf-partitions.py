# Prints a JSON dict mapping the different partitions in the terraform-tests.yaml to their service
import json

import yaml

with open("tests/terraform/terraform-tests.yaml") as f:
    service_mapping = yaml.load(f, Loader=yaml.FullLoader)
    mapping = []
    for service, partition_or_tests in service_mapping.items():
        if isinstance(partition_or_tests, dict):
            partitions = list(partition_or_tests.keys())
            for partition in partitions:
                mapping.append({"service": service, "partition": str(partition)})
        else:
            mapping.append({"service": service, "partition": None})
    print(json.dumps(mapping))
