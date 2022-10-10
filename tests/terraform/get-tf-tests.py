import sys

import yaml


def print_test_names(service_name, partition_name):
    with open("tests/terraform/terraform-tests.yaml") as f:
        dct = yaml.load(f, Loader=yaml.FullLoader)

        if not partition_name:
            # If not partition is given, the tests are directly in the service section
            tests = dct.get(service_name)
        else:
            # Otherwise, we select the tests in the specific partition
            partitions = dct.get(service_name)
            if not partitions:
                # Exit if there are no partitions
                sys.exit(1)
            tests = partitions.get(partition_name)

        # exits if no tests were found
        if not tests:
            sys.exit(1)

        if len(tests) == 1:
            print(tests[0])
        else:
            print('"(^' + "$|^".join(tests) + '$)"')


if __name__ == "__main__":
    if len(sys.argv) == 2:
        service_name = sys.argv[1]
        partition_name = None
    elif len(sys.argv) == 3:
        service_name = sys.argv[1]
        partition_name = sys.argv[2]
    else:
        sys.exit(1)

    print_test_names(service_name=service_name, partition_name=partition_name)
