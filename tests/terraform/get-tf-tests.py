import yaml
import sys


def print_test_names(service):
    with open("tests/terraform/terraform-tests.success.txt") as f:
        dct = yaml.load(f, Loader=yaml.FullLoader)
        tests = dct.get(service)
        if len(tests) == 1:
            print(tests[0])
        else:
            print('"(' + "|".join(tests) + ')"')


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("")
    else:
        print_test_names(service=sys.argv[1])
