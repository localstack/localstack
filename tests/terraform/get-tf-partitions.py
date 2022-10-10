import yaml

with open("tests/terraform/terraform-tests.yaml") as f:
    dct = yaml.load(f, Loader=yaml.FullLoader)
    print(list(dct.keys()))
