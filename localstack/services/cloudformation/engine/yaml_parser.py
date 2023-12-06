import yaml


def construct_raw(_, node):
    return node.value


class NoDatesSafeLoader(yaml.SafeLoader):
    @classmethod
    def remove_tag_constructor(cls, tag):
        """
        Remove the YAML constructor for a given tag and replace it with a raw constructor
        """
        # needed to make sure we're not changing the constructors of the base class
        # otherwise usage across the code base is affected as well
        if "yaml_constructors" not in cls.__dict__:
            cls.yaml_constructors = cls.yaml_constructors.copy()

        cls.yaml_constructors[tag] = construct_raw


NoDatesSafeLoader.remove_tag_constructor("tag:yaml.org,2002:timestamp")


def shorthand_constructor(loader: yaml.Loader, tag_suffix: str, node: yaml.Node):
    """
    TODO: proper exceptions (introduce this when fixing the provider)
    TODO: fix select & split (is this even necessary?)
    { "Fn::Select" : [ "2", { "Fn::Split": [",", {"Fn::ImportValue": "AccountSubnetIDs"}]}] }
    !Select [2, !Split [",", !ImportValue AccountSubnetIDs]]
    shorthand: 2 => canonical "2"
    """
    match tag_suffix:
        case "Ref":
            fn_name = "Ref"
        case "Condition":
            fn_name = "Condition"
        case _:
            fn_name = f"Fn::{tag_suffix}"

    if tag_suffix == "GetAtt" and isinstance(node, yaml.ScalarNode):
        # !GetAtt A.B.C => {"Fn::GetAtt": ["A", "B.C"]}
        parts = node.value.partition(".")
        if len(parts) != 3:
            raise ValueError(f"Node value contains unexpected format for !GetAtt: {parts}")
        return {fn_name: [parts[0], parts[2]]}

    if isinstance(node, yaml.ScalarNode):
        return {fn_name: node.value}
    elif isinstance(node, yaml.SequenceNode):
        return {fn_name: loader.construct_sequence(node)}
    elif isinstance(node, yaml.MappingNode):
        return {fn_name: loader.construct_mapping(node)}
    else:
        raise ValueError(f"Unexpected yaml Node type: {type(node)}")


customloader = NoDatesSafeLoader

yaml.add_multi_constructor("!", shorthand_constructor, customloader)


def parse_yaml(input_data: str):
    return yaml.load(input_data, customloader)
