def tag_list_to_dict(tag_list: list[dict[str, str]]) -> dict[str, str]:
    return {tag["Key"]: tag["Value"] for tag in tag_list}


def tag_dict_to_list(tag_dict: dict[str, str]) -> list[dict[str, str]]:
    return [{"Key": key, "Value": value} for key, value in dict.items()]
