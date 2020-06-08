from collections import defaultdict
from localstack.utils.common import to_str


def multi_value_dict_for_list(elements):
    temp_mv_dict = defaultdict(list)
    for key in elements:
        if isinstance(key, (list, tuple)):
            key, value = key
        else:
            value = elements[key]
        key = to_str(key)
        temp_mv_dict[key].append(value)

    return dict((k, tuple(v)) for k, v in temp_mv_dict.items())
