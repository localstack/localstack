from collections import defaultdict


def multi_value_dict_for_list(elements):
    temp_mv_dict = defaultdict(list)
    for key in elements:
        temp_mv_dict[key].append(elements[key])

    return dict((k, tuple(v)) for k, v in temp_mv_dict.items())
