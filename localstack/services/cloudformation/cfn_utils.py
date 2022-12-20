def rename_params(func, rename_map):
    def do_rename(params, **kwargs):
        values = func(params, **kwargs) if func else params
        for old_param, new_param in rename_map.items():
            values[new_param] = values.pop(old_param, None)
        return values

    return do_rename
