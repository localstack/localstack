from localstack.plugin.collector import EntryPointDict, SetuptoolsPluginCollector


def find_plugins(where=".", exclude=(), include=("*",)) -> EntryPointDict:
    """
    Utility for setup.py that collects all plugins from the specified path, and creates a dictionary for entry_points.

    For example:

    setup(
        entry_points=find_plugins()
    )
    """
    return SetuptoolsPluginCollector(
        where=where, exclude=exclude, include=include
    ).get_entry_points()
