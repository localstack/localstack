import datetime
import json
import os

import click


def get_outdated_snapshots_for_directory(
    path: str, date_limit: str, check_sub_directories: bool = True, differentiate_parametrized=False
) -> dict:
    """
    Fetches all snapshots that were recorded before the given date_limit
    :param path: The directory where to look for snapshot files.
    :param date_limit: All snapshots whose recorded-date is older than date-limit are considered outdated.
            Format of the date-string must be "DD-MM-YYYY".
    :param check_sub_directories: Whether to look for snapshots in subdirectories
    :param differentiate_parametrized: Whether to treat parametrized versions of the same test as multiple snapshots or
    not (meaning they are treated as the same one snapshot)
    :return: List of test names whose snapshots (if any) are outdated.
    """

    date_limit = datetime.datetime.strptime(date_limit, "%d-%m-%Y")
    result = {"date": date_limit}
    outdated_snapshots = []

    def do_get_outdated_snapshots(path: str):

        if not path.endswith("/"):
            path = f"{path}/"
        for file in os.listdir(path):
            if os.path.isdir(f"{path}{file}") and check_sub_directories:
                do_get_outdated_snapshots(f"{path}{file}")
            elif file.endswith(".snapshot.json"):
                with open(f"{path}{file}") as f:
                    json_content: dict = json.load(f)
                    for name, snapshot in json_content.items():
                        date = snapshot.get("recorded-date")
                        date = datetime.datetime.strptime(date, "%d-%m-%Y, %H:%M:%S")
                        if date < date_limit:
                            if not differentiate_parametrized:

                                name = name.split("[")[0]
                            outdated_snapshots.append(name)

    do_get_outdated_snapshots(path)
    # if differentiate_parametrized was True, we end up with duplicates that need to be removed
    outdated_snapshots = set(outdated_snapshots)
    result["count"] = len(outdated_snapshots)
    result["outdated_snapshots"] = outdated_snapshots
    return result


@click.command()
@click.argument("path", type=str, required=True)
@click.argument("date_limit", type=str, required=True)
@click.option(
    "--check-sub-dirs",
    type=bool,
    required=False,
    default=True,
    help="Whether to check sub directories of PATH too",
)
@click.option(
    "--differentiate-parametrized",
    type=bool,
    required=False,
    default=False,
    help="Whether to treat parametrized versions of the same test as multiple snapshots or not, and therefore as single one",
)
def get_snapshots(path: str, date_limit: str, check_sub_dirs, differentiate_parametrized):
    """
    Fetches all snapshots in PATH that were recorded before the given DATE_LIMIT.
    Format of the DATE_LIMIT-string must be "DD-MM-YYYY".

    Example usage: python gather_outdated_snapthos.py ../tests/integration 24-12-2022

    Returns a JSON with the relevant information
    """
    snapshots = get_outdated_snapshots_for_directory(
        path, date_limit, check_sub_dirs, differentiate_parametrized
    )
    # turn the list of snapshots into a whitespace separated string usable by pytest
    join = " ".join(snapshots["outdated_snapshots"])
    snapshots["pytest_executable_list"] = join
    print(json.dumps(snapshots, default=str))


if __name__ == "__main__":
    get_snapshots()
