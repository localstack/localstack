import datetime
import json
import os

import click


def get_outdated_snapshots_for_directory(
    path: str, date_limit: str, check_sub_directories: bool = True
) -> dict:
    """
    Fetches all snapshots that were recorded before the given date_limit
    :param path: The directory where to look for snapshot files.
    :param date_limit: All snapshots whose recorded-date is older than date-limit are considered outdated.
            Format of the date-string must be "DD-MM-YYYY".
    :param check_sub_directories: Whether to look for snapshots in subdirectories
    :param outdated_snapshots: The list of names of outdated snapshots. Used in combination with check_sub_directories
    to recurse through the directory tree
    :return: List of test names whose snapshots (if any) are outdated.
    """

    date_limit = datetime.datetime.strptime(date_limit, "%d-%m-%Y")
    result = {"date": date_limit}
    outdated_snapshots = []

    def do_get_outdated_snapshots(
        path: str, date_limit: datetime, check_sub_directories: bool = True
    ):

        if not path.endswith("/"):
            path = f"{path}/"
        for _, sub_dirs, files in os.walk(path):
            for file in files:
                if not file.endswith(".snapshot.json"):
                    continue
                try:
                    with open(f"{path}{file}") as f:
                        json_content: dict = json.load(f)
                        for name, snapshot in json_content.items():
                            date = snapshot.get("recorded-date")
                            date = datetime.datetime.strptime(date, "%d-%m-%Y, %H:%M:%S")
                            if date < date_limit:
                                outdated_snapshots.append(name)
                except FileNotFoundError as e:
                    print(e)
                    pass
            if check_sub_directories:
                for sub_dir in sub_dirs:
                    do_get_outdated_snapshots(f"{path}{sub_dir}", date_limit, check_sub_directories)

    do_get_outdated_snapshots(path, date_limit, check_sub_directories)
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
def get_snapshots(path: str, date_limit: str, check_sub_dirs):
    """
    Fetches all snapshots in PATH that were recorded before the given DATE_LIMIT.
    Format of the DATE_LIMIT-string must be "DD-MM-YYYY".

    Example usage: python get_snapshots.py ../tests/integration 24-12-2022

    Returns a JSON with the relevant information
    """
    snapshots = get_outdated_snapshots_for_directory(path, date_limit, check_sub_dirs)
    # turn the list of snapshots into a whitespace separated string usable by pytest
    join = " ".join(snapshots["outdated_snapshots"])
    snapshots["pytest_executable_list"] = join
    print(json.dumps(snapshots, default=str))


if __name__ == "__main__":
    get_snapshots()
