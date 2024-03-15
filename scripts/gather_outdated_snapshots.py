import datetime
import json
import os

import click


def get_outdated_snapshots_for_directory(
    path: str,
    date_limit: str,
    check_sub_directories: bool = True,
    combine_parametrized=True,
    show_date=False,
) -> dict:
    """
    Fetches all snapshots that were recorded before the given date_limit
    :param path: The directory where to look for snapshot files.
    :param date_limit: All snapshots whose recorded-date is older than date-limit are considered outdated.
            Format of the date-string must be "DD-MM-YYYY".
    :param check_sub_directories: Whether to look for snapshots in subdirectories
    :param combine_parametrized: Whether to combine versions of the same test and treat them as the same or not
    :return: List of test names whose snapshots (if any) are outdated.
    """

    result = {"date": date_limit}
    date_limit = datetime.datetime.strptime(date_limit, "%d-%m-%Y").timestamp()
    outdated_snapshots = {}

    def do_get_outdated_snapshots(path: str):
        if not path.endswith("/"):
            path = f"{path}/"
        for file in os.listdir(path):
            if os.path.isdir(f"{path}{file}") and check_sub_directories:
                do_get_outdated_snapshots(f"{path}{file}")
            elif file.endswith(".validation.json"):
                with open(f"{path}{file}") as f:
                    json_content: dict = json.load(f)
                    for name, recorded_snapshot_data in json_content.items():
                        recorded_date = recorded_snapshot_data.get("last_validated_date")
                        date = datetime.datetime.fromisoformat(recorded_date)
                        if date.timestamp() < date_limit:
                            outdated_snapshot_data = dict()
                            if show_date:
                                outdated_snapshot_data["last_validation_date"] = recorded_date
                            if combine_parametrized:
                                # change parametrized tests of the form <mytest[param_value]> to just <mytest>
                                name = name.split("[")[0]
                            outdated_snapshots[name] = outdated_snapshot_data

    do_get_outdated_snapshots(path)
    result["count"] = len(outdated_snapshots)
    result["outdated_tests"] = outdated_snapshots
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
    "--combine-parametrized",
    type=bool,
    required=False,
    default=True,
    help="If True, parametrized snapshots are treated as one",
)
@click.option(
    "--show-date",
    type=bool,
    required=False,
    default=False,
    help="Should tests have their recording date attached?",
)
def get_snapshots(path: str, date_limit: str, check_sub_dirs, combine_parametrized, show_date):
    """
    Fetches all snapshots in PATH that were recorded before the given DATE_LIMIT.
    Format of the DATE_LIMIT-string must be "DD-MM-YYYY".

    Returns a JSON with the relevant information

    \b
    Example usage:
    python gather_outdated_snapshots.py ../tests/integration 24-12-2022 | jq .
    """
    snapshots = get_outdated_snapshots_for_directory(
        path, date_limit, check_sub_dirs, combine_parametrized, show_date
    )
    # sorted lists are prettier to read in the console
    snapshots["outdated_tests"] = dict(sorted(snapshots["outdated_tests"].items()))

    # turn the list of snapshots into a whitespace separated string usable by pytest
    join = " ".join(snapshots["outdated_tests"])
    snapshots["pytest_executable_list"] = join
    print(json.dumps(snapshots, default=str))


if __name__ == "__main__":
    get_snapshots()
