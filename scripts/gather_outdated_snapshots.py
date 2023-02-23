import datetime
import json
import os
import sys


def get_outdated_snapshots_for_directory(path: str, date_limit: str) -> dict:
    """
    Fetches all snapshots that were recorded before the given date_limit
    :param path: The directory where to look for snapshot files.
    :param date_limit: All snapshots whose recorded-date is older than date-limit are considered outdated.
            Format of the date-string must be "DD-MM-YYYY".
    :return: List of test names whose snapshots (if any) are outdated.
    """

    date_limit = datetime.datetime.strptime(date_limit, "%d-%m-%Y")
    result = {"date": date_limit}
    outdated_snapshots = []
    if not path.endswith("/"):
        path = f"{path}/"
    for file in os.listdir(path):
        if not file.endswith(".snapshot.json"):
            continue
        with open(f"{path}{file}") as f:
            json_content: dict = json.load(f)
            for name, snapshot in json_content.items():
                date = snapshot.get("recorded-date")
                date = datetime.datetime.strptime(date, "%d-%m-%Y, %H:%M:%S")
                if date < date_limit:
                    outdated_snapshots.append(name)
    result["count"] = len(outdated_snapshots)
    result["outdated_snapshots"] = outdated_snapshots
    return result


if __name__ == "__main__":
    snapshots = get_outdated_snapshots_for_directory(sys.argv[1], sys.argv[2])
    # turn the list of snapshots into a whitespace separated string usable by pytest
    join = " ".join(snapshots["outdated_snapshots"])
    snapshots["pytest_executable_list"] = join
    print(json.dumps(snapshots, default=str))
