import datetime
import json
import os

integration_test_path = "../tests/integration/"


def get_outdated_snapshots(date_limit: str) -> list[str]:
    """
    Fetches all snapshots that were recorded before the given date_limit.
    :param date_limit: All snapshots whose recorded-date is older than date-limit are considered outdated.
            Format of the date-string must be "DD-MM-YYYY".
    :return: List of test names whose snapshots (if any) are outdated.
    """
    # FIXME: this might have side effects
    os.chdir(integration_test_path)
    date_limit = datetime.datetime.strptime(date_limit, "%d-%m-%Y")
    outdated_snapshots = []

    for file in os.listdir():
        if not file.endswith(".snapshot.json"):
            continue
        with open(file) as f:
            json_content: dict = json.load(f)
            for name, snapshot in json_content.items():
                date = snapshot.get("recorded-date")
                date = datetime.datetime.strptime(date, "%d-%m-%Y, %H:%M:%S")
                if date < date_limit:
                    outdated_snapshots.append(name)
    return outdated_snapshots


if __name__ == "__main__":
    snapshots = get_outdated_snapshots("14-09-2022")
    print(f"Number of outdated snapshots: {len(snapshots)}\n")
    print(f"Names of outdated snapshots: {snapshots}")
    join = " ".join(snapshots)
    pass
