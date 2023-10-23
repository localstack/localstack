import getpass
import os
import platform
import re
import stat
import subprocess
import time
from pathlib import Path


def handler(event, context):
    if event.get("wait"):
        time.sleep(event["wait"])

    paths = ["/var/task", "/opt", "/tmp", "/lambda-entrypoint.sh"]
    path_details = {}
    for p in paths:
        path_label = re.sub("/", "_", p)
        path = Path(p)
        path_details[f"{path_label}_mode"] = stat.filemode(path.stat().st_mode)
        path_details[f"{path_label}_uid"] = path.stat().st_uid
        path_details[f"{path_label}_owner"] = path.owner()
        path_details[f"{path_label}_gid"] = path.stat().st_gid
        # Raises KeyError "'getgrgid(): gid not found: 995'"
        # path_details[f"{path_label}_group"] = path.group()

    return {
        # Tested in tests/aws/services/lambda_/test_lambda_common.py
        # "environment": dict(os.environ),
        "event": event,
        # user behavior: https://stackoverflow.com/a/25574419
        "user_login_name": getpass.getuser(),
        "user_whoami": subprocess.getoutput("whoami"),
        "platform_system": platform.system(),
        "platform_machine": platform.machine(),
        "pwd": os.getcwd(),
        "paths": path_details,
    }
