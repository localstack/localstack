import getpass
import os
import platform
import stat
import subprocess
import time


def handler(event, context):

    if event.get("wait"):
        time.sleep(event["wait"])

    return {
        # Tested in tests/integration/awslambda/test_lambda_common.py
        # "environment": dict(os.environ),
        "event": event,
        # user behavior: https://stackoverflow.com/a/25574419
        "user_login_name": getpass.getuser(),
        "user_whoami": subprocess.getoutput("whoami"),
        "platform_system": platform.system(),
        "platform_machine": platform.machine(),
        "pwd_filemode": stat.filemode(os.stat(".").st_mode),
        "opt_filemode": stat.filemode(os.stat("/opt").st_mode),
    }
