import os
import pwd
from multiprocessing import Process, ProcessError
from typing import Callable


def run_as_os_user(target: Callable, uid: str | int, gid: str | int = None):
    """
    Run the given callable under a different OS user and (optionally) group, in a forked subprocess.
    :param target: the function to call in the subprocess
    :param uid: either the user name (string) or numeric user ID
    :param gid: optionally, either the group name (string) or numeric group ID
    """

    def _wrapper():
        if gid is not None:
            _gid = pwd.getpwnam(gid).pw_gid if isinstance(gid, str) else gid
            os.setgid(_gid)
        _uid = pwd.getpwnam(uid).pw_uid if isinstance(uid, str) else uid
        os.setuid(_uid)
        return target()

    proc = Process(target=_wrapper)
    proc.start()
    proc.join()
    if proc.exitcode != 0:
        raise ProcessError(f"Process exited with code {proc.exitcode}")
