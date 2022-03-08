import configparser
import inspect
import logging
import os
import shutil
import tempfile
from pathlib import Path
from typing import Dict

LOG = logging.getLogger(__name__)
TMP_FILES = []


def parse_config_file(file_or_str: str, single_section: bool = True) -> Dict:
    """Parse the given properties config file/string and return a dict of section->key->value.
    If the config contains a single section, and 'single_section' is True, returns"""

    config = configparser.RawConfigParser()

    if os.path.exists(file_or_str):
        file_or_str = load_file(file_or_str)

    try:
        config.read_string(file_or_str)
    except configparser.MissingSectionHeaderError:
        file_or_str = f"[default]\n{file_or_str}"
        config.read_string(file_or_str)

    sections = list(config.sections())

    result = {sec: dict(config.items(sec)) for sec in sections}
    if len(sections) == 1 and single_section:
        result = result[sections[0]]

    return result


def cache_dir() -> Path:
    from localstack.utils.platform import is_linux, is_mac_os, is_windows

    if is_windows():
        return Path("%LOCALAPPDATA%", "cache", "localstack")
    if is_mac_os():
        return Path.home() / "Library" / "Caches" / "localstack"
    if is_linux():
        string_path = os.environ.get("XDG_CACHE_HOME")
        if string_path and os.path.isabs(string_path):
            return Path(string_path)
    # Use the common place to store caches in Linux as a default
    return Path.home() / ".cache" / "localstack"


def save_file(file, content, append=False, permissions=None):
    mode = "a" if append else "w+"
    if not isinstance(content, str):
        mode = mode + "b"

    def _opener(path, flags):
        return os.open(path, flags, permissions)

    # make sure that the parent dir exsits
    mkdir(os.path.dirname(file))
    # store file contents
    with open(file, mode, opener=_opener if permissions else None) as f:
        f.write(content)
        f.flush()


def load_file(file_path, default=None, mode=None):
    if not os.path.isfile(file_path):
        return default
    if not mode:
        mode = "r"
    with open(file_path, mode) as f:
        result = f.read()
    return result


def get_or_create_file(file_path, content=None, permissions=None):
    if os.path.exists(file_path):
        return load_file(file_path)
    content = "{}" if content is None else content
    try:
        save_file(file_path, content, permissions=permissions)
        return content
    except Exception:
        pass


def replace_in_file(search, replace, file_path):
    """Replace all occurrences of `search` with `replace` in the given file (overwrites in place!)"""
    content = load_file(file_path) or ""
    content_new = content.replace(search, replace)
    if content != content_new:
        save_file(file_path, content_new)


def mkdir(folder: str):
    if not os.path.exists(folder):
        os.makedirs(folder, exist_ok=True)


def is_empty_dir(directory: str, ignore_hidden: bool = False) -> bool:
    """Return whether the given directory contains any entries (files/folders), including hidden
    entries whose name starts with a dot (.), unless ignore_hidden=True is passed."""
    if not os.path.isdir(directory):
        raise Exception(f"Path is not a directory: {directory}")
    entries = os.listdir(directory)
    if ignore_hidden:
        entries = [e for e in entries if not e.startswith(".")]
    return not bool(entries)


def ensure_readable(file_path: str, default_perms: int = None):
    if default_perms is None:
        default_perms = 0o644
    try:
        with open(file_path, "rb"):
            pass
    except Exception:
        LOG.info("Updating permissions as file is currently not readable: %s", file_path)
        os.chmod(file_path, default_perms)


def chown_r(path: str, user: str):
    """Recursive chown on the given file/directory path."""
    # keep these imports here for Windows compatibility
    import grp
    import pwd

    uid = pwd.getpwnam(user).pw_uid
    gid = grp.getgrnam(user).gr_gid
    os.chown(path, uid, gid)
    for root, dirs, files in os.walk(path):
        for dirname in dirs:
            os.chown(os.path.join(root, dirname), uid, gid)
        for filename in files:
            os.chown(os.path.join(root, filename), uid, gid)


def chmod_r(path: str, mode: int):
    """Recursive chmod"""
    if not os.path.exists(path):
        return
    os.chmod(path, mode)
    for root, dirnames, filenames in os.walk(path):
        for dirname in dirnames:
            os.chmod(os.path.join(root, dirname), mode)
        for filename in filenames:
            os.chmod(os.path.join(root, filename), mode)


def rm_rf(path: str):
    """
    Recursively removes a file or directory
    """
    from localstack.utils.platform import is_debian
    from localstack.utils.run import run

    if not path or not os.path.exists(path):
        return
    # Running the native command can be an order of magnitude faster in Alpine on Travis-CI
    if is_debian():
        try:
            return run('rm -rf "%s"' % path)
        except Exception:
            pass
    # Make sure all files are writeable and dirs executable to remove
    try:
        chmod_r(path, 0o777)
    except PermissionError:
        pass  # todo log
    # check if the file is either a normal file, or, e.g., a fifo
    exists_but_non_dir = os.path.exists(path) and not os.path.isdir(path)
    if os.path.isfile(path) or exists_but_non_dir:
        os.remove(path)
    else:
        shutil.rmtree(path)


def cp_r(src: str, dst: str, rm_dest_on_conflict=False, ignore_copystat_errors=False, **kwargs):
    """Recursively copies file/directory"""
    # attention: this patch is not threadsafe
    copystat_orig = shutil.copystat
    if ignore_copystat_errors:

        def _copystat(*args, **kwargs):
            try:
                return copystat_orig(*args, **kwargs)
            except Exception:
                pass

        shutil.copystat = _copystat
    try:
        if os.path.isfile(src):
            if os.path.isdir(dst):
                dst = os.path.join(dst, os.path.basename(src))
            return shutil.copyfile(src, dst)
        if "dirs_exist_ok" in inspect.getfullargspec(shutil.copytree).args:
            kwargs["dirs_exist_ok"] = True
        try:
            return shutil.copytree(src, dst, **kwargs)
        except FileExistsError:
            if rm_dest_on_conflict:
                rm_rf(dst)
                return shutil.copytree(src, dst, **kwargs)
            raise
    except Exception as e:

        def _info(_path):
            return "%s (file=%s, symlink=%s)" % (
                _path,
                os.path.isfile(_path),
                os.path.islink(_path),
            )

        LOG.debug("Error copying files from %s to %s: %s", _info(src), _info(dst), e)
        raise
    finally:
        shutil.copystat = copystat_orig


def disk_usage(path: str) -> int:
    """Return the disk usage of the given file or directory."""

    if not os.path.exists(path):
        return 0

    if os.path.isfile(path):
        return os.path.getsize(path)

    total_size = 0
    for dirpath, dirnames, filenames in os.walk(path):
        for f in filenames:
            fp = os.path.join(dirpath, f)
            # skip if it is symbolic link
            if not os.path.islink(fp):
                total_size += os.path.getsize(fp)
    return total_size


def file_exists_not_empty(path: str) -> bool:
    """Return whether the given file or directory exists and is non-empty (i.e., >0 bytes content)"""
    return path and disk_usage(path) > 0


def cleanup_tmp_files():
    for tmp in TMP_FILES:
        try:
            rm_rf(tmp)
        except Exception:
            pass  # file likely doesn't exist, or permission denied
    del TMP_FILES[:]


def new_tmp_file() -> str:
    """Return a path to a new temporary file."""
    tmp_file, tmp_path = tempfile.mkstemp()
    os.close(tmp_file)
    TMP_FILES.append(tmp_path)
    return tmp_path


def new_tmp_dir():
    folder = new_tmp_file()
    rm_rf(folder)
    mkdir(folder)
    return folder
