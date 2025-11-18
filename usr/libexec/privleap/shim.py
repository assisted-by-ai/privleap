#!/usr/bin/python3 -su

# Copyright (C) 2025 - 2025 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
# See the file COPYING for copying conditions.

# pylint: disable=broad-exception-caught
# Rationale:
#   broad-exception-caught: except blocks are intended to catch all possible
#     exceptions in each instance to ensure the process exits with a special
#     exit code in these instances.

"""shim.py - PAM integration shim for privleap. This exists to allow privleap
actions to integrate seamlessly with PAM, allowing each action to have
environment variables and umask customized by PAM without conflicting with other
actions that may be starting simultaneously. Originally this logic was
implemented as part of privleapd itself, but because umask changes are applied
at the process level (not the thread level), PAM was modifying the umask for
privleapd as a whole, which could cause issues. This shim provides a layer of
separation between privleapd and PAM."""

import sys
import pwd
import grp
import os
import subprocess
from pathlib import Path
from typing import Any

import PAM  # type: ignore

SAFE_ENV_VARS: set[str] = {
    "LANG",
    "LANGUAGE",
    "LC_ALL",
    "LC_COLLATE",
    "LC_CTYPE",
    "LC_MESSAGES",
    "LC_MONETARY",
    "LC_NUMERIC",
    "LC_TIME",
    "TERM",
    "TZ",
}
SAFE_ENV_PREFIXES: tuple[str, ...] = ("LC_",)
DEFAULT_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"


def _get_supplementary_groups(user_name: str, primary_gid: int) -> list[int]:
    """Return the supplementary groups configured for user_name."""

    group_id_list: list[int]
    try:
        group_id_list = os.getgrouplist(user_name, primary_gid)
    except (AttributeError, OSError):
        group_id_list = [primary_gid]
        for group in grp.getgrall():
            if user_name in group.gr_mem and group.gr_gid not in group_id_list:
                group_id_list.append(group.gr_gid)

    return [gid for gid in group_id_list if gid != primary_gid]


def _should_copy_env_var(key: str) -> bool:
    if key in SAFE_ENV_VARS:
        return True
    for prefix in SAFE_ENV_PREFIXES:
        if key.startswith(prefix):
            return True
    return False

if len(sys.argv) < 5:
    sys.exit(255)

calling_user: str = sys.argv[1]
target_user: str = sys.argv[2]
target_group: str = sys.argv[3]
command_arr: list[str] = sys.argv[4:]

try:
    target_user_info: pwd.struct_passwd = pwd.getpwnam(target_user)
    _: Any = pwd.getpwnam(target_user)
    _ = grp.getgrnam(target_group)
except Exception:
    sys.exit(255)

pam_obj: Any = PAM.pam()
pam_obj.start("privleapd")
pam_obj.set_item(PAM.PAM_USER, calling_user)
pam_obj.set_item(PAM.PAM_RUSER, calling_user)
try:
    pam_obj.acct_mgmt()
except PAM.error as e:
    if e.args[1] == PAM.PAM_NEW_AUTHTOK_REQD:
        pass
    else:
        sys.exit(255)
pam_obj.set_item(PAM.PAM_USER, target_user)
pam_obj.setcred(PAM.PAM_REINITIALIZE_CRED)
try:
    pam_obj.open_session()
except Exception:
    pam_obj.setcred(PAM.PAM_DELETE_CRED | PAM.PAM_SILENT)
    sys.exit(255)
pam_env_list_raw: list[str] | None = pam_obj.getenvlist()
pam_env_list: list[str] = pam_env_list_raw if pam_env_list_raw is not None else []

target_cwd: str = target_user_info.pw_dir
if not Path(target_cwd).is_dir():
    target_cwd = "/"

supplementary_groups: list[int] = _get_supplementary_groups(
    target_user_info.pw_name, target_user_info.pw_gid
)

action_env: dict[str, str] = {
    "HOME": target_user_info.pw_dir,
    "LOGNAME": target_user_info.pw_name,
    "SHELL": "/usr/bin/bash",
    "PWD": target_cwd,
    "USER": target_user_info.pw_name,
    "PATH": DEFAULT_PATH,
}

for key, value in os.environ.items():
    if _should_copy_env_var(key):
        action_env[key] = value

for env_var in pam_env_list:
    env_var_parts: list[str] = env_var.split("=", 1)
    if len(env_var_parts) != 2:
        continue
    env_key: str = env_var_parts[0]
    env_value: str = env_var_parts[1]
    if _should_copy_env_var(env_key):
        action_env[env_key] = env_value

try:
    exit_code: int = subprocess.run(
        command_arr,
        stdin=subprocess.DEVNULL,
        user=target_user,
        group=target_group,
        extra_groups=supplementary_groups,
        env=action_env,
        cwd=target_cwd,
        check=False,
    ).returncode
except Exception:
    sys.exit(255)

try:
    pam_obj.close_session(0)
    pam_obj.setcred(PAM.PAM_DELETE_CRED | PAM.PAM_SILENT)
except Exception:
    sys.exit(255)

sys.exit(exit_code)
