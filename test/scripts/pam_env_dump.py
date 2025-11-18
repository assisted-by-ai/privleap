#!/usr/bin/python3

"""Dump the environment returned by pam_env for privleap tests."""

from __future__ import annotations

import ctypes
import ctypes.util
import os
import sys


libpam_name = ctypes.util.find_library("pam")
if not libpam_name:
    raise SystemExit("Unable to locate libpam on this system")
libpam = ctypes.CDLL(libpam_name)

libc_name = ctypes.util.find_library("c")
if not libc_name:
    raise SystemExit("Unable to locate libc on this system")
libc = ctypes.CDLL(libc_name)


PAM_SUCCESS = 0
PAM_USER = 1 + 1  # pam_appl.h defines PAM_SERVICE as 1
PAM_RUSER = 4
PAM_CONV_ERR = 19


class PamMessage(ctypes.Structure):
    _fields_ = [
        ("msg_style", ctypes.c_int),
        ("msg", ctypes.c_char_p),
    ]


class PamResponse(ctypes.Structure):
    _fields_ = [
        ("resp", ctypes.c_char_p),
        ("resp_retcode", ctypes.c_int),
    ]


CONV_FUNC = ctypes.CFUNCTYPE(
    ctypes.c_int,
    ctypes.c_int,
    ctypes.POINTER(ctypes.POINTER(PamMessage)),
    ctypes.POINTER(ctypes.POINTER(PamResponse)),
    ctypes.c_void_p,
)


def _conversation(
    num_msg: int,
    _msg: ctypes.POINTER(ctypes.POINTER(PamMessage)),
    resp: ctypes.POINTER(ctypes.POINTER(PamResponse)),
    _appdata_ptr: ctypes.c_void_p,
) -> int:
    if num_msg <= 0:
        return PAM_CONV_ERR

    size = ctypes.sizeof(PamResponse)
    buffer_ptr = libc.calloc(num_msg, size)
    if not buffer_ptr:
        return PAM_CONV_ERR

    resp_array = ctypes.cast(buffer_ptr, ctypes.POINTER(PamResponse))
    resp[0] = resp_array
    return PAM_SUCCESS


class PamConv(ctypes.Structure):
    _fields_ = [
        ("conv", CONV_FUNC),
        ("appdata_ptr", ctypes.c_void_p),
    ]


libpam.pam_start.argtypes = [
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.POINTER(PamConv),
    ctypes.POINTER(ctypes.c_void_p),
]
libpam.pam_start.restype = ctypes.c_int
libpam.pam_set_item.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p]
libpam.pam_set_item.restype = ctypes.c_int
libpam.pam_acct_mgmt.argtypes = [ctypes.c_void_p, ctypes.c_int]
libpam.pam_acct_mgmt.restype = ctypes.c_int
libpam.pam_open_session.argtypes = [ctypes.c_void_p, ctypes.c_int]
libpam.pam_open_session.restype = ctypes.c_int
libpam.pam_close_session.argtypes = [ctypes.c_void_p, ctypes.c_int]
libpam.pam_close_session.restype = ctypes.c_int
libpam.pam_getenvlist.argtypes = [ctypes.c_void_p]
libpam.pam_getenvlist.restype = ctypes.POINTER(ctypes.c_char_p)
libpam.pam_end.argtypes = [ctypes.c_void_p, ctypes.c_int]
libpam.pam_end.restype = ctypes.c_int

libpam.pam_strerror.argtypes = [ctypes.c_void_p, ctypes.c_int]
libpam.pam_strerror.restype = ctypes.c_char_p

libc.calloc.argtypes = [ctypes.c_size_t, ctypes.c_size_t]
libc.calloc.restype = ctypes.c_void_p
libc.free.argtypes = [ctypes.c_void_p]


def _pam_call(func, handle, *args) -> None:
    result = func(handle, *args)
    if result != PAM_SUCCESS:
        message = libpam.pam_strerror(handle, result)
        text = message.decode() if message else f"PAM error {result}"
        raise RuntimeError(text)


def dump_env(service_name: str, calling_user: str, target_user: str) -> list[str]:
    conv = PamConv(CONV_FUNC(_conversation), None)
    handle = ctypes.c_void_p()
    result = libpam.pam_start(service_name.encode(), None, ctypes.byref(conv), ctypes.byref(handle))
    if result != PAM_SUCCESS:
        message = libpam.pam_strerror(handle, result)
        text = message.decode() if message else f"PAM error {result}"
        raise RuntimeError(text)

    try:
        _pam_call(libpam.pam_set_item, handle.value, PAM_USER, calling_user.encode())
        _pam_call(libpam.pam_set_item, handle.value, PAM_RUSER, calling_user.encode())
        _pam_call(libpam.pam_acct_mgmt, handle.value, 0)
        _pam_call(libpam.pam_set_item, handle.value, PAM_USER, target_user.encode())
        _pam_call(libpam.pam_open_session, handle.value, 0)
        env_list = libpam.pam_getenvlist(handle.value)
        entries: list[str] = []
        idx = 0
        while env_list and env_list[idx]:
            entries.append(env_list[idx].decode())
            idx += 1
        if env_list:
            libc.free(env_list)
        _pam_call(libpam.pam_close_session, handle.value, 0)
        return entries
    finally:
        libpam.pam_end(handle.value, 0)


def main() -> int:
    if os.geteuid() != 0:
        print("This helper must run as root so PAM can switch users.", file=sys.stderr)
        return 1

    if len(sys.argv) != 4:
        print(
            "usage: pam_env_dump.py <pam-service> <calling-user> <target-user>",
            file=sys.stderr,
        )
        return 1

    service_name, calling_user, target_user = sys.argv[1:4]
    for entry in sorted(dump_env(service_name, calling_user, target_user)):
        print(entry)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
