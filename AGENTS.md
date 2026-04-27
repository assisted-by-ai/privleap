# Agent Guidelines for privleap

This document captures security design decisions, reviewer conclusions, and
past audit findings so that future contributors (human or AI) do not re-propose
changes that have already been evaluated and resolved.

## Architecture invariants

- **No SUID binaries.** privleap runs as a background daemon (`privleapd`).
  Privilege separation is achieved through Unix domain sockets, not SUID.
- **File permissions are the sole authentication mechanism** for socket access.
  Each comm socket is owned by its user with mode `0600`. Do not add UID peer
  credential checks (`SO_PEERCRED`) — they are redundant and can break when a
  process's UID and EUID differ. (Reviewed and rejected in PR #1.)
- **One-way communication only.** stdin is never forwarded to actions. This is
  intentional to prevent interactive privilege escalation.
- **PAM environment variables are trusted.** Do not add env-var whitelisting in
  `shim.py`. If `pam_env.so` passes something through, that is the system
  administrator's decision. (Reviewed and rejected in PR #1.)
- **Supplementary groups are always cleared.** `extra_groups=[]` in `shim.py`
  is the correct fix. Do not set the target user's supplementary groups —
  privleap actions are not expected to inherit them. A future
  `EnableSupplementaryGroups` config key could change this if needed.
  (Reviewed in PR #1.)
- **No per-connection DoS rate limiting.** Each comm session runs in its own
  thread; rate limiting adds complexity without meaningful protection.
  (Reviewed and rejected in PR #1.)

## Code style

- **Formatter:** Black. Do not reformat code in ways Black disagrees with.
- **Python version:** Targets Python 3.12+ (uses nested f-strings).
- **Comments:** Minimal. The code should be self-explanatory.

## Security fixes already applied

The following vulnerabilities have been identified and fixed. Do not re-report
them.

### On master

- `config_file_regex` allowed `/` and `.` (path traversal characters). Fixed:
  regex is now `r"[-A-Za-z0-9_]+\.conf\Z"`.
- `uid_regex` was missing `\Z` end anchor, accepting trailing garbage like
  `"123abc"`. Fixed: regex is now `r"[0-9]+\Z"`.
- Socket cleanup in `destroy_comm_socket()` had a TOCTOU race
  (`exists()` then `unlink()`). Fixed: call `unlink()` directly and catch
  `FileNotFoundError`.
- Config file name validation used the full path (`str(config_file)`) against
  the filename regex. Fixed: validates `config_file.name` only.

### On branch `claude/security-audit-5BmJL`

- Socket creation TOCTOU: `bind()` created the socket file with the process
  umask, leaving a window before `chmod()`/`chown()`. Fixed: set
  `umask(0o177)` before `bind()`, restore after.
- Config directory permission check used a path string (follows symlinks,
  TOCTOU-vulnerable). Fixed: open the directory with `os.open()` and check
  permissions on the file descriptor.
- `state_dir` and `comm_dir` were world-readable (`0o755`), leaking which
  users have active sockets. Fixed: `0o711` (traverse-only for others).
- PAM handle reuse in `shim.py`: the same handle was used for
  `calling_user` account check and `target_user` session open, risking
  cached state leaking between users. Fixed: separate PAM handles.

## Things that look like bugs but are not

- **Nonexistent users in `AuthorizedUsers`** do not cause errors. This is
  intentional — a config may reference a user that does not yet exist (e.g.
  `sysmaint`). Crashing would break package installation workflows.
- **`action_command` passed to `bash -c`** is not shell-escaped. This is by
  design — commands come from root-owned, permission-checked config files and
  are meant to be shell expressions.
- **`pwd.getpwall()`** is a valid (if unusual) Python stdlib function that
  returns all password database entries. It is not a typo.
