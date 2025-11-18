#!/bin/bash

set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
    echo "This test must run as root to create temporary accounts." >&2
    exit 1
fi

SERVICE_NAME="privleapd-test"
CALLER_USER="pam-calling-user"
TARGET_USER="pam-target-user"
CALLER_VALUE="caller-controlled"
TARGET_VALUE="target-controlled"
SERVICE_FILE="/etc/pam.d/${SERVICE_NAME}"

cleanup() {
    userdel -rf "${CALLER_USER}" >/dev/null 2>&1 || true
    userdel -rf "${TARGET_USER}" >/dev/null 2>&1 || true
    rm -f "${SERVICE_FILE}"
}

trap cleanup EXIT
cleanup

useradd -m -s /usr/sbin/nologin "${CALLER_USER}"
useradd -m -s /usr/sbin/nologin "${TARGET_USER}"

install -o "${CALLER_USER}" -g "${CALLER_USER}" -m 0644 /dev/stdin \
    "/home/${CALLER_USER}/.pam_environment" <<EOF
CALLER_VAR=${CALLER_VALUE}
EOF

install -o "${TARGET_USER}" -g "${TARGET_USER}" -m 0644 /dev/stdin \
    "/home/${TARGET_USER}/.pam_environment" <<EOF
TARGET_VAR=${TARGET_VALUE}
EOF

cat >"${SERVICE_FILE}" <<'EOF'
auth        required pam_permit.so
account     required pam_permit.so
session     required pam_env.so user_readenv=1
session     required pam_permit.so
EOF

echo "Dumping PAM-provided environment for target user ${TARGET_USER}" >&2
env_output=$(python3 test/scripts/pam_env_dump.py "${SERVICE_NAME}" \
    "${CALLER_USER}" "${TARGET_USER}")
echo "${env_output}"

if grep -q '^CALLER_VAR=' <<<"${env_output}"; then
    echo "ERROR: Caller-controlled variable leaked into target environment." >&2
    exit 1
fi

if ! grep -q "^TARGET_VAR=${TARGET_VALUE}$" <<<"${env_output}"; then
    echo "ERROR: Target's pam_env setting missing from environment." >&2
    exit 1
fi

echo "Success: only the target user's pam_env entries are present." >&2
