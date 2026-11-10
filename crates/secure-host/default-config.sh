# Bootstrap before the forwarded action installs a binary. Read os-release as
# data, never source it. platform.rs tests this selector against host admission.
set -euo pipefail
id= version= seen_id= seen_version=
field="^(ID|VERSION_ID)=(\"([a-z0-9.]+)\"|'([a-z0-9.]+)'|([a-z0-9.]+))$"
while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in ID=*|VERSION_ID=*) ;; *) continue ;; esac
    [[ "$line" =~ $field ]] || exit 1
    value=${BASH_REMATCH[3]}${BASH_REMATCH[4]}${BASH_REMATCH[5]}
    if [ "${BASH_REMATCH[1]}" = ID ]; then
        [ -z "$seen_id" ] || exit 1
        id=$value seen_id=yes
    else
        [ -z "$seen_version" ] || exit 1
        version=$value seen_version=yes
    fi
done < "${1:-/etc/os-release}"
if [[ "$id" = ubuntu && "$version" = 26.04 ]]; then
    printf '%s\n' hosted.toml
elif [[ "$id" = rhel && "$version" =~ ^10(\.[0-9]+)*$ ]] || [[ "$id" = centos && "$version" = 10 ]]; then
    printf '%s\n' rhel-cloud.toml
else
    printf '%s\n' 'secure-host: cannot select a default for an unsupported host' >&2
    exit 1
fi
