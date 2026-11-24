# Builds the world-write policy object, `world_write.bpf.o`, into OUT:
#
#   bash bpf/build.sh OUT
#
# CO-RE relocates it to the running kernel; it is little-endian, as the
# x86_64 hosts that load it are. Needs clang, nothing else.
set -euo pipefail
[ $# -eq 1 ] || { echo "usage: build.sh OUT" >&2; exit 2; }
clang -O2 -g -target bpfel -Wall -Wextra -Werror -c "$(dirname "${BASH_SOURCE[0]}")/world_write.bpf.c" -o "$1"
