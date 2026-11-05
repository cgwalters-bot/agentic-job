# Gets a source-addressed release using its attested manifest, or builds
# this source when no manifest has been published yet. It runs before any
# agentic-job exists on the machine, so it is shell and not the binary's
# Rust. It uses sha256sum, jq, coreutils' timeout and gh, which `gh`
# installs where it is missing; every step after it is the binary's.
#
# What decides that a file is the release's is its checksum in the
# verified, source-matching manifest, and not where it came from:
# one that does not match stops the job, and nothing is built in
# its place. A build is not kept in a cache: a cache is the calling
# repository's, where any workflow on its default branch or on the run's
# own ref can leave an entry for a commit nobody has built yet. A push
# to main that changes the source publishes its release a few minutes
# after the push (pin.yml, which skips a push a newer one overtook): a
# job of a commit off main, of a skipped one, or one that starts in
# those minutes builds, and the build's minutes are the price of taking
# nothing on trust but this repository's attestation.
#
#   binary.sh get --out DIR [--build]   the binaries, into DIR
#   binary.sh object --out DIR          the world-write policy object, into DIR
#   binary.sh digest [--root DIR]       the digest of the source at DIR
#   binary.sh gh                        install gh, where it is missing
#   binary.sh fetch --url URL --out FILE [--missing]
#                                       one GitHub URL, with bounded retries
#   binary.sh pin --dist DIR --release TAG [--repository OWNER/NAME]
#                                       release.json for a build of this source
#
# The action and the reusable workflow's policy job both run `get`, the
# workflows that publish a release run `pin`, and
# crates/agentic-job/tests/binary_sh.rs covers verification: the rule is
# written once.

set -euo pipefail
shopt -s inherit_errexit
# Names sort by their bytes, as the digest needs.
export LC_ALL=C
shopt -s dotglob nullglob

# This repository at this file's commit.
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

REPOSITORY=cgwalters-forge/agentic-job

# What the binaries are built from. Whatever the build comes to read from
# elsewhere (an `include_str!` of a file outside these, a toolchain file)
# has to be added, or a job would take a release for its own source when
# it is not; CI's `lint` job looks for the first of those. This file
# decides what a release holds: a release published before that changed
# lacks a file this one requires, and must not be taken for this source.
# `skills` and `workflow/review.md` are the agents' skills, built in.
BUILT_FROM=(Cargo.lock Cargo.toml crates egress skills workflow/review.md secure-host/binary.sh)

# The scripted agent too: a run with `agent: fake` needs it. secure-host
# is what the image holds: the host's side, with no agent code.
NAMES=(agentic-job fake-agent secure-host)

# One static binary, so that it runs on whatever the job's runner is.
TARGET=x86_64-unknown-linux-musl

# The access-time world-write policy, compiled once with the binaries and
# taken by its checksum, so that a host loading it needs no compiler. CO-RE
# relocates it to the running kernel; it is little-endian, as TARGET is.
OBJECT=world_write.bpf.o
OBJECT_SOURCE=crates/agentic-job/bpf/world_write.bpf.c

SHA256='^[0-9a-f]{64}$'

fail() {
  echo "error: $*" >&2
  exit 1
}

sha256() {
  sha256sum | cut -d' ' -f1
}

# Every file under PATH of ROOT, in the order of their names, as
# `KIND SHA256 PATH`: `x` for a program, `f` for another file, `l` for a
# link, whose content is where it points.
entries() {
  local root=$1 path=$2 full="$1/$2" name kind=f target sum mode
  # One line each: a name with a newline in it could pass for another's.
  [[ "$path" != *$'\n'* ]] || fail "$full has a newline in its name"
  if [ -L "$full" ]; then
    # All of the target, though command substitution drops final newlines.
    target=$(readlink -- "$full"; echo .)
    target=${target%$'\n.'}
    sum=$(printf %s "$target" | sha256)
    printf 'l %s %s\n' "$sum" "$path"
  elif [ -f "$full" ]; then
    mode=$(stat -c %a -- "$full")
    sum=$(sha256 < "$full")
    (( 8#$mode & 8#100 )) && kind=x
    printf '%s %s %s\n' "$kind" "$sum" "$path"
  elif [ -d "$full" ]; then
    for name in "$full"/*; do entries "$root" "$path/${name##*/}"; done
  else
    fail "$full is neither a file, a link nor a directory"
  fi
}

# The digest of the source at ROOT: of the content, modes and names of
# everything the binaries are built from, and of nothing else. It needs
# no git, so that it is the same in a checkout and in the copy of this
# repository a runner fetches for an action. A file that is not the
# source's (a build's leavings) changes it, and the job then builds.
digest() {
  local root=$1 path part listing=""
  for path in "${BUILT_FROM[@]}"; do
    part=$(entries "$root" "$path")
    [ -z "$part" ] || listing+=$part$'\n'
  done
  printf %s "$listing" | sha256
}

# How long one fetch may spend retrying GitHub's signaled throttling,
# in seconds, and the most one backoff waits unless GitHub asks for more.
GITHUB_BUDGET=120
GITHUB_BACKOFF_MAX=30

# gh, where the image lacks it: by the host's package manager, as root.
need_gh() {
  local manager
  command -v gh > /dev/null && return 0
  for manager in dnf apt-get; do
    if command -v "$manager" > /dev/null; then
      sudo "$manager" install -y gh || fail "could not install gh"
      return 0
    fi
  done
  fail "gh is required; no supported package manager found"
}

# `gh ARGS`, which fetches URL, with its output in FILE, retrying a response GitHub marks as
# throttled within GITHUB_BUDGET: a transient limit should not lose a job
# before it starts, and a permission denial should not wait. With
# `missing` for MISSING, a 404 returns 1; any other failure stops. gh's
# API trace (GH_DEBUG) is how the status and headers are known; it can
# hold credentials, so it stays in this variable and is never printed.
github() {
  local file=$1 missing=$2 url=$3 deadline attempt=0 left trace code status response after reset remaining delay requested
  shift 3
  deadline=$(( $(date +%s) + GITHUB_BUDGET ))
  while :; do
    left=$(( deadline - $(date +%s) ))
    (( left > 0 )) || left=1
    trace=$(GH_DEBUG=api timeout "$left" gh "$@" 2>&1 > "$file") && return 0 || code=$?
    # timeout's status: the trace can hold an earlier status line, a 200.
    [ "$code" != 124 ] || fail "fetching $url: no complete answer from GitHub within ${GITHUB_BUDGET}s"
    status=$(grep -oE 'HTTP/[^[:space:]]+[[:space:]]+[0-9]{3}' <<< "$trace" | tail -n 1 | grep -oE '[0-9]{3}$') || status=""
    [ "$missing" != missing ] || [ "$status" != 404 ] || return 1
    # A request can follow redirects: the headers are the failed
    # response's, from its status line on, not an earlier one's.
    response=$(awk '/HTTP\/[^[:space:]]+[[:space:]]+[0-9][0-9][0-9]/ { kept = "" } { kept = kept $0 "\n" } END { printf "%s", kept }' <<< "$trace")
    after=$(header "$response" retry-after)
    reset=$(header "$response" x-ratelimit-reset)
    remaining=$(header "$response" x-ratelimit-remaining)
    if ! { [[ "$status" == 403 || "$status" == 429 ]] && { [ -n "$after" ] || [ "$remaining" = 0 ] ||
        grep -qiE 'secondary rate limit|API rate limit exceeded' <<< "$trace"; }; }; then
      fail "fetching $url: GitHub request failed${status:+ (HTTP $status)}; check token permissions and resource availability"
    fi
    delay=$(( 1 << attempt ))
    (( delay <= GITHUB_BACKOFF_MAX )) || delay=$GITHUB_BACKOFF_MAX
    # Retry-After is seconds or an HTTP date; the reset is epoch seconds.
    if [ -n "$after" ]; then
      if [[ "$after" =~ ^[0-9]+$ ]]; then requested=$after
      else requested=$(( $(date -d "$after" +%s 2> /dev/null || date +%s) - $(date +%s) ))
      fi
      (( requested <= delay )) || delay=$requested
    fi
    if [ "$remaining" = 0 ] && [[ "$reset" =~ ^[0-9]+$ ]]; then
      requested=$(( reset - $(date +%s) ))
      (( requested <= delay )) || delay=$requested
    fi
    (( $(date +%s) + delay < deadline )) || fail "fetching $url: GitHub rate limit (HTTP $status); retry budget exhausted"
    sleep "$delay"
    attempt=$(( attempt + 1 ))
  done
}

# The first header NAME of RESPONSE, a trace's `< Name: value` lines.
header() {
  sed -nE "s/^< $2:[[:blank:]]*(.*[^[:space:]])[[:space:]]*$/\1/Ip" <<< "$1" | head -n 1
}

# URL into FILE using authenticated gh and bounded rate-limit retries.
# With `missing`, only an absent release or asset returns 1.
fetch() {
  local url=$1 file=$2 missing=${3-} repository tag name id
  if [[ "$url" =~ ^https://api\.github\.com/(.+)$ ]]; then
    github "$file" "$missing" "$url" api "${BASH_REMATCH[1]}" || return 1
    return 0
  fi
  [[ "$url" =~ ^https://github\.com/([^/]+/[^/]+)/releases/download/([^/]+)/([^/]+)$ ]] || fail "unsupported release URL: $url"
  repository=${BASH_REMATCH[1]} tag=${BASH_REMATCH[2]} name=${BASH_REMATCH[3]}
  # Not `gh release download`: it looks up published (REST) and draft
  # (GraphQL) releases concurrently, so the last status in its trace need
  # not be the lookup's, and an absent release can end in GraphQL's 200.
  # One REST lookup at a time keeps 404 and rate-limit statuses unambiguous.
  github "$file" "$missing" "$url" api "repos/$repository/releases/tags/$(jq -rn --arg tag "$tag" '$tag | @uri')" || return 1
  id=$(jq -r --arg name "$name" 'first(.assets[]? | select(.name == $name) | .id | select(type == "number" and . >= 0 and . == floor)) // ""' "$file" 2> /dev/null) || id=""
  if [ -z "$id" ]; then
    [ "$missing" != missing ] || return 1
    fail "release $tag has no asset $name"
  fi
  github "$file" "" "$url" api -H "Accept: application/octet-stream" "repos/$repository/releases/assets/$id"
}

# Throws unless MANIFEST pins a checksum for each file; then each file of
# FROM into OUT, kept only when it has the checksum the manifest names.
take() {
  local manifest=$1 from=$2 out=$3 release name asset mode found want
  release=$(jq -r .release "$manifest")
  for name in "${NAMES[@]}" "$OBJECT"; do
    jq -e --arg name "$name" --arg pattern "$SHA256" '.sha256[$name] | type == "string" and test($pattern)' "$manifest" > /dev/null ||
      fail "$manifest pins $release with no checksum for $name"
  done
  for name in "${NAMES[@]}" "$OBJECT"; do
    asset=$name-$TARGET mode=0755
    [ "$name" != "$OBJECT" ] || asset=$name mode=0644
    fetch "$from/$asset" "$out/$name.part"
    found=$(sha256 < "$out/$name.part")
    want=$(jq -r --arg name "$name" '.sha256[$name]' "$manifest")
    [ "$found" = "$want" ] || fail "$name of $release has SHA-256 $found, and the pin says $want: refusing it"
    chmod "$mode" "$out/$name.part"
    mv -f -- "$out/$name.part" "$out/$name"
  done
}

# A reusable workflow's identity, never the caller's ref, selects a tagged
# release: policy.yml at a version tag of its own repository.
fetch_tagged() {
  local source=$1 out=$2 repository=${WORKFLOW_REPOSITORY-} commit=${WORKFLOW_SHA-} ref="" tag resolved from
  [ -n "$repository" ] && [ -n "${WORKFLOW_IDENTITY-}" ] || return 0
  ref=$(jq -r '.workflow_ref // ""' <<< "$WORKFLOW_IDENTITY")
  local prefix="$repository/.github/workflows/policy.yml@refs/tags/"
  [[ "$ref" == "$prefix"* ]] || return 0
  tag=${ref#"$prefix"}
  [[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ && "$commit" =~ ^[0-9a-f]{40}$ ]] || fail "invalid tagged workflow identity"
  # Resolve the tag, including annotated tags, rather than trusting a release's
  # target_commitish (which may be a moving branch). A moved tag must not make
  # a workflow resolved earlier execute another commit's binary.
  if fetch "https://api.github.com/repos/$repository/git/ref/tags/$tag" "$out/commit.json" missing &&
      [ "$(jq -r '.object.type // ""' "$out/commit.json")" = commit ]; then
    resolved=$(jq -r '.object.sha // ""' "$out/commit.json")
  else
    fetch "https://api.github.com/repos/$repository/commits/$tag" "$out/commit.json"
    resolved=$(jq -r '.sha // ""' "$out/commit.json")
  fi
  rm -f -- "$out/commit.json"
  [ "$resolved" = "$commit" ] || fail "release tag does not match the workflow commit"
  from="https://github.com/$repository/releases/download/$tag"
  fetch "$from/release.json" "$out/release.json"
  fetch "$from/provenance.jsonl" "$out/provenance.jsonl"
  # Verify before trusting any manifest field: a release editor can replace
  # assets and checksums, but cannot sign a manifest as release.yml on main
  # running at the workflow's commit.
  gh attestation verify "$out/release.json" --bundle "$out/provenance.jsonl" \
    --repo "$repository" --cert-identity "https://github.com/$repository/.github/workflows/release.yml@refs/heads/main" \
    --source-ref refs/heads/main --source-digest "$commit" --deny-self-hosted-runners
  jq -e --arg repository "$repository" --arg release "$tag" --arg target "$TARGET" --arg source "$source" --arg commit "$commit" \
    '.repository == $repository and .release == $release and .target == $target and .source == $source and .commit == $commit' \
    "$out/release.json" > /dev/null || fail "tagged release manifest does not match the workflow source"
  take "$out/release.json" "$from" "$out"
  fetched=tagged
}

fetch_release() {
  local source=$1 out=$2 release="build-$1" from
  from="https://github.com/$REPOSITORY/releases/download/$release"
  fetch "$from/release.json" "$out/release.json" missing || { rm -f -- "$out/release.json"; return 0; }
  fetch "$from/provenance.jsonl" "$out/provenance.jsonl"
  # Verify before trusting any manifest field. A release editor cannot
  # substitute bytes or attest a manifest from a PR or another workflow.
  gh attestation verify "$out/release.json" --bundle "$out/provenance.jsonl" \
    --repo "$REPOSITORY" --cert-identity "https://github.com/$REPOSITORY/.github/workflows/pin.yml@refs/heads/main" \
    --source-ref refs/heads/main --deny-self-hosted-runners
  jq -e --arg repository "$REPOSITORY" --arg release "$release" --arg target "$TARGET" --arg source "$source" \
    '.repository == $repository and .release == $release and .target == $target and .source == $source' \
    "$out/release.json" > /dev/null || fail "release manifest does not describe this source: refusing it"
  take "$out/release.json" "$from" "$out"
  fetched=release
}

object() {
  mkdir -p -- "$1"
  clang -O2 -g -target bpfel -Wall -Wextra -Werror -c "$ROOT/$OBJECT_SOURCE" -o "$1/$OBJECT"
}

# musl-gcc is for the C that dependencies bring with them, clang for the
# policy object.
build() {
  local out=$1 missing=() name
  command -v musl-gcc > /dev/null || missing+=(musl-tools)
  command -v clang > /dev/null || missing+=(clang)
  if [ "${#missing[@]}" -gt 0 ]; then
    command -v apt-get > /dev/null || fail "a build needs ${missing[*]}, and this machine has no apt-get to install them with"
    # Before agentic-job exists to tune apt (`secure-host apt`): the same
    # network bounds, for this command only.
    sudo apt-get -o Acquire::Retries=3 -o Acquire::http::Timeout=10 -o Acquire::https::Timeout=10 \
      install -y --no-install-recommends "${missing[@]}"
  fi
  object "$out"
  rustup target add "$TARGET"
  (cd "$ROOT" && cargo build --release --locked --target "$TARGET" -p agentic-job -p secure-host)
  for name in "${NAMES[@]}"; do install -m 0755 -- "$ROOT/target/$TARGET/release/$name" "$out/$name"; done
}

get() {
  local out=$1 asked=$2 source fetched=""
  [ -n "$out" ] || fail "get: --out DIR is required"
  source=$(digest "$ROOT")
  mkdir -p -- "$out"
  if [ "$asked" != true ]; then
    need_gh
    fetch_tagged "$source" "$out"
    [ -n "$fetched" ] || fetch_release "$source" "$out"
  fi
  case $fetched in
    tagged) echo "fetched tagged release by its attested checksums" ;;
    release) echo "fetched build-$source by its attested checksums" ;;
    *)
      if [ "$asked" = true ]; then
        echo "::notice::A build was requested; building from this source, about two minutes"
      else
        echo "::notice::No release exists for source $source (pin.yml publishes one for each push to main, a few minutes after it; a commit off main has none); building from this source, about two minutes"
      fi
      build "$out"
      echo "built from this source"
      ;;
  esac
  [ -z "${GITHUB_OUTPUT-}" ] || printf 'fetched=%s\nsource=%s\n' "$([ -n "$fetched" ] && echo true || echo false)" "$source" >> "$GITHUB_OUTPUT"
}

# release.json for the files of DIST, as a build of this source left them.
pin() {
  local dist=$1 release=$2 repository=${3:-$REPOSITORY} sums='{}' name file sum source
  [ -n "$dist" ] && [ -n "$release" ] || fail "pin: --dist DIR and --release TAG are required"
  for name in "${NAMES[@]}" "$OBJECT"; do
    file=$name-$TARGET
    [ "$name" != "$OBJECT" ] || file=$name
    sum=$(sha256 < "$dist/$file")
    sums=$(jq -c --arg name "$name" --arg sum "$sum" '.[$name] = $sum' <<< "$sums")
  done
  source=$(digest "$ROOT")
  jq -n --arg repository "$repository" --arg release "$release" --arg target "$TARGET" --arg source "$source" \
    --arg commit "${GITHUB_SHA-}" --argjson sha256 "$sums" \
    '{repository: $repository, release: $release, target: $target, source: $source, commit: $commit, sha256: $sha256}
      | if .commit == "" then del(.commit) else . end'
}

main() {
  local command=${1-} out="" build=false root=$ROOT dist="" release="" repository="" url="" missing=""
  [ $# -eq 0 ] || shift
  while [ $# -gt 0 ]; do
    case $1 in
      --build) build=true; shift; continue ;;
      --missing) missing=missing; shift; continue ;;
      --out | --root | --dist | --release | --repository | --url) [ $# -ge 2 ] || fail "$1 needs a value" ;;
      *) fail "unknown argument: $1" ;;
    esac
    case $1 in
      --out) out=$2 ;;
      --root) root=$2 ;;
      --dist) dist=$2 ;;
      --release) release=$2 ;;
      --repository) repository=$2 ;;
      --url) url=$2 ;;
    esac
    shift 2
  done
  case $command in
    get) get "$out" "$build" ;;
    object) [ -n "$out" ] || fail "object: --out DIR is required"; object "$out" ;;
    digest) digest "$root" ;;
    pin) pin "$dist" "$release" "$repository" ;;
    gh) need_gh ;;
    # Exit status 2 for an absent resource, with --missing.
    fetch) [ -n "$url" ] && [ -n "$out" ] || fail "fetch: --url URL and --out FILE are required"; fetch "$url" "$out" "$missing" || exit 2 ;;
    *) fail "usage: binary.sh get|object|digest|pin|gh|fetch [options]" ;;
  esac
}

main "$@"
