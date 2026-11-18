#!/usr/bin/env bash
# The files of this repository's draft release, through GitHub's REST API: a
# draft is seen by writers only and has no tag yet, so `gh release` cannot
# reach it. Used by the Daily workflow; needs GH_TOKEN, GITHUB_REPOSITORY and
# RELEASE_ID (the draft's id).
#
#   scripts/draft.sh names           its files, one per line
#   scripts/draft.sh get NAME OUT    downloads one
#   scripts/draft.sh put FILE        uploads one under its own name, in place
#                                    of a file of that name
#   scripts/draft.sh rm NAME         removes one, if it is there
#   scripts/draft.sh clear           removes them all
set -euo pipefail
: "${GH_TOKEN:?}" "${GITHUB_REPOSITORY:?}" "${RELEASE_ID:?}"
[[ "$RELEASE_ID" =~ ^[0-9]+$ ]] || { echo "not a release id: $RELEASE_ID" >&2; exit 2; }
API="https://api.github.com/repos/$GITHUB_REPOSITORY/releases"
AUTH=(-H "Authorization: Bearer $GH_TOKEN" -H "X-GitHub-Api-Version: 2022-11-28")

assets() { curl -fsSL --retry 3 "${AUTH[@]}" "$API/$RELEASE_ID/assets?per_page=100"; }
id_of() { assets | jq -r --arg n "$1" '.[] | select(.name == $n) | .id'; }
remove() { curl -fsS --retry 3 -X DELETE "${AUTH[@]}" "$API/assets/$1"; }

case "${1:-}" in
  names)
    assets | jq -r '.[].name'
    ;;
  get)
    id="$(id_of "$2")"
    [ -n "$id" ] || { echo "::error::the draft has no $2" >&2; exit 1; }
    # curl does not send the Authorization header on to the storage the API
    # redirects to.
    curl -fsSL --retry 3 "${AUTH[@]}" -H "Accept: application/octet-stream" -o "$3" "$API/assets/$id"
    ;;
  put)
    name="$(basename "$2")"
    [[ "$name" =~ ^[A-Za-z0-9._-]+$ ]] || { echo "unexpected file name: $name" >&2; exit 2; }
    id="$(id_of "$name")"
    [ -z "$id" ] || remove "$id"
    curl -fsS -X POST "${AUTH[@]}" -H "Content-Type: application/octet-stream" \
      --data-binary @"$2" \
      "https://uploads.github.com/repos/$GITHUB_REPOSITORY/releases/$RELEASE_ID/assets?name=$name" \
      | jq -r '"uploaded \(.name), \(.size) bytes"'
    ;;
  rm)
    id="$(id_of "$2")"
    [ -z "$id" ] || remove "$id"
    ;;
  clear)
    for id in $(assets | jq -r '.[].id'); do remove "$id"; done
    ;;
  *)
    sed -n '2,13p' "$0" >&2
    exit 2
    ;;
esac
