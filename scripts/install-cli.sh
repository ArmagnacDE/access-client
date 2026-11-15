#!/usr/bin/env bash
# access-read für Sessions auf der VM installieren: genau ein Tag, schreibgeschützt, ein fester Befehlsname.
#   scripts/install-cli.sh v1.0.0
# Legt ~/.local/share/access-client/<tag>/ aus dem Tag an (git archive, nur src/, bin/, package.json, README.md),
# nimmt allen das Schreibrecht und zeigt ~/.local/bin/access-read darauf. Die Freigaberegel für Sessions nennt nur
# diesen Befehlsnamen; was er ausführt, ist damit immer ein getaggter, geprüfter Stand, nie ein Arbeitsverzeichnis.
set -euo pipefail
TAG=${1:-}
[[ $TAG =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "Aufruf: $0 v<major>.<minor>.<patch>" >&2; exit 2; }
REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
git -C "$REPO" fetch --quiet --tags origin
git -C "$REPO" rev-parse --verify --quiet "refs/tags/$TAG" >/dev/null || { echo "Tag $TAG fehlt" >&2; exit 1; }
BASE="$HOME/.local/share/access-client"
DEST="$BASE/$TAG"
if [ -e "$DEST" ]; then
  echo "$DEST gibt es schon; nur der Link wird gesetzt."
else
  mkdir -p "$BASE"
  TMP=$(mktemp -d "$BASE/.install-XXXXXX")
  git -C "$REPO" archive "$TAG" src bin package.json README.md | tar -x -C "$TMP"
  node --input-type=module -e "import('$TMP/src/read/cli.js')" >/dev/null
  chmod -R a-w "$TMP"
  chmod u+w "$TMP"; mv "$TMP" "$DEST"; chmod a-w "$DEST"
fi
mkdir -p "$HOME/.local/bin"
ln -sfn "$DEST/bin/access-read.mjs" "$HOME/.local/bin/access-read"
echo "access-read → $DEST ($(git -C "$REPO" rev-parse --short "$TAG^{commit}"))"
