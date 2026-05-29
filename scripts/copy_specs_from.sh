#!/usr/bin/env bash
set -euo pipefail

if [[ $# != 1 ]]; then
  echo "Expected exactly one path to a Linux repo. Got $# arguments"
  exit 1
fi

for spec_path in "$@"/Documentation/netlink/specs/*.yaml; do
  spec="$(rg '^name: (\S*)$' -r '$1' -- "$spec_path")"

  mkdir -p netlink-bindings/src/"$spec"
  cp -v "$spec_path" netlink-bindings/src/"$spec"/"$spec".yaml
done
