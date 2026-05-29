#!/usr/bin/env bash

set -e

export TESTING=1

features="
  conntrack,
  rt-link,
  rt-addr,
  rt-route,
  wireguard,
  nftables,
  nl80211,
  tc,
  inet-diag,
  netdev
"

examples="
  conntrack
  wireguard
  wireguard-setup
  ip-route-show
  nftables
  nftables-api
  nl80211
  nl80211-raw
  tc-prio
  tcp-rtt
  multicast-simple
  multicast-generic
  multicast-rtnetlink
"

targets="
  $(uname -m)-unknown-linux-gnu
  $(uname -m)-unknown-linux-musl
"

run() {
  echo >&2
  echo ">" "$@" >&2
  command "$@"
}

cargo() {
  run cargo "$@" --features="$(echo $features | tr -d " ")" --target="$target"
}

matches() {
  if ! rg --passthru -- "$1"; then
    echo
    echo "Error: Pattern didn't match. Expected: $1"
    exit 1
  fi
}

if ! ip link show wg0 >/dev/null; then
  # Create "wg0" interface for doctests in readme
  ip link add dev wg0 type wireguard
fi

rm -rf ./target/bin_dir
mkdir -p ./target/bin_dir

for target in $targets; do
  cargo check -p netlink-bindings --all-features

  cargo test

  for runtime in "" tokio smol; do
    cargo run --example=extack |
      matches 'Attribute failed policy validation: attribute "Ifname" in "LinkAttrs": PolicyTypeAttrs \{ MaxLength: 15, Type: 11 \}'

    for example in $examples; do
      cargo run --example="$example" --features="$runtime"
      cp "./target/debug/examples/$example" "./target/bin_dir/$target-$runtime-$example"
    done
  done
done

# Run the same examples in a VM against a bunch of different kernel versions
if ! type -P nix &>/dev/null; then
  echo "Skipping vm tests: 'nix' command not found"
  exit 0
fi

vm_out="$(
  run nix build \
    --print-out-paths --no-link \
    -f ./scripts/vm_tests.nix \
    --argstr bin_dir "target/bin_dir" \
    driver
)"

# To debug inside the vm run `$vm_runner --interactive`, type
# `machine.start()`, wait until it boots, and ssh root@vsock/7502{0,1,2,...}
run "$vm_out/bin/nixos-test-driver" # [--interactive]
