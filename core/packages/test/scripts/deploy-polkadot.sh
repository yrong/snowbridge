#!/usr/bin/env bash
set -eu

source scripts/set-env.sh


wait_start() {
    scripts/wait-for-it.sh -t 120 127.0.0.1:12144
}

zombienet_launch() {
    npx zombienet spawn config/launch-config.toml --provider=native --dir="$zombienet_data_dir" 2>&1 &
    wait_start
}

deploy_polkadot() {
    zombienet_launch
}
