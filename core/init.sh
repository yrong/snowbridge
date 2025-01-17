#!/usr/bin/env bash

echo "Update submodules"
(cd .. && (git submodule update --init --recursive||true))

echo "Install husky hook"
(cd .. && ./core/node_modules/.bin/husky install)

echo "Installing sszgen"
go install github.com/ferranbt/fastssz/sszgen@latest

echo "Initialize foundry libraries"
(cd packages/contracts && forge install)

