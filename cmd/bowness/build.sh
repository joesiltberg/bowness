#!/usr/bin/env bash

version=$(git describe --dirty --always)
go build -ldflags="-X 'main.version="${version}"'"
