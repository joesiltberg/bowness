#!/usr/bin/env bash

version=$(git describe --dirty)
go build -ldflags="-X 'main.version="${version}"'"
