#!/usr/bin/env bash

set -e

VERSION=$(git describe --tags --dirty)
GO_BUILD_CMD="go build -a -installsuffix cgo"
GO_BUILD_LDFLAGS="-s -w -X main.version=$VERSION"

BUILD_PLATFORMS="linux"
BUILD_ARCHS="amd64"

mkdir -p release

for OS in ${BUILD_PLATFORMS[@]}; do
  for ARCH in ${BUILD_ARCHS[@]}; do
    NAME="pve_exporter-$OS-$ARCH"
    echo "Building for $OS/$ARCH"
    GOARCH=$ARCH GOOS=$OS CGO_ENABLED=0 $GO_BUILD_CMD -ldflags "$GO_BUILD_LDFLAGS"\
     -o "release/$NAME" pve_exporter.go
    shasum -a 256 "release/$NAME" > "release/$NAME".sha256
  done
done