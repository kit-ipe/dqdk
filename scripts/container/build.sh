#! /bin/bash
set -e

image_container=$(buildah from ubuntu:24.04)
echo "Build container: $image_container"

author=$(whoami)
echo "Image Author: $author"
buildah config --author=$author $image_container

echo "Installing build depedencies..."
buildah run --env DEBIAN_FRONTEND=noninteractive $image_container -- apt update -qq 2>/dev/null > /dev/null
buildah run --env DEBIAN_FRONTEND=noninteractive $image_container -- bash -c 'apt install -yqq clang llvm libelf-dev libpcap-dev gcc-multilib build-essential linux-tools-common linux-tools-generic linux-headers-$(uname -r) m4 libnuma-dev liburing-dev git 2>&1 > /dev/null'

echo "Installing tools..."
buildah run --env DEBIAN_FRONTEND=noninteractive $image_container -- bash -c 'apt install -yqq ethtool iproute2 2>&1 > /dev/null'

echo "Cloning DQDK Repository..."
buildah run $image_container -- git clone --recursive https://github.com/kit-ipe/dqdk.git 2>&1 > /dev/null
buildah config --workingdir /dqdk $image_container

echo "Building DQDK..."
buildah run $image_container -- make 2>&1 > /dev/null
buildah run --env DEBIAN_FRONTEND=noninteractive $image_container -- bash -c 'apt remove -yqq clang llvm gcc-multilib build-essential m4 git 2>&1 > /dev/null'

echo "Installing DQDK..."
buildah run $image_container -- make install 2>&1 > /dev/null

image_id=$(buildah images -q dqdk)
if [ -z $image_id ]; then
    echo "Committing image..."
else
    echo "Replacing $image_id..."
fi
buildah unmount $image_container
buildah commit --rm --squash $image_container dqdk:latest

if [ ! -z $image_id ]; then
    echo "Cleaning up..."
    buildah rmi $image_id
fi

buildah images
