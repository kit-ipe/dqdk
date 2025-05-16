#! /bin/bash
image_container=$(buildah from ubuntu:24.04)
echo "Build container: $image_container"

author=$(whoami)
echo "Image Author: $author"
buildah config --author=$author $image_container

echo "Installing build depedencies..."
buildah run --env DEBIAN_FRONTEND=noninteractive $image_container -- apt update -qqq
buildah run --env DEBIAN_FRONTEND=noninteractive $image_container -- bash -c 'apt install -yqqq clang llvm libelf-dev libpcap-dev gcc-multilib build-essential linux-tools-common linux-tools-generic linux-headers-$(uname -r) m4 libnuma-dev liburing-dev'

echo "Installing tools..."
buildah run --env DEBIAN_FRONTEND=noninteractive $image_container -- bash -c 'apt install -yqqq ethtool iproute2 pciutils bsdextrautils iputils-ping vim linux-tools-$(uname -r)'

echo "Cloning DQDK Repository..."
buildah config --workingdir /dqdk $image_container
buildah copy $image_container .

echo "Building DQDK..."
buildah run $image_container -- bash -c 'pwd && ls && make'

echo "Installing DQDK..."
buildah run $image_container -- make install
buildah run --env DEBIAN_FRONTEND=noninteractive $image_container -- bash -c 'apt remove -yqq clang llvm gcc-multilib build-essential m4 && apt autoremove -yqq'

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
