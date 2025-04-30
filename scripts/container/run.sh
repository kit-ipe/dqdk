#! /bin/bash

network=$1


case "$network" in
    "bridge")
    podman run --rm --privileged --cap-add=ALL --security-opt seccomp=unconfined --network=bridge -it dqdk
    ;;

    "host")

    ;;

    *)
        echo "Invalid network type."
        exit 1
    ;;
esac