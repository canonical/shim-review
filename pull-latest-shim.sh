#!/bin/sh
# Get the latest shim from the PPA, this creates a directory like 15.7-0ubuntu1
curl https://ppa.launchpadcontent.net/ubuntu-uefi-team/ppa/ubuntu/dists/kinetic/main/signed/shim-amd64/current/signed.tar.gz | tar xvz
curl https://ppa.launchpadcontent.net/ubuntu-uefi-team/ppa/ubuntu/dists/kinetic/main/signed/shim-arm64/current/signed.tar.gz | tar xvz
# Delete all .signed binaries, they were signed with PPA test key and are not relevant
find -name '*.signed' -delete
