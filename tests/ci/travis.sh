#!/bin/sh -e

# Install build-depends
yes | sudo mk-build-deps -i

# Build packages
debuild -uc -us

# Install packages
sudo dpkg -i ../*.deb

# Run stress test
$(find . -name eblob_stress) -m0 -f100 -D0 -I30000 -i1000 -r 1000 -S10 -F87
