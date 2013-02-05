#!/bin/sh -ex

# Install build-depends
yes | sudo mk-build-deps -i

# Build packages
yes | debuild -e CC -e CXX --prepend-path="/usr/local/bin/" -uc -us

# Install packages
sudo -- dpkg -i ../*.deb

# Run cpp bindings test
$(find . -name eblob_cpp_test)

# Run stress test
$(find . -name eblob_stress) -m0 -f100 -D0 -I30000 -o20000 -i1000 -r 1000 -S10 -F87
