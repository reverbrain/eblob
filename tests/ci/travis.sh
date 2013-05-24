#!/bin/sh -ex

# Install build-depends
yes | sudo mk-build-deps -i

# Build packages
yes | debuild -e CC -e CXX --prepend-path="/usr/local/bin/" -uc -us

# Install packages
sudo -- dpkg -i ../*.deb

# Run python bindings test
$(find . -name test.py)

# Run cpp bindings test
$(find . -name eblob_cpp_test)

# Run stress test
$(find . -name eblob_stress) -m0 -f1000 -D0 -I300000 -o20000 -i1000 -l1 -r 1000 -S10 -F87
$(find . -name eblob_stress) -m0 -f100 -b 64 -D0 -I30000 -o2000 -i100 -l1 -r 100 -S100 -F30
