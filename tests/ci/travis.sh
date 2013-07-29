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

# Big and small stress tests
$(find . -name eblob_stress) -m0 -f1000 -D0 -I300000 -o20000 -i1000 -l0 -r 1000 -S10 -F87
$(find . -name eblob_stress) -m0 -f100 -D0 -I30000 -o2000 -i100 -l0 -r 100 -S100 -F14

# Overwrite-heavy test with many bases and threads
$(find . -name eblob_stress) -f1000 -D0 -I100000 -i64 -r 40 -S10 -F64 -T32 -l0 -o 0
