#!/bin/bash

apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y gcc make cmake libcunit1 libcunit1-dev net-tools valgrind cppcheck
