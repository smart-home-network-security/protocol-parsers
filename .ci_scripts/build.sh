#!/bin/bash

# Build the project.
# Usage: build.sh [-C working_directory] [-t cmake_toolchain_file]
#   -C working_directory: The directory to build the project in.

# Default values
WORKING_DIRECTORY=""

# Print usage information
usage() {
    echo "Usage: $0 [-C working_directory]" 1>&2
    exit 1
}

# Parse command line arguments
while getopts "C:" opt;
do
    case "${opt}" in
        C)
            # Working directory
            WORKING_DIRECTORY="${OPTARG}"
            echo "Building in directory ${WORKING_DIRECTORY}"
            ;;
        *)
            usage
            ;;
    esac
done
shift $((OPTIND-1))

# Change to working directory if specified
if [[ $WORKING_DIRECTORY ]]
then
    cd $WORKING_DIRECTORY
fi

# Clean directory
sudo rm -rf build bin

# Build project
mkdir build bin
cd build
cmake ..
cmake --build .
