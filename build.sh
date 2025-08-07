#!/bin/bash

# Build the project.
# Usage: build.sh [-C working_directory] [-T]
#   -C working_directory: The directory to build the project in.
#   -T: Whether to build tests.

# Default values
WORKING_DIRECTORY=""
DO_TESTS=""

# Print usage information
usage() {
    echo "Usage: $0 [-C working_directory] [-T]" 1>&2
    exit 1
}

# Parse command line arguments
while getopts "C:T" opt;
do
    case "${opt}" in
        C)
            # Working directory
            WORKING_DIRECTORY="${OPTARG}"
            echo "Building in directory ${WORKING_DIRECTORY}"
            ;;
        T)
            # Whether to build tests
            DO_TESTS="TRUE"
            echo "Building tests"
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
rm -rf build bin

## Environmental variables
ENV_VARS=""
# Whether to build tests
if [[ $DO_TESTS ]]
then
    ENV_VARS="$ENV_VARS -DDO_TESTS=TRUE"
fi

# Build project
mkdir build bin
cd build
cmake $ENV_VARS ..
cmake --build .
