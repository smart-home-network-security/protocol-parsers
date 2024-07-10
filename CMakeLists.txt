# Minimum required CMake version
cmake_minimum_required(VERSION 3.20)

# Project name
project(protocol-parsers C)

## Set project directories
link_directories($ENV{LD_LIBRARY_PATH})
set(CMAKE_INSTALL_PREFIX ${PROJECT_SOURCE_DIR})
set(INCLUDE_DIR ${PROJECT_SOURCE_DIR}/include)
set(LIB_DIR ${PROJECT_SOURCE_DIR}/lib)
set(BIN_DIR ${PROJECT_SOURCE_DIR}/bin)
set(EXECUTABLE_OUTPUT_PATH ${BIN_DIR})
# Hashmap directory
set(HASHMAP_DIR ${PROJECT_SOURCE_DIR}/src/hashmap)

# Set compiler flags
#add_compile_options(-Wall -Werror -Wno-unused-variable -DDEBUG)   # Debug
#add_compile_options(-Wall -Werror -Wno-unused-variable -DLOG)     # Logging
#add_compile_options(-Wall -Werror -Wno-unused-variable)           # Production
# With optimisation
#add_compile_options(-Wall -Werror -Wno-unused-variable -O3 -DDEBUG)   # Debug
#add_compile_options(-Wall -Werror -Wno-unused-variable -O3 -DLOG)     # Packet Logging
add_compile_options(-Wall -Werror -Wno-unused-variable -O3)           # Production
# With debug symbols
#add_compile_options(-Wall -Werror -Wno-unused-variable -g)  # Without debug logging
#add_compile_options(-Wall -Werror -Wno-unused-variable -DDEBUG -g)  # With debug logging

# Custom parsers
set(PARSERS header dns dhcp http igmp ssdp coap)

# Subdirectories containing code
add_subdirectory(src)
IF( NOT OPENWRT_CROSSCOMPILING )
    add_subdirectory(test)
ENDIF()
