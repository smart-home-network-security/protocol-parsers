# Minimum required CMake version
cmake_minimum_required(VERSION 3.20)

# Set test output directory
set(TEST_BIN_DIR ${BIN_DIR}/test)
set(EXECUTABLE_OUTPUT_PATH ${TEST_BIN_DIR})

# Packet utils test
add_executable(packet_utils-test packet_utils.c)
target_include_directories(packet_utils-test PRIVATE ${INCLUDE_DIR})
target_link_libraries(packet_utils-test cunit)
target_link_libraries(packet_utils-test packet_utils)
install(TARGETS packet_utils-test DESTINATION ${TEST_BIN_DIR})


## Protocol parsers

# Header
add_executable(header-test header.c)
target_include_directories(header-test PRIVATE ${INCLUDE_DIR})
target_link_libraries(header-test cunit)
target_link_libraries(header-test packet_utils)
target_link_libraries(header-test header)
install(TARGETS header-test DESTINATION ${TEST_BIN_DIR})

# DNS
add_executable(dns-test dns.c)
target_include_directories(dns-test PRIVATE ${INCLUDE_DIR})
target_link_libraries(dns-test cunit)
target_link_libraries(dns-test packet_utils)
target_link_libraries(dns-test header dns)
install(TARGETS dns-test DESTINATION ${TEST_BIN_DIR})

# DHCP
add_executable(dhcp-test dhcp.c)
target_include_directories(dhcp-test PRIVATE ${INCLUDE_DIR})
target_link_libraries(dhcp-test cunit)
target_link_libraries(dhcp-test packet_utils)
target_link_libraries(dhcp-test header dhcp)
install(TARGETS dhcp-test DESTINATION ${TEST_BIN_DIR})

# HTTP
add_executable(http-test http.c)
target_include_directories(http-test PRIVATE ${INCLUDE_DIR})
target_link_libraries(http-test cunit)
target_link_libraries(http-test packet_utils)
target_link_libraries(http-test header http)
install(TARGETS http-test DESTINATION ${TEST_BIN_DIR})

# IGMP
add_executable(igmp-test igmp.c)
target_include_directories(igmp-test PRIVATE ${INCLUDE_DIR})
target_link_libraries(igmp-test cunit)
target_link_libraries(igmp-test packet_utils)
target_link_libraries(igmp-test header igmp)
install(TARGETS igmp-test DESTINATION ${TEST_BIN_DIR})

# SSDP
add_executable(ssdp-test ssdp.c)
target_include_directories(ssdp-test PRIVATE ${INCLUDE_DIR})
target_link_libraries(ssdp-test cunit)
target_link_libraries(ssdp-test packet_utils)
target_link_libraries(ssdp-test header ssdp)
install(TARGETS ssdp-test DESTINATION ${TEST_BIN_DIR})

# CoAP
add_executable(coap-test coap.c)
target_include_directories(coap-test PRIVATE ${INCLUDE_DIR})
target_link_libraries(coap-test cunit)
target_link_libraries(coap-test packet_utils)
target_link_libraries(coap-test header coap)
install(TARGETS coap-test DESTINATION ${TEST_BIN_DIR})


## DNS map
add_executable(dns_map-test dns_map.c)
target_include_directories(dns_map-test PRIVATE ${INCLUDE_DIR})
target_link_libraries(dns_map-test cunit)
target_link_libraries(dns_map-test hashmap)
target_link_libraries(dns_map-test packet_utils)
target_link_libraries(dns_map-test dns_map)
install(TARGETS dns_map-test DESTINATION ${TEST_BIN_DIR})
