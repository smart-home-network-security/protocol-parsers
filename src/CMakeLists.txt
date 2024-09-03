# Minimum required CMake version
cmake_minimum_required(VERSION 3.20)

# hashmap
add_library(hashmap STATIC ${HASHMAP_DIR}/hashmap.h ${HASHMAP_DIR}/hashmap.c)
target_include_directories(hashmap PRIVATE ${HASHMAP_DIR})
install(TARGETS hashmap DESTINATION ${LIB_DIR})

# SHA256
add_library(sha256 STATIC ${INCLUDE_DIR}/sha256.h sha256.c)
target_include_directories(sha256 PRIVATE ${INCLUDE_DIR})
install(TARGETS sha256 DESTINATION ${LIB_DIR})

# packet_utils
add_library(packet_utils STATIC ${INCLUDE_DIR}/packet_utils.h packet_utils.c)
target_link_libraries(packet_utils sha256)
target_include_directories(packet_utils PRIVATE ${INCLUDE_DIR})
install(TARGETS packet_utils DESTINATION ${LIB_DIR})

## Protocol parsers
# Header parser
add_library(header STATIC ${INCLUDE_DIR}/header.h header.c)
target_include_directories(header PRIVATE ${INCLUDE_DIR} ${INCLUDE_DIR})
target_link_libraries(header packet_utils)
install(TARGETS header DESTINATION ${LIB_DIR})
# DNS parser
add_library(dns STATIC ${INCLUDE_DIR}/dns.h dns.c)
target_include_directories(dns PRIVATE ${INCLUDE_DIR} ${INCLUDE_DIR})
target_link_libraries(dns packet_utils dns_map)
install(TARGETS dns DESTINATION ${LIB_DIR})
# DHCP parser
add_library(dhcp STATIC ${INCLUDE_DIR}/dhcp.h dhcp.c)
target_include_directories(dhcp PRIVATE ${INCLUDE_DIR} ${INCLUDE_DIR})
install(TARGETS dhcp DESTINATION ${LIB_DIR})
# HTTP parser
add_library(http STATIC ${INCLUDE_DIR}/http.h http.c)
target_include_directories(http PRIVATE ${INCLUDE_DIR} ${INCLUDE_DIR})
install(TARGETS http DESTINATION ${LIB_DIR})
# IGMP parser
add_library(igmp STATIC ${INCLUDE_DIR}/igmp.h igmp.c)
target_include_directories(igmp PRIVATE ${INCLUDE_DIR} ${INCLUDE_DIR})
install(TARGETS igmp DESTINATION ${LIB_DIR})
# SSDP parser
add_library(ssdp STATIC ${INCLUDE_DIR}/ssdp.h ssdp.c)
target_include_directories(ssdp PRIVATE ${INCLUDE_DIR} ${INCLUDE_DIR})
install(TARGETS ssdp DESTINATION ${LIB_DIR})
# CoAP parser
add_library(coap STATIC ${INCLUDE_DIR}/coap.h coap.c)
target_include_directories(coap PRIVATE ${INCLUDE_DIR} ${INCLUDE_DIR})
target_link_libraries(coap http)
install(TARGETS coap DESTINATION ${LIB_DIR})

# DNS map
add_library(dns_map STATIC ${INCLUDE_DIR}/dns_map.h dns_map.c)
target_link_libraries(dns_map hashmap)
target_include_directories(dns_map PRIVATE ${INCLUDE_DIR})
install(TARGETS dns_map DESTINATION ${LIB_DIR})
