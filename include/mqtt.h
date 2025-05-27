/**
 * @file include/parsers/mqtt.h
 * @author Mehdi Laurent (mehdi.laurent@student.uclouvain.be)
 * @brief MQTT message parser header file
 * @date 2024-08-05
 * 
 * @copyright (c) 2024
 * 
 * Disclaimer: the content of this file has been enhanced using the Claude AI assistant tool.
 * 
 */

#ifndef _PROTOCOL_PARSERS_MQTT_
#define _PROTOCOL_PARSERS_MQTT_

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <regex.h>
#include <arpa/inet.h>

/**
 * MQTT Control Packet types
 */
typedef enum {
    MQTT_CONNECT = 1,
    MQTT_CONNACK = 2,
    MQTT_PUBLISH = 3,
    MQTT_PUBACK = 4,
    MQTT_PUBREC = 5,
    MQTT_PUBREL = 6,
    MQTT_PUBCOMP = 7,
    MQTT_SUBSCRIBE = 8,
    MQTT_SUBACK = 9,
    MQTT_UNSUBSCRIBE = 10,
    MQTT_UNSUBACK = 11,
    MQTT_PINGREQ = 12,
    MQTT_PINGRESP = 13,
    MQTT_DISCONNECT = 14,
} mqtt_packet_type_t;

/**
 * MQTT versions
 */
typedef enum {
    MQTT_VERSION_3_1 = 3,
    MQTT_VERSION_3_1_1 = 4,
    MQTT_VERSION_5_0 = 5,
} mqtt_version_t;

/**
 * Maximum length for topic name
 */
#define MQTT_MAX_TOPIC_LENGTH 256

/**
 * Maximum length for payload
 */
#define MQTT_MAX_PAYLOAD_LENGTH 2048

/**
 * Maximum length for client ID
 */
#define MQTT_MAX_CLIENT_ID_LENGTH 128

/**
 * Maximum number of subscribe topics in a single message
 */
#define MQTT_MAX_SUBSCRIBE_TOPICS 16

/**
 * CONNECT flags structure
 */
typedef struct mqtt_connect_flags {
    bool clean_session;
    bool will_flag;
    uint8_t will_qos;
    bool will_retain;
    bool password_flag;
    bool username_flag;
} mqtt_connect_flags_t;

/**
 * Subscribe topic structure
 */
typedef struct mqtt_subscribe_topic {
    char topic_filter[MQTT_MAX_TOPIC_LENGTH];
    uint16_t topic_filter_length;
    uint8_t requested_qos;
} mqtt_subscribe_topic_t;

/**
 * Abstraction of an MQTT message
 * 
 * Only relevant fields for the IoT firewall are included.
 */
typedef struct mqtt_message {
    mqtt_version_t mqtt_version;
    uint32_t remaining_length;

    /* Fixed Header */
    mqtt_packet_type_t packet_type;
    bool dup_flag;
    uint8_t qos_level;
    bool retain_flag;

    /* Variable Header */
    bool session_present;  // For CONNACK

    /* CONNECT specific fields */
    mqtt_connect_flags_t connect_flags;
    uint16_t keep_alive;
    char client_id[MQTT_MAX_CLIENT_ID_LENGTH];
    uint16_t client_id_length;
    
    /* SUBSCRIBE specific fields */
    uint16_t subscribe_packet_id;
    uint8_t subscribe_topic_count;
    mqtt_subscribe_topic_t subscribe_topics[MQTT_MAX_SUBSCRIBE_TOPICS];

    /* PUBLISH specific fields */
    uint16_t topic_length;
    char topic_name[MQTT_MAX_TOPIC_LENGTH];
    uint16_t payload_length;
    uint8_t payload[MQTT_MAX_PAYLOAD_LENGTH];
    uint16_t packet_identifier;  // Only present for QoS > 0
    
} mqtt_message_t;

////////// FUNCTIONS //////////

///// PARSING /////

/**
 * @brief Check if a TCP message is an MQTT message.
 * 
 * @param data Pointer to the start of the TCP payload
 * @return true if the message is a valid MQTT message, false otherwise
 */
bool is_mqtt(uint8_t *data);

/**
 * @brief Parse an MQTT message into a structured representation.
 * 
 * @param data Pointer to the start of the MQTT message
 * @return mqtt_message_t Structured representation of the MQTT message, zeroed if parsing failed
 */
mqtt_message_t mqtt_parse_message(uint8_t *data);

/**
 * @brief Print the contents of an MQTT message to standard output.
 * 
 * @param message The MQTT message structure to print
 */
void mqtt_print_message(mqtt_message_t message);

/**
 * @brief Check if an MQTT payload matches a given regex pattern.
 * 
 * @param payload pointer to the start of the payload
 * @param payload_len length of the payload in bytes
 * @param regex_pattern the regex pattern to match against the payload
 * @return true if the payload matches the pattern, false if no match or error occurs
 */
bool check_payload_regex(const uint8_t *payload, size_t payload_len, const char *regex_pattern);

#endif /* _PROTOCOL_PARSERS_MQTT_ */
