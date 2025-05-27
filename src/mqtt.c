/** 
 * 
 * @file src/parsers/mqtt.c
 * @author Mehdi Laurent (mehdi.laurent@student.uclouvain.be)
 * @brief MQTT message parser header file
 * @date 2024-08-05
 * 
 * @copyright (c) 2024
 *  
 * Disclaimer: the content of this file has been enhanced using the Claude AI assistant tool.
 * 
 */

#include "mqtt.h"

/**
 * @brief Parse the variable-length encoding of the remaining length field.
 * 
 * @param data Pointer to the start of the remaining length bytes
 * @param value Pointer to store the decoded value
 * @return int Number of bytes used to encode the remaining length
 */
static int parse_remaining_length(const uint8_t *data, uint32_t *value) {
    int multiplier = 1;
    int bytes_read = 0;
    uint32_t length = 0;
    uint8_t encoded_byte;

    do {
        encoded_byte = data[bytes_read];
        length += (encoded_byte & 127) * multiplier;
        multiplier *= 128;
        bytes_read++;
    } while ((encoded_byte & 128) != 0 && bytes_read < 4);

    *value = length;
    return bytes_read;
}

/**
 * @brief Parse CONNECT flags from the variable header.
 * 
 * @param byte The flags byte from the CONNECT packet
 * @return mqtt_connect_flags_t Structured representation of the connection flags
 */
static mqtt_connect_flags_t parse_connect_flags(uint8_t byte) {
    mqtt_connect_flags_t flags = {0};
    flags.clean_session = (byte & 0x02) >> 1;
    flags.will_flag = (byte & 0x04) >> 2;
    flags.will_qos = (byte & 0x18) >> 3;
    flags.will_retain = (byte & 0x20) >> 5;
    flags.password_flag = (byte & 0x40) >> 6;
    flags.username_flag = (byte & 0x80) >> 7;
    return flags;
}

/**
 * @brief Parse CONNECT packet content from the variable header and payload.
 * 
 * @param data Pointer to the start of the variable header
 * @param msg Pointer to message structure to populate
 * @param remaining_length Total remaining length of the packet
 * @return true if parsing was successful, false if errors occurred
 */
static bool parse_connect_content(uint8_t *data, mqtt_message_t *msg, uint32_t remaining_length) {
    uint16_t bytes_processed = 0;

    // Protocol Name Length and Value (already verified in is_mqtt)
    uint16_t protocol_name_length = ntohs(*(uint16_t *)data);
    bytes_processed += 2 + protocol_name_length;

    // Protocol Version
    msg->mqtt_version = (mqtt_version_t)(data[bytes_processed]);
    bytes_processed++;

    // Connect Flags
    msg->connect_flags = parse_connect_flags(data[bytes_processed]);
    bytes_processed++;

    // Keep Alive
    msg->keep_alive = ntohs(*(uint16_t *)(data + bytes_processed));
    bytes_processed += 2;

    // Client ID Length
    uint16_t client_id_length = ntohs(*(uint16_t *)(data + bytes_processed));
    bytes_processed += 2;

    if (client_id_length > MQTT_MAX_CLIENT_ID_LENGTH) {
        return false;
    }

    // Client ID
    msg->client_id_length = client_id_length;
    memcpy(msg->client_id, data + bytes_processed, client_id_length);
    msg->client_id[client_id_length] = '\0';

    return true;
}

/**
 * @brief Parse SUBSCRIBE packet content from the variable header and payload.
 * 
 * @param data Pointer to the start of the variable header
 * @param msg Pointer to message structure to populate
 * @param remaining_length Total remaining length of the packet
 * @return true if parsing was successful, false if errors occurred
 */
static bool parse_subscribe_content(uint8_t *data, mqtt_message_t *msg, uint32_t remaining_length) {
    uint16_t bytes_processed = 0;

    // Packet Identifier
    msg->subscribe_packet_id = ntohs(*(uint16_t *)data);
    bytes_processed += 2;

    msg->subscribe_topic_count = 0;
    
    // Parse topic filters
    while (bytes_processed < remaining_length && 
           msg->subscribe_topic_count < MQTT_MAX_SUBSCRIBE_TOPICS) {
        
        // Topic Filter Length
        uint16_t topic_length = ntohs(*(uint16_t *)(data + bytes_processed));
        bytes_processed += 2;

        if (topic_length > MQTT_MAX_TOPIC_LENGTH || 
            bytes_processed + topic_length + 1 > remaining_length) {
            return false;
        }

        // Topic Filter
        mqtt_subscribe_topic_t *topic = &msg->subscribe_topics[msg->subscribe_topic_count];
        memcpy(topic->topic_filter, data + bytes_processed, topic_length);
        topic->topic_filter[topic_length] = '\0';
        topic->topic_filter_length = topic_length;
        bytes_processed += topic_length;

        // Requested QoS
        topic->requested_qos = data[bytes_processed] & 0x03;
        bytes_processed++;

        msg->subscribe_topic_count++;
    }

    return msg->subscribe_topic_count > 0;
}

/**
 * @brief Parse SUBSCRIBE packet content from the variable header and payload.
 * 
 * @param data Pointer to the start of the variable header
 * @param msg Pointer to message structure to populate
 * @param remaining_length Total remaining length of the packet
 * @return true if parsing was successful, false if errors occurred
 */
static bool parse_publish_content(uint8_t *data, mqtt_message_t *msg, uint32_t remaining_length) {
    uint16_t bytes_processed = 0;

    // Parse topic length (2 bytes)
    msg->topic_length = ntohs(*(uint16_t *)data);
    bytes_processed += 2;

    // Validate topic length
    if (msg->topic_length > MQTT_MAX_TOPIC_LENGTH || 
        msg->topic_length > remaining_length - bytes_processed) {
        return false;
    }

    // Copy topic name
    memcpy(msg->topic_name, data + bytes_processed, msg->topic_length);
    msg->topic_name[msg->topic_length] = '\0';
    bytes_processed += msg->topic_length;

    // If QoS > 0, packet identifier is present (2 bytes)
    if (msg->qos_level > 0) {
        if (bytes_processed + 2 > remaining_length) {
            return false;
        }
        msg->packet_identifier = ntohs(*(uint16_t *)(data + bytes_processed));
        bytes_processed += 2;
    }

    // Calculate payload length
    if (remaining_length > bytes_processed) {
        msg->payload_length = remaining_length - bytes_processed;
        if (msg->payload_length > MQTT_MAX_PAYLOAD_LENGTH) {
            msg->payload_length = MQTT_MAX_PAYLOAD_LENGTH;  // Truncate if too long
        }
        memcpy(msg->payload, data + bytes_processed, msg->payload_length);
    } else {
        msg->payload_length = 0;
    }

    return true;
}

/**
 * @brief Check if a TCP message is an MQTT message.
 * 
 * @param data Pointer to the start of the TCP payload
 * @return true if the message is a valid MQTT message, false otherwise
 */
bool is_mqtt(uint8_t *data) {
    if (!data) return false;

    uint8_t first_byte = data[0];
    uint8_t packet_type = (first_byte >> 4) & 0x0F;

    // Check if packet type is valid (1-14)
    if (packet_type < 1 || packet_type > 14) {
        return false;
    }

    // For CONNECT packets, verify protocol name
    if (packet_type == MQTT_CONNECT) {
        uint32_t remaining_length;
        int bytes_used = parse_remaining_length(data + 1, &remaining_length);
        
        // Check minimum length for CONNECT packet
        if (remaining_length < 7) {
            return false;
        }

        // Get protocol name length
        uint16_t protocol_name_length = ntohs(*(uint16_t *)(data + 1 + bytes_used));
        
        // Verify protocol name length is 4 (for "MQTT")
        if (protocol_name_length != 4) {
            return false;
        }

        // Check if protocol name is "MQTT"
        if (memcmp(data + 1 + bytes_used + 2, "MQTT", 4) != 0) {
            return false;
        }
    }

    return true;
}

/**
 * @brief Parse an MQTT message into a structured representation.
 * 
 * @param data Pointer to the start of the MQTT message
 * @return mqtt_message_t Structured representation of the MQTT message, zeroed if parsing failed
 */
mqtt_message_t mqtt_parse_message(uint8_t *data) {
    mqtt_message_t msg = {0};  // Initialize all fields to 0
    if (!data) return msg;

    // Parse Fixed Header
    uint8_t first_byte = data[0];
    msg.packet_type = (mqtt_packet_type_t)((first_byte >> 4) & 0x0F);
    msg.dup_flag = (first_byte & 0x08) >> 3;
    msg.qos_level = (first_byte & 0x06) >> 1;
    msg.retain_flag = first_byte & 0x01;

    // Parse Remaining Length
    uint32_t remaining_length;
    int bytes_used = parse_remaining_length(data + 1, &remaining_length);
    msg.remaining_length = remaining_length;

    // Point to start of variable header
    uint8_t *variable_header = data + 1 + bytes_used;

    switch (msg.packet_type) {
        case MQTT_CONNECT:
            if (!parse_connect_content(variable_header, &msg, remaining_length)) {
                memset(&msg, 0, sizeof(mqtt_message_t));
            }
            break;

        case MQTT_CONNACK:
            msg.session_present = (*variable_header & 0x01) == 0x01;
            break;

        case MQTT_PUBLISH:
            if (!parse_publish_content(variable_header, &msg, remaining_length)) {
                memset(&msg, 0, sizeof(mqtt_message_t));
            }
            break;

        case MQTT_SUBSCRIBE:
            if (!parse_subscribe_content(variable_header, &msg, remaining_length)) {
                memset(&msg, 0, sizeof(mqtt_message_t));
            }
            break;

        default:
            break;
    }

    return msg;
}


/**
 * @brief Check if an MQTT payload matches a given regex pattern.
 * 
 * @param payload pointer to the start of the payload
 * @param payload_len length of the payload in bytes
 * @param regex_pattern the regex pattern to match against the payload
 * @return true if the payload matches the pattern, false if no match or error occurs
 */
bool check_payload_regex(const uint8_t *payload, size_t payload_len, const char *regex_pattern) {
    regex_t regex;
    int reti;
    bool result = false;
    
    // Compile regex pattern
    reti = regcomp(&regex, regex_pattern, REG_EXTENDED);
    if (reti) {
        return false;
    }
    
    // Create null-terminated string from payload
    char *payload_str = (char *)malloc(payload_len + 1);
    if (!payload_str) {
        regfree(&regex);
        return false;
    }
    
    memcpy(payload_str, payload, payload_len);
    payload_str[payload_len] = '\0';
    
    // Execute regex matching
    reti = regexec(&regex, payload_str, 0, NULL, 0);
    if (!reti) {
        result = true;
    }
    
    // Cleanup
    free(payload_str);
    regfree(&regex);
    
    return result;
}



/**
 * @brief Print the contents of an MQTT message to standard output.
 * 
 * @param message The MQTT message structure to print
 */
void mqtt_print_message(mqtt_message_t message) {
    printf("MQTT Message:\n");
    printf("  Packet Type: %d\n", message.packet_type);
    printf("  Remaining Length: %d\n", message.remaining_length);
    printf("  DUP Flag: %d\n", message.dup_flag);
    printf("  QoS Level: %d\n", message.qos_level);
    printf("  Retain Flag: %d\n", message.retain_flag);

    if (message.packet_type == MQTT_PUBLISH) {
        printf("  Topic Name: %s\n", message.topic_name);
        printf("  Payload Length: %d\n", message.payload_length);
        // printf("  Payload: ");
        // for (int i = 0; i < message.payload_length; i++) {
        //     printf("%02X ", message.payload[i]);
        // }
        // printf("\n");
    }
    else if (message.packet_type == MQTT_CONNECT) {
        printf("  MQTT Version: %d\n", message.mqtt_version);
        printf("  Clean Session: %d\n", message.connect_flags.clean_session);
        printf("  Will Flag: %d\n", message.connect_flags.will_flag);
        printf("  Will QoS: %d\n", message.connect_flags.will_qos);
        printf("  Will Retain: %d\n", message.connect_flags.will_retain);
        printf("  Password Flag: %d\n", message.connect_flags.password_flag);
        printf("  Username Flag: %d\n", message.connect_flags.username_flag);
        printf("  Keep Alive: %d\n", message.keep_alive);
        printf("  Client ID: %s\n", message.client_id);
    }
    else if (message.packet_type == MQTT_SUBSCRIBE) {
        printf("  Packet Identifier: %d\n", message.subscribe_packet_id);
        printf("  Topic Count: %d\n", message.subscribe_topic_count);
        // for (int i = 0; i < message.subscribe_topic_count; i++) {
            // printf("    Topic Filter: %s\n", message.subscribe_topics[i].topic_filter);
            // printf("    Requested QoS: %d\n", message.subscribe_topics[i].requested_qos);
        // }
    }
    else if (message.packet_type == MQTT_CONNACK) {
        printf("  Session Present: %d\n", message.session_present);
    }
}
