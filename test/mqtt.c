/**
 * @file test/parsers/mqtt.c
 * @author Mehdi Laurent (mehdi.laurent@student.uclouvain.be)
 * @brief Unit test for the MQTT parser
 * @date 2024-08-05
 * 
 * @copyright (c) 2024
 * 
 * Disclaimer: the content of this file has been enhanced using the Claude AI assistant tool.
 * 
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
// Custom libraries
#include "packet_utils.h"
#include "mqtt.h"
// CUnit
#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>



/**
 * @brief Compare the fields of two MQTT messages structures.
 * 
 * Only the fields pertinent to the IoT firewall are set in the structures.
 * 
 * @param expected expected MQTT message
 * @param actual actual MQTT message
 */
void compare_fields(mqtt_message_t expected, mqtt_message_t actual) {

    CU_ASSERT_EQUAL(expected.packet_type, actual.packet_type);
    CU_ASSERT_EQUAL(expected.mqtt_version, actual.mqtt_version);
    CU_ASSERT_EQUAL(expected.dup_flag, actual.dup_flag);
    CU_ASSERT_EQUAL(expected.qos_level, actual.qos_level);
    CU_ASSERT_EQUAL(expected.retain_flag, actual.retain_flag);
    CU_ASSERT_EQUAL(expected.session_present, actual.session_present);

    if (expected.packet_type == MQTT_PUBLISH) {
        
        CU_ASSERT_EQUAL(expected.topic_length, actual.topic_length);
        CU_ASSERT_EQUAL(expected.payload_length, actual.payload_length);
        CU_ASSERT_STRING_EQUAL(expected.topic_name, actual.topic_name);
        CU_ASSERT_EQUAL(expected.packet_identifier, actual.packet_identifier);
    }

}

/**
 * @brief Test that TCP payloads are correctly identified as MQTT messages.
 * 
 * Verifies that the is_mqtt() function correctly returns true for
 * a valid MQTT CONNECT message. This tests the basic identification
 * logic of the MQTT parser.
 */
void test_is_mqtt() {
    
    char* hexstring = "45000041000100004006f638c0a801c9c0a80164c000075b00000f0f00000f9650182000e3030000101700044d5154540402003c000b74656d705f73656e736f72"; // MQTT Connect Ack

    uint8_t *payload;
    size_t length = hexstr_to_payload(hexstring, &payload);
    CU_ASSERT_EQUAL(length, strlen(hexstring) / 2);

    CU_ASSERT_TRUE(is_mqtt(payload));

    free(payload);
}

/**
 * @brief Test parsing of an MQTT PUBLISH message with temperature data.
 * 
 * Tests the correct identification and parsing of an MQTT PUBLISH message
 * containing temperature sensor data (20.7°C). Verifies that the parser correctly
 * extracts the topic name, payload, QoS level, and other relevant fields.
 * 
 * This test focuses on PUBLISH messages which are common in IoT device communication.
 */
void parse_publish_temperature_msg_example() {
    char* hexstring = "3014000b74656d706572617475726532302e37c2b043"; // MQTT Publish Temperature 20.7°C

    uint8_t *payload;
    size_t length = hexstr_to_payload(hexstring, &payload);
    CU_ASSERT_EQUAL(length, strlen(hexstring) / 2);

    mqtt_message_t expected;

    expected.packet_type = MQTT_PUBLISH;
    expected.mqtt_version = 0; // info missing from the payload
    expected.dup_flag = 0;
    expected.qos_level = 0;
    expected.retain_flag = 0;
    expected.session_present = 0;
    expected.topic_length = 11;
    expected.payload_length = 7;
    strcpy(expected.topic_name, "temperature");
    expected.packet_identifier = 0;

    mqtt_message_t actual = mqtt_parse_message(payload);

    compare_fields(expected, actual);

    free(payload);
}

/**
 * @brief Test parsing of an MQTT PUBLISH message with humidity data.
 * 
 * Tests the correct identification and parsing of an MQTT PUBLISH message
 * containing humidity sensor data (51.7%). Verifies that the parser correctly
 * extracts the topic name, payload, QoS level, and other relevant fields.
 * 
 * This test provides additional coverage for PUBLISH messages with different
 * topic names and payload formats.
 */
void parse_publish_humidity_msg_example() {
    char* hexstring = "300f000868756d696469747935312e3725"; // MQTT Publish Humidity 51.7%

    uint8_t *payload;
    size_t length = hexstr_to_payload(hexstring, &payload);
    CU_ASSERT_EQUAL(length, strlen(hexstring) / 2);

    mqtt_message_t expected;

    expected.packet_type = MQTT_PUBLISH;
    expected.mqtt_version = 0; // info missing from the payload
    expected.dup_flag = 0;
    expected.qos_level = 0;
    expected.retain_flag = 0;
    expected.session_present = 0;
    expected.topic_length = 8;
    expected.payload_length = 5;
    strcpy(expected.topic_name, "humidity");
    expected.packet_identifier = 0;

    mqtt_message_t actual = mqtt_parse_message(payload);

    compare_fields(expected, actual);

    free(payload);
}

/**
 * @brief Test parsing of an MQTT CONNECT message.
 * 
 * Tests the correct identification and parsing of an MQTT CONNECT message
 * from a temperature sensor device. Verifies that the parser correctly extracts 
 * the client ID, protocol version, keep alive interval, and connect flags.
 * 
 * CONNECT messages are essential for establishing MQTT sessions and contain
 * important device identification information.
 */
void parse_connect_command_msg_example() {
    char* hexstring = "101900044d5154540402003c000d74656d705f73656e736f725f31"; // MQTT Connect Command

    uint8_t *payload;
    size_t length = hexstr_to_payload(hexstring, &payload);
    CU_ASSERT_EQUAL(length, strlen(hexstring) / 2);

    mqtt_message_t expected;
    memset(&expected, 0, sizeof(mqtt_message_t));  // Initialize all fields to 0

    // Fixed header fields
    expected.packet_type = MQTT_CONNECT;
    expected.mqtt_version = MQTT_VERSION_3_1_1;  // Version 4 (MQTT 3.1.1)
    expected.dup_flag = 0;
    expected.qos_level = 0;
    expected.retain_flag = 0;

    // Connect-specific fields
    expected.keep_alive = 60;  // 0x003c = 60 seconds
    expected.client_id_length = 13;  // 0x000d = 13 bytes
    strcpy(expected.client_id, "temp_sensor_1");

    // Connect flags
    expected.connect_flags.clean_session = 1;
    expected.connect_flags.will_flag = 0;
    expected.connect_flags.will_qos = 0;
    expected.connect_flags.will_retain = 0;
    expected.connect_flags.password_flag = 0;
    expected.connect_flags.username_flag = 0;

    mqtt_message_t actual = mqtt_parse_message(payload);

    // Compare fields
    compare_fields(expected, actual);
    
    // Additional CONNECT-specific assertions
    CU_ASSERT_EQUAL(expected.keep_alive, actual.keep_alive);
    CU_ASSERT_EQUAL(expected.client_id_length, actual.client_id_length);
    CU_ASSERT_STRING_EQUAL(expected.client_id, actual.client_id);
    
    // Compare connect flags
    CU_ASSERT_EQUAL(expected.connect_flags.clean_session, actual.connect_flags.clean_session);
    CU_ASSERT_EQUAL(expected.connect_flags.will_flag, actual.connect_flags.will_flag);
    CU_ASSERT_EQUAL(expected.connect_flags.will_qos, actual.connect_flags.will_qos);
    CU_ASSERT_EQUAL(expected.connect_flags.will_retain, actual.connect_flags.will_retain);
    CU_ASSERT_EQUAL(expected.connect_flags.password_flag, actual.connect_flags.password_flag);
    CU_ASSERT_EQUAL(expected.connect_flags.username_flag, actual.connect_flags.username_flag);

    free(payload);
}

/**
 * @brief Test parsing of an MQTT SUBSCRIBE message.
 * 
 * Tests the correct identification and parsing of an MQTT SUBSCRIBE message
 * requesting updates for a temperature topic. Verifies that the parser correctly
 * extracts the packet identifier, topic filters, requested QoS levels, and
 * other relevant fields.
 * 
 * SUBSCRIBE messages are important for understanding what data topics IoT devices
 * are interested in receiving.
 */
void parse_subscribe_request_msg_example() {
    char* hexstring = "82100001000b74656d706572617475726500"; // MQTT Subscribe Request

    uint8_t *payload;
    size_t length = hexstr_to_payload(hexstring, &payload);
    CU_ASSERT_EQUAL(length, strlen(hexstring) / 2);

    mqtt_message_t expected;
    memset(&expected, 0, sizeof(mqtt_message_t));  // Initialize all fields to 0

    // Fixed header fields
    expected.packet_type = MQTT_SUBSCRIBE;
    expected.mqtt_version = 0;  // Not specified in SUBSCRIBE packet
    expected.dup_flag = 0;
    expected.qos_level = 1;  // QoS 1 for SUBSCRIBE packet
    expected.retain_flag = 0;

    // Subscribe-specific fields
    expected.subscribe_packet_id = 1;  // Packet identifier = 1
    expected.subscribe_topic_count = 1;

    // First (and only) topic in subscription
    expected.subscribe_topics[0].topic_filter_length = 11;  // 0x000b = 11 bytes
    strcpy(expected.subscribe_topics[0].topic_filter, "temperature");
    expected.subscribe_topics[0].requested_qos = 0;  // QoS 0 requested for subscription

    mqtt_message_t actual = mqtt_parse_message(payload);

    // Compare common fields
    compare_fields(expected, actual);
    
    // Additional SUBSCRIBE-specific assertions
    CU_ASSERT_EQUAL(expected.subscribe_packet_id, actual.subscribe_packet_id);
    CU_ASSERT_EQUAL(expected.subscribe_topic_count, actual.subscribe_topic_count);
    
    // Compare first topic
    CU_ASSERT_EQUAL(expected.subscribe_topics[0].topic_filter_length, 
                    actual.subscribe_topics[0].topic_filter_length);
    CU_ASSERT_STRING_EQUAL(expected.subscribe_topics[0].topic_filter, 
                          actual.subscribe_topics[0].topic_filter);
    CU_ASSERT_EQUAL(expected.subscribe_topics[0].requested_qos, 
                    actual.subscribe_topics[0].requested_qos);
    
    free(payload);
}

/**
 * @brief Test regex validation of an MQTT payload containing humidity data.
 * 
 * Verifies that the check_payload_regex() function correctly validates
 * an MQTT payload containing a humidity reading (58.9%) against a pattern
 * that matches humidity percentage values.
 * 
 * This test demonstrates how payload content can be validated for specific
 * data formats, which is useful for IoT firewall filtering.
 */
void test_payload_humidity_regex() {
    /*
    MQ Telemetry Transport Protocol, Publish Message
    Header Flags: 0x30, Message Type: Publish Message, QoS Level: At most once delivery (Fire and Forget)
    Msg Len: 15
    Topic Length: 8
    Topic: humidity
    Message: 35382e3925 // 58.9%
    */

    char* hexstring = "300f000868756d696469747935382e3925";

    uint8_t *payload;
    size_t length = hexstr_to_payload(hexstring, &payload);
    CU_ASSERT_EQUAL(length, strlen(hexstring) / 2);


    mqtt_message_t actual = mqtt_parse_message(payload);

    const char *humidity_regex = "[0-9]?[0-9]\\.[0-9]%";
    bool is_valid = check_payload_regex(actual.payload, strlen((char *)actual.payload), humidity_regex);

    CU_ASSERT_TRUE(is_valid);

    free(payload);
}

/**
 * @brief Test regex validation of an MQTT payload containing temperature data.
 * 
 * Verifies that the check_payload_regex() function correctly validates
 * an MQTT payload containing a temperature reading (23.3°C) against a pattern
 * that matches temperature values with Celsius units.
 * 
 * This test demonstrates how payload content can be validated for specific
 * data formats, which is useful for IoT firewall filtering.
 */
void test_payload_temperature_regex() {
    /*
    MQ Telemetry Transport Protocol, Publish Message
    Header Flags: 0x30, Message Type: Publish Message, QoS Level: At most once delivery (Fire and Forget)
    Msg Len: 20
    Topic Length: 11
    Topic: temperature
    Message: 32332e33c2b043 // 23.3°C
    */

    char* hexstring = "3014000b74656d706572617475726532332e33c2b043";

    uint8_t *payload;
    size_t length = hexstr_to_payload(hexstring, &payload);
    CU_ASSERT_EQUAL(length, strlen(hexstring) / 2);


    mqtt_message_t actual = mqtt_parse_message(payload);

    const char *temperature_regex = "-?[0-9]?[0-9]\\.[0-9]°C";
    bool is_valid = check_payload_regex(actual.payload, strlen((char *)actual.payload), temperature_regex);

    CU_ASSERT_TRUE(is_valid);

    free(payload);
}

/** 
 * Main function for the unit tests.
 */
int main() {
    // Initialize registry and suite
    if (CU_initialize_registry() != CUE_SUCCESS) {
        return CU_get_error();
    }
    CU_pSuite suite = CU_add_suite("mqtt_suite", NULL, NULL);
    
    // Run tests
    CU_add_test(suite, "test_is_mqtt", test_is_mqtt);
    CU_add_test(suite, "parse_publish_temperature_msg_example", parse_publish_temperature_msg_example);
    CU_add_test(suite, "parse_publish_humidity_msg_example", parse_publish_humidity_msg_example);
    CU_add_test(suite, "parse_connect_command_msg_example", parse_connect_command_msg_example);
    CU_add_test(suite, "parse_subscribe_request_msg_example", parse_subscribe_request_msg_example);

    CU_add_test(suite, "test_payload_humidity_regex", test_payload_humidity_regex);
    CU_add_test(suite, "test_payload_temperature_regex", test_payload_temperature_regex);

    CU_basic_run_tests();
    CU_cleanup_registry();
    return 0;
}
