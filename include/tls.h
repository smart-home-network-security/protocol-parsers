/**
 * @file include/parsers/tls.h
 * @author Mehdi Laurent (mehdi.laurent@student.uclouvain.be)
 * @brief TLS message parser header file
 * @date 2024-04-23
 * 
 * @copyright Copyright (c) 2024
 * 
*/

#ifndef _PROTOCOL_PARSERS_TLS_
#define _PROTOCOL_PARSERS_TLS_

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <string.h>

#define TLS_SUPPORTED_VERSIONS 0x002b  // assigned value for extension "Supported Versions"
#define TLS_MAX_RECORD_SIZE 16384      // Maximum size of a TLS record (16 KB)

/**
 * TLS content types
*/
typedef enum {
    TLS_CHANGE_CIPHER_SPEC = 20,
    TLS_ALERT = 21,
    TLS_HANDSHAKE = 22, // 0x16
    TLS_APPLICATION_DATA = 23,
    TLS_HEARTBEAT = 24
} tls_content_type_t;

/**
 * TLS handshake types
*/
typedef enum {
    TLS_CLIENT_HELLO = 1,
    TLS_SERVER_HELLO = 2,
    TLS_CERTIFICATE = 11,
    TLS_SERVER_KEY_EXCHANGE = 12,
    TLS_CERTIFICATE_REQUEST = 13,
    TLS_SERVER_HELLO_DONE = 14,
    TLS_CERTIFICATE_VERIFY = 15,
    TLS_CLIENT_KEY_EXCHANGE = 16,
    // TLS_FINISHED is not included here because its handshake header is encrypted.
} tls_handshake_type_t;

/**
 * TLS versions
*/
typedef enum {
    TLS_VERSION_1_0 = 0x0301,
    TLS_VERSION_1_1 = 0x0302,
    TLS_VERSION_1_2 = 0x0303,
    TLS_VERSION_1_3 = 0x0304,
} tls_version_t;

/**
 * Abstraction of a TLS message
 * 
 * Only relevant fields for the IoT firewall are included.
*/
typedef struct tls_message {
    tls_version_t tls_version;
    uint16_t length;

    /* RECORD HEADER */
    tls_content_type_t content_type;

    /* HANDSHAKE HEADER */ 
    tls_handshake_type_t handshake_type;
    bool session_id_present;
} tls_message_t;


typedef struct tls_message_list {
    tls_message_t message;
    struct tls_message_list* next;
} tls_message_list_t;

typedef struct tls_packet {
    tls_message_list_t* messages;
    size_t record_count;
    size_t total_length;
} tls_packet_t;

typedef struct {
    uint8_t* data;
    size_t length;
    size_t capacity;
} tls_record_buffer_t;

////////// FUNCTIONS //////////

///// PARSING /////

/**
 * @brief Check if a TCP message is a TLS message.
 * 
 * @param data pointer to the start of the TCP payload
 * @return true if the message is a TLS message, false otherwise
 */
bool is_tls(uint8_t *data);

/**
 * @brief Parse a TLS message.
 * 
 * @param data pointer to the start of the TLS message
 * @return tls_message_t abstraction of the TLS message 
 */
tls_message_t tls_parse_message(uint8_t *data);

/**
 * @brief Parse a TLS packet.
 * 
 * @param data pointer to the start of the payload
 * @param packet_length length of the payload
 * @return tls_packet_t* pointer to an abstraction of TLS packet
 */
tls_packet_t* tls_parse_packet(uint8_t* data, size_t packet_length);

/**
 * @brief Free the memory allocated for a TLS packet structure.
 * 
 * This function properly deallocates all memory associated with a TLS packet,
 * including all TLS message nodes in the linked list. It safely handles NULL
 * pointers.
 * 
 * @param packet Pointer to the TLS packet structure to free. If NULL, 
 *        the function returns without doing anything.
 * 
 * @note After calling this function, the packet pointer should not be used again
 *       as it points to deallocated memory.
 */
void tls_free_packet(tls_packet_t* packet);

/**
 * @brief Free the static TLS record buffer.
 * 
 * This function deallocates the memory used by the static TLS record buffer
 * and resets the buffer pointer to NULL. It should be called when the buffer
 * is no longer needed to avoid memory leaks.
 * 
 * @note After calling this function, any further attempts to use the buffer
 *       will result in a new buffer being created on the next call to tls_parse_packet().
 */
void tls_free_buffer(void);

/**
 * @brief Print formatted details of a TLS message to standard output.
 * 
 * This function displays the content type, TLS version, length, and handshake
 * type (if applicable) of a TLS message. For ClientHello and ServerHello
 * messages, it also shows whether a session ID is present.
 * 
 * The output format is structured with indentation for readability and
 * includes human-readable strings for TLS versions.
 * 
 * @param message The TLS message structure to display
 * 
 * @note This function is primarily intended for debugging and diagnostic purposes.
 *       It writes directly to stdout using printf.
 */
void tls_print_message(tls_message_t message);

/**
 * @brief Print formatted details of a TLS packet to standard output.
 * 
 * This function displays information about a TLS packet, including the total number
 * of records, total length, and detailed information about each individual record.
 * For each record, it calls tls_print_message() to display the specific message details.
 * 
 * @param packet Pointer to the TLS packet structure to print. Must not be NULL.
 * 
 * @see tls_print_message() For details on how individual TLS messages are displayed.
 * 
 * @note This function is primarily intended for debugging and diagnostic purposes.
 */
void tls_print_packet(tls_packet_t* packet);


#endif /* _PROTOCOL_PARSERS_TLS_ */
