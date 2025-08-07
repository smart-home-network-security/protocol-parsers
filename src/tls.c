/**
 * @file src/parsers/tls.c
 * @author Mehdi Laurent (mehdi.laurent@student.uclouvain.be)
 * @brief TLS message parser
 * @date 2024-04-23
 * 
*/

#include "tls.h"

// Static buffer for reassembling fragmented TLS records
static tls_record_buffer_t* buffer = NULL;


/** @brief Check if a TCP message is a TLS message.
 * 
 * A TLS message starts with a specific byte corresponding
 * to the content type of the message.
 * 
 * @param data pointer to the start of the TCP payload
 * @return true if the message is a TLS message 
 * @return false if the message is not a TLS message
 */
bool is_tls(uint8_t *data) {
    uint8_t first_byte = *(data + 0);
    
    // iterate over all possibles values of the content type field
    switch (first_byte)
    {
        case TLS_CHANGE_CIPHER_SPEC:
        case TLS_ALERT:
        case TLS_HANDSHAKE:
        case TLS_APPLICATION_DATA:
        case TLS_HEARTBEAT:
            return true;
        default:
            return false;
    }
}

/**
 * @brief Parse the content type of a TLS message.
 * 
 * Parse a TLS message to retrieve its content type in the record header,
 * and return it as a tls_content_type_t data type.
 * 
 * Content type is defined in the first byte of the TLS record header.
 * 
 * @param data pointer to the start of the TLS message
 * @return tls_content_type_t the TLS content type 
*/
static tls_content_type_t get_tls_content_type(uint8_t *data) {
    return (tls_content_type_t) *(data + 0);
}

/**
 * @brief Get the handshake type of a TLS message.
 * 
 * The handshake type is located at offset 5 of the TLS handshake message.
 * The handshake type is only relevant for TLS handshake messages.
 * 
 * Note: For TLS Finished messages, the handshake header is encrypted, so the value
 * returned by this function may not be meaningful.
 * 
 * @param data pointer to the start of the TLS message
 * @return tls_handshake_type_t the handshake type
 */
uint8_t get_handshake_type(uint8_t* data) {
    return (tls_handshake_type_t) *(data + 5);
}

/**
 * @brief Get the TLS version of a TLS message.
 * 
 * Retrieve the TLS version from the content header of a TLS message.
 * 
 * The TLS version is located at offset 1 and 2 in the TLS message.
 * 
 * Other functions are available to retrieve the TLS version in particular cases.
 * 
 * @param data pointer to the start of the TLS message
 * @return tls_version_t the TLS version
 */
tls_version_t get_tls_version(uint8_t* data) {
    tls_version_t tls_version = (*(data + 1) << 8) | *(data + 2);
    return tls_version;
}

/**
 * @brief Retrieve the value in the TLS record length field.
 * 
 * Retrieve the value from the length field in the record header of a TLS message.
 * The length field is located at offset 3 and 4 of the TLS message.
 * 
 * This value indicates the number of bytes that follow the record header,
 * thus it does not indicate the entire length of the data payload.
 * 
 * @param data pointer to the start of the TLS message
 * @return u_int16_t the length of the record
 */
u_int16_t get_record_length(uint8_t* data) {
    return (*(data + 3) << 8) | *(data + 4);
}

/**
 * @brief Get the TLS version of a handshake message.
 * 
 * Retrieve the TLS version in the handshake header of a TLS message.
 * The TLS version in the handshake header is located at offset 9 and 10
 * of the TLS message. 
 * 
 * It's useful especially for ClientHello messages as the TLS version in
 * the record header is hardcoded to TLS 1.0 instead of the actual version
 * used during the handshake.
 * 
 * @param data pointer to the start of the TLS message
 * @return tls_version_t the TLS version
 */
tls_version_t get_tls_version_from_handshake_header(uint8_t* data) {
    tls_version_t tls_version = (*(data + 9) << 8) | *(data + 10);
    return tls_version;
}

/**
 * @brief Determine if a TLS message uses TLS 1.3 protocol.
 * 
 * Examines the "supported versions" extension of a ClientHello or ServerHello message
 * to determine if it's using TLS 1.3. TLS 1.3 connections initially appear as TLS 1.2
 * in the record header, so this deeper inspection is necessary.
 * 
 * @param data Pointer to the start of the TLS message
 * @param message_type The type of the handshake message (must be ClientHello or ServerHello)
 * @param length The length of the payload in bytes
 * 
 * @return tls_version_t Returns TLS_VERSION_1_3 if the message uses TLS 1.3,
 *         or TLS_VERSION_1_2 otherwise
 * 
 * @note This function assumes the input is either a ClientHello or ServerHello message.
 *       Behavior is undefined for other message types.
 */
tls_version_t parse_tls_1_3(uint8_t* data, tls_handshake_type_t message_type, uint16_t length) {
    // Skip the initial parts of the message
    size_t offset = 4; // Content Type (1 byte) + version (2 bytes) + length (2 bytes)
    offset += 1 + 3 + 2 + 32; // Handshake Type (1 byte) + length (3 bytes) + version (2 bytes) + random (32 bytes) 
    offset += 1; // session ID length
    
    u_int8_t session_id_length = data[offset];
    offset += 1;
    offset += session_id_length;

    if (offset + 1 >= length) {
        return TLS_VERSION_1_2;
    }

    // Adjust offset based on whether it's a ClientHello or ServerHello
    if (message_type == TLS_CLIENT_HELLO) {

        uint16_t cipher_suites_length = (uint16_t)(data[offset] << 8) | data[offset + 1];
        offset += 2 + cipher_suites_length;

        uint8_t compression_methods_length = data[offset];
        offset += 1;

        // check that the only compression method is "null" (0x00)
        if (compression_methods_length != 1 || data[offset] != 0x00) {
            return TLS_VERSION_1_2;  // TLS 1.3 requires "null" compression
        }

        offset += 1; // Skip the compression method byte

    } else if (message_type == TLS_SERVER_HELLO) {

        offset += 2; // Cipher Suite
        offset += 1; // Compression Method
    }

    if (offset + 1 >= length) {
        return TLS_VERSION_1_2;
    }

    const uint16_t extensions_length = (uint16_t) (data[offset] << 8) | data[offset + 1];
    offset += 2;
    
    // Parse each extension
    const uint8_t *extensions = data + offset;
    uint16_t extensions_remaining = extensions_length;

    if (extensions_remaining >= length) {
        return TLS_VERSION_1_2;
    }

    while (extensions_remaining >= 4) {
        uint16_t extension_type = (uint16_t) (extensions[0] << 8) | extensions[1];
        uint16_t extension_length = (uint16_t) (extensions[2] << 8) | extensions[3];

        if (extensions_remaining < 4 + extension_length) {
            return TLS_VERSION_1_2;
        }

        // Check if this is the supported_versions extension
        if (extension_type == TLS_SUPPORTED_VERSIONS) {
            uint8_t supported_versions_length = (uint8_t) extension_length;
            short int is_client_offset = 0;
            if (message_type == TLS_CLIENT_HELLO) { // one more byte is used to indicate the length
                supported_versions_length = extensions[4];
                is_client_offset = 1;
            }

            // Check each version in the supported_versions list
            for (short int i = 0; i < supported_versions_length; i += 2) {
                uint16_t version = (uint16_t) (extensions[4 + i + is_client_offset] << 8) | extensions[5 + i + is_client_offset];
                if (version == TLS_VERSION_1_3) {
                    return TLS_VERSION_1_3;
                }
            }

            return TLS_VERSION_1_2; // TLS 1.3 is not found in the supported_versions
        }

        // Move to the next extension
        extensions += 4 + extension_length;
        extensions_remaining -= 4 + extension_length;
    }

    return TLS_VERSION_1_2;
}


/**
 * @brief Check if a session ID is present in a ClientHello or ServerHello message.
 * 
 * Examines the session ID length field to determine if a session ID is being used
 * to resume a previous TLS session.
 * 
 * @param data Pointer to the start of a TLS ClientHello or ServerHello message
 * 
 * @return true If the session ID length is greater than zero
 * @return false If the session ID length is zero
 * 
 * @warning This function assumes the data pointer points to a valid TLS ClientHello
 *          or ServerHello message. Behavior is undefined for other message types.
 */
bool is_session_id_present(uint8_t* data) {
    
    // Get the length of the session_id
    uint8_t session_id_length = *(data + 43);
    
    // Check if the session id is equal to zero
    if (session_id_length == 0) {
        return false;
    } else {
        return true;
    }
}

/**
 * @brief Parse a TLS message.
 * 
 * Parse a TLS message to retrieve its type, the protocol version it uses
 * and other relevant information in case it is a handshake message.
 * 
 * @param data pointer to the start of the TLS message
 * @return the parsed TLS message 
 */
tls_message_t tls_parse_message(uint8_t *data) {
    tls_message_t message;

    // Parse the type of the TLS message
    message.content_type = get_tls_content_type(data);
    
    // Parse the TLS version
    message.tls_version = get_tls_version(data);

    // Retrieve the length in record header and add 5 bytes for the record header itself 
    message.length = get_record_length(data) + 5;
    
    if (message.content_type == TLS_HANDSHAKE) {
        message.handshake_type = get_handshake_type(data);
        if (message.handshake_type == TLS_CLIENT_HELLO || message.handshake_type == TLS_SERVER_HELLO)
            message.session_id_present = is_session_id_present(data);
        else 
            message.session_id_present = NULL;
        
        /* as TLS version is hardcoded to TLS 1.0 in record header of ClientHello messages
           we need to retrieve the actual TLS version in the handshake header */
        if (message.handshake_type == TLS_CLIENT_HELLO) {
            message.tls_version = get_tls_version_from_handshake_header(data);
        }
        
        /* TLS 1.3 is disguised as a TLS 1.2 connection so we have to check whether
           version 1.2 is genuine or not */
        if ((message.tls_version == TLS_VERSION_1_2)) {
            if (message.handshake_type == TLS_CLIENT_HELLO || message.handshake_type == TLS_SERVER_HELLO) {
                message.tls_version = parse_tls_1_3(data, message.handshake_type, message.length);
            }
        }
            
    } else {
        message.handshake_type = -1; // not a handshake message
        message.session_id_present = NULL;
    }

    return message;
}

/**
 * @brief Create a new TLS record buffer.
 * 
 * Allocates memory for a new TLS record buffer with the default capacity 
 * of 16384 bytes (maximum TLS record size).
 */
static void tls_buffer_create(void) {
    buffer = malloc(sizeof(tls_record_buffer_t));
    if (!buffer) return;  // Memory allocation failed
    
    buffer->data = malloc(TLS_MAX_RECORD_SIZE);
    buffer->length = 0;
    buffer->capacity = TLS_MAX_RECORD_SIZE;
}

/**
 * @brief Append data to an existing TLS record buffer.
 * 
 * Copies the provided data to the end of the buffer. If the buffer doesn't have
 * enough capacity to store the new data, the function will return without 
 * appending anything.
 * 
 * @param data Pointer to the data to append
 * @param length Number of bytes to append
 */
static void tls_buffer_append(const uint8_t* data, size_t length) {
    if (buffer->length + length > buffer->capacity) {
        return; // Buffer full
    }
    memcpy(buffer->data + buffer->length, data, length);
    buffer->length += length;
}

/**
 * @brief Parse a TLS packet containing one or more TLS records.
 * 
 * This function processes incoming TLS data, maintaining state between calls through a static
 * buffer. It handles fragmented TLS records that may span multiple TCP packets.
 * 
 * The function appends the new data to an internal buffer, then extracts and parses
 * complete TLS records from this buffer. Incomplete records at the end of the buffer
 * are preserved for the next call.
 * 
 * @param data Pointer to the raw packet data (may contain multiple TLS records)
 * @param packet_length Length of the packet data in bytes
 * 
 * @return tls_packet_t* Pointer to a newly allocated packet structure containing
 *         all parsed TLS messages, or NULL if memory allocation failed.
 *         The caller must free this structure using tls_free_packet() when done.
 * 
 * @note This function uses a static buffer between calls to handle fragmented records.
 *       The buffer is initialized on the first call.
 */
tls_packet_t* tls_parse_packet(uint8_t* data, size_t packet_length) {
    // Initialize buffer if needed
    if (!buffer) {
        tls_buffer_create();
    }
    
    // Append new data
    tls_buffer_append(data, packet_length);
    
    // Try to parse complete records
    tls_packet_t* packet = malloc(sizeof(tls_packet_t));
    if (!packet) return NULL;
    
    packet->messages = NULL;
    packet->record_count = 0;
    packet->total_length = 0;
    
    size_t offset = 0;
    while (offset + 5 <= buffer->length) {
        // Check for complete record
        uint16_t record_length = (buffer->data[offset + 3] << 8) | buffer->data[offset + 4];
        if (offset + record_length + 5 > buffer->length) {
            break; // Incomplete record
        }
        
        // Parse this record
        tls_message_t message = tls_parse_message(buffer->data + offset);
        
        // Create new list node
        tls_message_list_t* node = malloc(sizeof(tls_message_list_t));
        if (!node) {
            tls_free_packet(packet);
            return NULL;
        }
        
        node->message = message;
        node->next = NULL;
        
        // Add to linked list
        if (!packet->messages) {
            packet->messages = node;
        } else {
            tls_message_list_t* current = packet->messages;
            while (current->next) {
                current = current->next;
            }
            current->next = node;
        }
        
        packet->record_count++;
        packet->total_length += message.length;
        offset += message.length;
    }
    
    // Remove processed data from buffer
    if (offset > 0) {
        memmove(buffer->data, buffer->data + offset, buffer->length - offset);
        buffer->length -= offset;
    }
    
    return packet;
}

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
void tls_free_packet(tls_packet_t* packet) {
    if (!packet) return;
    
    tls_message_list_t* current = packet->messages;
    while (current) {
        tls_message_list_t* next = current->next;
        free(current);
        current = next;
    }
    
    free(packet);
}

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
void tls_free_buffer(void) {
    if (buffer) {
        free(buffer->data);
        free(buffer);
        buffer = NULL; // Reset the buffer pointer
    }
}


/////// PRINT FUNCTIONS ///////

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
void tls_print_message(tls_message_t message) {
    printf("TLS Message:\n");
    printf("  Content Type: %d\n", message.content_type);
    char* tls_version = "TLS 1.0";  // Default value
    switch (message.tls_version)
    {
    case TLS_VERSION_1_0:
        tls_version = "TLS 1.0";
        break;

    case TLS_VERSION_1_1:
        tls_version = "TLS 1.1";
        break;  
    
    case TLS_VERSION_1_2:
        tls_version = "TLS 1.2";
        break;

    case TLS_VERSION_1_3:
        tls_version = "TLS 1.3";
        break;
    
    default:
        break;
    }
    printf("  TLS Version: %s\n", tls_version);
    printf("  Length: %d\n", message.length);
    if (message.content_type == TLS_HANDSHAKE) {
        printf("  Handshake Type: %d\n", message.handshake_type);
        if (message.handshake_type == TLS_CLIENT_HELLO || message.handshake_type == TLS_SERVER_HELLO) {
            printf("  Session ID present: %s\n", message.session_id_present ? "true" : "false");
        }
    }
}

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
void tls_print_packet(tls_packet_t* packet) {
    printf("TLS Packet containing %zu records (total length: %zu):\n", 
           packet->record_count, packet->total_length);
    
    tls_message_list_t* current = packet->messages;
    int record_num = 1;
    
    while (current) {
        printf("\nRecord %d:\n", record_num++);
        tls_print_message(current->message);
        current = current->next;
        printf("\n");
    }
}
