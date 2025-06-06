/**
 * @file test/parsers/dns.c
 * @author François De Keersmaeker (francois.dekeersmaeker@uclouvain.be)
 * @brief Unit tests for the DNS parser
 * @date 2022-09-09
 * 
 * @copyright Copyright (c) 2022
 * 
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
// Custom libraries
#include "packet_utils.h"
#include "header.h"
#include "dns.h"
// CUnit
#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>


/**
 * Unit test for the header section of a DNS message.
 * Verify that each header field is as expected.
 */
void compare_headers(dns_header_t actual, dns_header_t expected) {
    CU_ASSERT_EQUAL(actual.id, expected.id);
    CU_ASSERT_EQUAL(actual.flags, expected.flags);
    CU_ASSERT_EQUAL(actual.qr, expected.qr);
    CU_ASSERT_EQUAL(actual.qdcount, expected.qdcount);
    CU_ASSERT_EQUAL(actual.ancount, expected.ancount);
    CU_ASSERT_EQUAL(actual.nscount, expected.nscount);
    CU_ASSERT_EQUAL(actual.arcount, expected.arcount);
}

/**
 * Unit test for the questions section
 * of a DNS message.
 */
void compare_questions(uint16_t qdcount, dns_question_t *actual, dns_question_t *expected) {
    for (int i = 0; i < qdcount; i++) {
        CU_ASSERT_STRING_EQUAL((actual + i)->qname, (expected + i)->qname);
        CU_ASSERT_EQUAL((actual + i)->qtype, (expected + i)->qtype);
        CU_ASSERT_EQUAL((actual + i)->qclass, (expected + i)->qclass);
    }
}

/**
 * Unit test for a resource records section
 * of a DNS message.
 */
void compare_rrs(uint16_t count, dns_resource_record_t *actual, dns_resource_record_t *expected) {
    for (int i = 0; i < count; i++) {
        CU_ASSERT_STRING_EQUAL((actual + i)->name, (expected + i)->name);
        CU_ASSERT_EQUAL((actual + i)->rtype, (expected + i)->rtype);
        CU_ASSERT_EQUAL((actual + i)->rclass, (expected + i)->rclass);
        CU_ASSERT_EQUAL((actual + i)->ttl, (expected + i)->ttl);
        CU_ASSERT_EQUAL((actual + i)->rdlength, (expected + i)->rdlength);
        CU_ASSERT_STRING_EQUAL(
            dns_rdata_to_str((actual + i)->rtype, (actual + i)->rdlength, (actual + i)->rdata),
            dns_rdata_to_str((expected + i)->rtype, (expected + i)->rdlength, (expected + i)->rdata)
        );
    }
}

/**
 * @brief Unit test for the dns_convert_qname function.
 */
void test_dns_convert_qname() {
    // Test parameters
    char *qname           = "www.google.com";
    uint8_t qname_len     = strlen(qname);
    char *expected        = "\3www\6google\3com";
    uint8_t converted_len = qname_len + 2;
    
    // Execute function
    char *actual = (char*) malloc(converted_len);
    dns_convert_qname(actual, qname, qname_len);

    // Verify result
    CU_ASSERT_STRING_EQUAL(actual, expected);

    // Clean up
    free(actual);
}

/**
 * Unit test for the DNS parser.
 */
void test_dns_xiaomi() {

    char *hexstring = "450000912ecc40004011879dc0a80101c0a801a10035a6b5007d76b46dca8180000100020000000008627573696e6573730b736d61727463616d6572610361706902696f026d6903636f6d0000010001c00c0005000100000258002516636e616d652d6170702d636f6d2d616d7370726f78790177066d692d64756e03636f6d00c04000010001000000930004142f61e7";
    
    uint8_t *payload;
    size_t length = hexstr_to_payload(hexstring, &payload);
    CU_ASSERT_EQUAL(length, strlen(hexstring) / 2);  // Verify message length

    size_t skipped = get_headers_length(payload);
    dns_message_t message = dns_parse_message(payload + skipped);
    free(payload);
    //dns_print_message(message);

    // Test different sections of the DNS message

    // Header
    dns_header_t expected_header;
    expected_header.id = 0x6dca;
    expected_header.flags = 0x8180;
    expected_header.qr = 1;
    expected_header.qdcount = 1;
    expected_header.ancount = 2;
    expected_header.nscount = 0;
    expected_header.arcount = 0;
    compare_headers(message.header, expected_header);
    
    // Questions
    dns_question_t *expected_question;
    expected_question = malloc(sizeof(dns_question_t) * message.header.qdcount);
    expected_question->qname = "business.smartcamera.api.io.mi.com";
    expected_question->qtype = A;
    expected_question->qclass = 1;
    compare_questions(message.header.qdcount, message.questions, expected_question);
    free(expected_question);
    
    // Answer resource records
    dns_resource_record_t *expected_answer;
    expected_answer = malloc(sizeof(dns_resource_record_t) * message.header.ancount);
    // Answer n°0
    expected_answer->name = "business.smartcamera.api.io.mi.com";
    expected_answer->rtype = CNAME;
    expected_answer->rclass = 1;
    expected_answer->ttl = 600;
    expected_answer->rdlength = 37;
    expected_answer->rdata.domain_name = "cname-app-com-amsproxy.w.mi-dun.com";
    // Answer n°1
    (expected_answer + 1)->name = "cname-app-com-amsproxy.w.mi-dun.com";
    (expected_answer + 1)->rtype = 1;
    (expected_answer + 1)->rclass = 1;
    (expected_answer + 1)->ttl = 147;
    (expected_answer + 1)->rdlength = 4;
    (expected_answer + 1)->rdata.ip.version = 4;
    (expected_answer + 1)->rdata.ip.value.ipv4 = ipv4_str_to_net("20.47.97.231");
    compare_rrs(message.header.ancount, message.answers, expected_answer);
    free(expected_answer);


    // Lookup functions

    // Search for domain name
    char *domain_name = "business.smartcamera.api.io.mi.com";
    CU_ASSERT_TRUE(dns_contains_full_domain_name(message.questions, message.header.qdcount, domain_name));
    char *suffix = "api.io.mi.com";
    CU_ASSERT_TRUE(dns_contains_suffix_domain_name(message.questions, message.header.qdcount, suffix, strlen(suffix)));
    domain_name = "swag.framinem.org";
    CU_ASSERT_FALSE(dns_contains_full_domain_name(message.questions, message.header.qdcount, domain_name));
    suffix = "framinem.com";
    CU_ASSERT_FALSE(dns_contains_suffix_domain_name(message.questions, message.header.qdcount, suffix, strlen(suffix)));

    // Get question from domain name
    domain_name = "business.smartcamera.api.io.mi.com";
    dns_question_t *question_lookup = dns_get_question(message.questions, message.header.qdcount, domain_name);
    CU_ASSERT_PTR_NOT_NULL(question_lookup);
    domain_name = "swag.framinem.org";
    question_lookup = dns_get_question(message.questions, message.header.qdcount, domain_name);
    CU_ASSERT_PTR_NULL(question_lookup);

    // Get IP addresses from domain name
    domain_name = "business.smartcamera.api.io.mi.com";
    ip_list_t ip_list = dns_get_ip_from_name(message.answers, message.header.ancount, domain_name);
    char *ip_address = "20.47.97.231";
    CU_ASSERT_EQUAL(ip_list.ip_count, 1);
    CU_ASSERT_STRING_EQUAL(ipv4_net_to_str(ip_list.ip_addresses->value.ipv4), ip_address);
    free(ip_list.ip_addresses);
    domain_name = "swag.framinem.org";
    ip_list = dns_get_ip_from_name(message.answers, message.header.ancount, domain_name);
    CU_ASSERT_EQUAL(ip_list.ip_count, 0);
    CU_ASSERT_PTR_NULL(ip_list.ip_addresses);

    // Free memory
    dns_free_message(message);
}

/**
 * Unit test for the DNS parser.
 */
void test_dns_office() {
    char *hexstring = "4500012a4aa900003e114737826801018268e4110035d7550116a82b3ebf81800001000900000001076f75746c6f6f6b066f666669636503636f6d0000010001c00c0005000100000007000c09737562737472617465c014c03000050001000000500017076f75746c6f6f6b096f666669636533363503636f6d00c0480005000100000093001a076f75746c6f6f6b026861096f666669636533363503636f6d00c06b000500010000000b001c076f75746c6f6f6b076d732d61636463066f666669636503636f6d00c091000500010000001b000a07414d532d65667ac099c0b90001000100000004000434619ea2c0b90001000100000004000428650c62c0b9000100010000000400042863cc22c0b9000100010000000400042865791200002904d0000000000000";

    // Create payload from hexstring
    uint8_t *payload;
    size_t length = hexstr_to_payload(hexstring, &payload);
    CU_ASSERT_EQUAL(length, strlen(hexstring) / 2);  // Verify message length
    size_t skipped = get_headers_length(payload);
    dns_message_t message = dns_parse_message(payload + skipped);
    free(payload);
    //dns_print_message(message);

    // Test different sections of the DNS message

    // Header
    dns_header_t expected_header;
    expected_header.id = 0x3ebf;
    expected_header.flags = 0x8180;
    expected_header.qr = 1;
    expected_header.qdcount = 1;
    expected_header.ancount = 9;
    expected_header.nscount = 0;
    expected_header.arcount = 1;
    compare_headers(message.header, expected_header);

    // Questions
    dns_question_t *expected_question;
    expected_question = malloc(sizeof(dns_question_t) * message.header.qdcount);
    expected_question->qname = "outlook.office.com";
    expected_question->qtype = A;
    expected_question->qclass = 1;
    compare_questions(message.header.qdcount, message.questions, expected_question);
    free(expected_question);

    // Answer resource records
    dns_resource_record_t *expected_answer;
    expected_answer = malloc(sizeof(dns_resource_record_t) * message.header.ancount);
    // Answer n°0
    expected_answer->name = "outlook.office.com";
    expected_answer->rtype = 5;
    expected_answer->rclass = 1;
    expected_answer->ttl = 7;
    expected_answer->rdlength = 12;
    expected_answer->rdata.domain_name = "substrate.office.com";
    // Answer n°1
    (expected_answer + 1)->name = "substrate.office.com";
    (expected_answer + 1)->rtype = 5;
    (expected_answer + 1)->rclass = 1;
    (expected_answer + 1)->ttl = 80;
    (expected_answer + 1)->rdlength = 23;
    (expected_answer + 1)->rdata.domain_name = "outlook.office365.com";
    // Answer n°2
    (expected_answer + 2)->name = "outlook.office365.com";
    (expected_answer + 2)->rtype = 5;
    (expected_answer + 2)->rclass = 1;
    (expected_answer + 2)->ttl = 147;
    (expected_answer + 2)->rdlength = 26;
    (expected_answer + 2)->rdata.domain_name = "outlook.ha.office365.com";
    // Answer n°3
    (expected_answer + 3)->name = "outlook.ha.office365.com";
    (expected_answer + 3)->rtype = 5;
    (expected_answer + 3)->rclass = 1;
    (expected_answer + 3)->ttl = 11;
    (expected_answer + 3)->rdlength = 28;
    (expected_answer + 3)->rdata.domain_name = "outlook.ms-acdc.office.com";
    // Answer n°4
    (expected_answer + 4)->name = "outlook.ms-acdc.office.com";
    (expected_answer + 4)->rtype = CNAME;
    (expected_answer + 4)->rclass = 1;
    (expected_answer + 4)->ttl = 27;
    (expected_answer + 4)->rdlength = 10;
    (expected_answer + 4)->rdata.domain_name = "AMS-efz.ms-acdc.office.com";
    // Answer n°5
    (expected_answer + 5)->name = "AMS-efz.ms-acdc.office.com";
    (expected_answer + 5)->rtype = A;
    (expected_answer + 5)->rclass = 1;
    (expected_answer + 5)->ttl = 4;
    (expected_answer + 5)->rdlength = 4;
    (expected_answer + 5)->rdata.ip.version = 4;
    (expected_answer + 5)->rdata.ip.value.ipv4 = ipv4_str_to_net("52.97.158.162");
    // Answer n°6
    (expected_answer + 6)->name = "AMS-efz.ms-acdc.office.com";
    (expected_answer + 6)->rtype = A;
    (expected_answer + 6)->rclass = 1;
    (expected_answer + 6)->ttl = 4;
    (expected_answer + 6)->rdlength = 4;
    (expected_answer + 6)->rdata.ip.version = 4;
    (expected_answer + 6)->rdata.ip.value.ipv4 = ipv4_str_to_net("40.101.12.98");
    // Answer n°7
    (expected_answer + 7)->name = "AMS-efz.ms-acdc.office.com";
    (expected_answer + 7)->rtype = A;
    (expected_answer + 7)->rclass = 1;
    (expected_answer + 7)->ttl = 4;
    (expected_answer + 7)->rdlength = 4;
    (expected_answer + 7)->rdata.ip.version = 4;
    (expected_answer + 7)->rdata.ip.value.ipv4 = ipv4_str_to_net("40.99.204.34");
    // Answer n°8
    (expected_answer + 8)->name = "AMS-efz.ms-acdc.office.com";
    (expected_answer + 8)->rtype = A;
    (expected_answer + 8)->rclass = 1;
    (expected_answer + 8)->ttl = 4;
    (expected_answer + 8)->rdlength = 4;
    (expected_answer + 8)->rdata.ip.version = 4;
    (expected_answer + 8)->rdata.ip.value.ipv4 = ipv4_str_to_net("40.101.121.18");
    // Compare and free answer
    compare_rrs(message.header.ancount, message.answers, expected_answer);
    free(expected_answer);


    // Lookup functions

    // Search for domain name
    char *domain_name = "outlook.office.com";
    CU_ASSERT_TRUE(dns_contains_full_domain_name(message.questions, message.header.qdcount, domain_name));
    char* suffix = "office.com";
    CU_ASSERT_TRUE(dns_contains_suffix_domain_name(message.questions, message.header.qdcount, suffix, strlen(suffix)));
    domain_name = "swag.framinem.org";
    CU_ASSERT_FALSE(dns_contains_full_domain_name(message.questions, message.header.qdcount, domain_name));
    suffix = "framinem.org";
    CU_ASSERT_FALSE(dns_contains_suffix_domain_name(message.questions, message.header.qdcount, suffix, strlen(suffix)));

    // Get question from domain name
    domain_name = "outlook.office.com";
    dns_question_t *question_lookup = dns_get_question(message.questions, message.header.qdcount, domain_name);
    CU_ASSERT_PTR_NOT_NULL(question_lookup);
    domain_name = "swag.framinem.org";
    question_lookup = dns_get_question(message.questions, message.header.qdcount, domain_name);
    CU_ASSERT_PTR_NULL(question_lookup);

    // Get IP addresses from domain name
    domain_name = "outlook.office.com";
    ip_list_t ip_list = dns_get_ip_from_name(message.answers, message.header.ancount, domain_name);
    char* ip_addresses[] = {
        "52.97.158.162",
        "40.101.12.98",
        "40.99.204.34",
        "40.101.121.18"
    };
    CU_ASSERT_EQUAL(ip_list.ip_count, 4);
    for (uint8_t i = 0; i < 4; i++) {
        CU_ASSERT_STRING_EQUAL(ipv4_net_to_str((ip_list.ip_addresses + i)->value.ipv4), ip_addresses[i]);
    }
    free(ip_list.ip_addresses);
    domain_name = "swag.framinem.org";
    ip_list = dns_get_ip_from_name(message.answers, message.header.ancount, domain_name);
    CU_ASSERT_EQUAL(ip_list.ip_count, 0);
    CU_ASSERT_PTR_NULL(ip_list.ip_addresses);

    // Free memory
    dns_free_message(message);
}


/**
 * @brief Test the DNS parser with a DNS SRV response.
 */
void test_srv_response() {

    char *hexstring = "450000781c4640004011b861c0000201cb00710500353039006400000003818000010001000000001a5f786d70702d736572766572045f746370076578616d706c6503636f6d0000210001c00c0021000100000e10000f0005000a148b05786d707031076578616d706c6503636f6d00 ";

    uint8_t *payload;
    size_t length = hexstr_to_payload(hexstring, &payload);
    CU_ASSERT_EQUAL(length, strlen(hexstring) / 2); // Verify message length

    size_t skipped = get_headers_length(payload);
    dns_message_t message = dns_parse_message(payload + skipped);
    free(payload);


    /* Test different sections of the DNS message */

    // Header
    dns_header_t expected_header;
    expected_header.id = 3;
    expected_header.flags = 0x8180;
    expected_header.qr = 1;
    expected_header.qdcount = 1;
    expected_header.ancount = 1;
    expected_header.nscount = 0;
    expected_header.arcount = 0;
    compare_headers(message.header, expected_header);

    // Questions
    dns_question_t *expected_question;
    expected_question = malloc(sizeof(dns_question_t) * message.header.qdcount);
    expected_question->qname = "_xmpp-server._tcp.example.com";
    expected_question->qtype = SRV;
    expected_question->qclass = 1;
    compare_questions(message.header.qdcount, message.questions, expected_question);
    free(expected_question);

    // Answers
    dns_resource_record_t *expected_answer;
    expected_answer = malloc(sizeof(dns_resource_record_t) * message.header.ancount);
    expected_answer->name = "_xmpp-server._tcp.example.com";
    expected_answer->rtype = SRV;
    expected_answer->rclass = 1;
    expected_answer->ttl = 3600;
    expected_answer->rdlength = 15;
    expected_answer->rdata.srv_data.priority = 5;
    expected_answer->rdata.srv_data.weight = 10;
    expected_answer->rdata.srv_data.port = 5269;
    expected_answer->rdata.srv_data.target = "xmpp1.example.com";
    compare_rrs(message.header.ancount, message.answers, expected_answer);
    free(expected_answer);


    /* Lookup functions */

    // Get question from domain name
    char *domain_name = "_xmpp-server._tcp.example.com";
    dns_question_t *question_lookup = dns_get_question(message.questions, message.header.qdcount, domain_name);
    CU_ASSERT_PTR_NOT_NULL(question_lookup);
    domain_name = "swag.framinem.org";
    question_lookup = dns_get_question(message.questions, message.header.qdcount, domain_name);
    CU_ASSERT_PTR_NULL(question_lookup);


    // Free memory
    dns_free_message(message);
}


/**
 * @brief Test the `dns_send_query` and `dns_receive_response` functions.
 */
void test_dns_send_receive() {
    // Initialize
    int ret;
    char *domain_name = "www.google.com";

    // Open socket
    int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    CU_ASSERT_TRUE(sockfd > 0);
    
    // Server address: network gateway
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(53);
    server_addr.sin_addr.s_addr = inet_addr("8.8.8.8");

    // Send query for dummy domain name
    ret = dns_send_query(domain_name, sockfd, &server_addr);
    CU_ASSERT_EQUAL(ret, 0);

    // Receive response
    dns_message_t dns_response;
    ret = dns_receive_response(sockfd, &server_addr, &dns_response);
    CU_ASSERT_EQUAL(ret ,0);
    CU_ASSERT_STRING_EQUAL(dns_response.questions->qname, domain_name);

    // Free memory
    dns_free_message(dns_response);
}

/**
 * Main function for the unit tests.
 */
int main(int argc, char const *argv[])
{
    // Initialize registry and suite
    if (CU_initialize_registry() != CUE_SUCCESS)
        return CU_get_error();
    printf("Test suite: dns\n");
    CU_pSuite suite = CU_add_suite("dns", NULL, NULL);
    // Run tests
    CU_add_test(suite, "dns-convert-qname", test_dns_convert_qname);
    CU_add_test(suite, "dns-xiaomi", test_dns_xiaomi);
    CU_add_test(suite, "dns-office", test_dns_office);
    CU_add_test(suite, "dns-send-receive", test_dns_send_receive);
    CU_basic_run_tests();
    CU_cleanup_registry();
    return 0;
}
