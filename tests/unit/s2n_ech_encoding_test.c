/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

#include "tls/s2n_ech_encoding.h"

#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "tls/extensions/s2n_extension_type.h"
#include "tls/s2n_client_hello.h"
#include "tls/s2n_tls_parameters.h"

/* clang-format off */
#define TEST_ECH_ENC                                                       \
    "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
#define TEST_ECH_PAYLOAD "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
#define TEST_ECH_CLIENT_HELLO_OUTER                                        \
    "00"                     /* type: outer */                             \
    "0001"                   /* kdf_id: HKDF-SHA256 */                     \
    "0003"                   /* aead_id: ChaCha20Poly1305 */               \
    "2a"                     /* config_id */                               \
    "0020" TEST_ECH_ENC      /* enc */                                     \
    "0010" TEST_ECH_PAYLOAD  /* payload */

/* A ClientHelloOuter body with server_name "example.com", supported_versions,
 * and TEST_ECH_CLIENT_HELLO_OUTER as its last extension, so the ECH payload
 * is its last TEST_ECH_PAYLOAD_SIZE bytes. */
#define TEST_ECH_PAYLOAD_SIZE 16
#define TEST_CLIENT_HELLO_RANDOM                                           \
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
#define TEST_CLIENT_HELLO_OUTER_BEFORE_PAYLOAD                             \
    "0303"                   /* legacy_version */                          \
    TEST_CLIENT_HELLO_RANDOM /* random */                                  \
    "20"                     /* legacy_session_id */                       \
    "e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"     \
    "0002" "1301"            /* cipher_suites */                           \
    "01" "00"                /* legacy_compression_methods */              \
    "0059"                   /* extensions length */                       \
    "0000" "0010"            /* server_name */                             \
    "000e" "00" "000b" "6578616d706c652e636f6d"                            \
    "002b" "0003" "02" "0304" /* supported_versions */                     \
    "fe0d" "003a"            /* encrypted_client_hello */                  \
    "00" "0001" "0003" "2a" "0020" TEST_ECH_ENC "0010"
#define TEST_CLIENT_HELLO_OUTER                                            \
    "01" "0000a4"            /* handshake header */                        \
    TEST_CLIENT_HELLO_OUTER_BEFORE_PAYLOAD TEST_ECH_PAYLOAD
/* The ClientHelloOuterAAD for TEST_CLIENT_HELLO_OUTER: the body with the
 * ECH payload replaced by zeros */
#define TEST_CLIENT_HELLO_OUTER_AAD                                        \
    TEST_CLIENT_HELLO_OUTER_BEFORE_PAYLOAD                                 \
    "00000000000000000000000000000000"

/* The extensions of a ClientHelloOuter, without the list length. 0x0015
 * (padding) and 0x1234 are not extensions s2n recognizes. */
#define TEST_OUTER_EXT_A   "000a" "0002" "aaaa"
#define TEST_OUTER_EXT_D   "0015" "0002" "0000"
#define TEST_OUTER_EXT_B   "000d" "0002" "bbbb"
#define TEST_OUTER_EXT_ECH "fe0d" "0002" "eeee"
#define TEST_OUTER_EXT_C   "0033" "0002" "cccc"
#define TEST_OUTER_EXT_E   "1234" "0001" "12"
#define TEST_OUTER_EXTENSIONS                                              \
    TEST_OUTER_EXT_A TEST_OUTER_EXT_D TEST_OUTER_EXT_B                     \
    TEST_OUTER_EXT_ECH TEST_OUTER_EXT_C TEST_OUTER_EXT_E
/* Extensions of an EncodedClientHelloInner */
#define TEST_INNER_EXT_X   "0000" "0004" "11112222"
#define TEST_INNER_EXT_ECH "fe0d" "0001" "01"

/* An EncodedClientHelloInner for TEST_CLIENT_HELLO_OUTER, with server_name
 * "secret.example", supported_versions compressed, and no padding */
#define TEST_INNER_RANDOM                                                  \
    "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"
#define TEST_INNER_EXT_SERVER_NAME                                         \
    "0000" "0013" "0011" "00" "000e" "7365637265742e6578616d706c65"
#define TEST_ENCODED_INNER                                                 \
    "0303"                   /* legacy_version */                          \
    TEST_INNER_RANDOM        /* random */                                  \
    "00"                     /* legacy_session_id: empty */                \
    "0002" "1301"            /* cipher_suites */                           \
    "01" "00"                /* legacy_compression_methods */              \
    "0023"                   /* extensions length */                       \
    TEST_INNER_EXT_SERVER_NAME                                             \
    "fd00" "0003" "02" "002b" /* ech_outer_extensions: supported_versions */ \
    TEST_INNER_EXT_ECH
/* The ClientHelloInner body that TEST_ENCODED_INNER decodes to */
#define TEST_INNER_BODY                                                    \
    "0303"                                                                 \
    TEST_INNER_RANDOM                                                      \
    "20"                     /* legacy_session_id from the outer */        \
    "e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"     \
    "0002" "1301"                                                          \
    "01" "00"                                                              \
    "0023"                                                                 \
    TEST_INNER_EXT_SERVER_NAME                                             \
    "002b" "0003" "02" "0304" /* supported_versions from the outer */      \
    TEST_INNER_EXT_ECH
#define TEST_INNER_MESSAGE "01" "00006e" TEST_INNER_BODY
/* clang-format on */

/* Decodes the hex-encoded EncodedClientHelloInner against `outer`, and checks
 * that the header-prefixed and body-only copies agree */
static S2N_RESULT s2n_test_decode(const char *encoded_inner_hex, const struct s2n_client_hello *outer,
        struct s2n_blob *inner_message, struct s2n_blob *inner_raw_message)
{
    S2N_CHECKED_BLOB_FROM_HEX(encoded_inner, RESULT_GUARD, encoded_inner_hex);
    RESULT_GUARD(s2n_ech_encoded_inner_decode(&encoded_inner, outer, inner_message, inner_raw_message));
    RESULT_ENSURE_EQ(inner_message->size, inner_raw_message->size + TLS_HANDSHAKE_HEADER_LENGTH);
    RESULT_ENSURE(memcmp(inner_message->data + TLS_HANDSHAKE_HEADER_LENGTH, inner_raw_message->data,
                          inner_raw_message->size)
                    == 0,
            S2N_ERR_SAFETY);
    return S2N_RESULT_OK;
}

/* Decompresses the hex-encoded EncodedClientHelloInner extensions against
 * TEST_OUTER_EXTENSIONS. */
static S2N_RESULT s2n_test_decompress(const char *encoded_inner_hex, struct s2n_stuffer *out)
{
    S2N_CHECKED_BLOB_FROM_HEX(encoded_inner, RESULT_GUARD, encoded_inner_hex);
    S2N_CHECKED_BLOB_FROM_HEX(outer, RESULT_GUARD, TEST_OUTER_EXTENSIONS);
    RESULT_GUARD(s2n_ech_decompress_extensions(&encoded_inner, &outer, out));
    return S2N_RESULT_OK;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /*
     *= https://www.rfc-editor.org/rfc/rfc9849#section-5
     *= type=test
     *#     enum { outer(0), inner(1) } ECHClientHelloType;
     *#
     *#     struct {
     *#        ECHClientHelloType type;
     *#        select (ECHClientHello.type) {
     *#            case outer:
     *#                HpkeSymmetricCipherSuite cipher_suite;
     *#                uint8 config_id;
     *#                opaque enc<0..2^16-1>;
     *#                opaque payload<1..2^16-1>;
     *#            case inner:
     *#                Empty;
     *#        };
     *#     } ECHClientHello;
     */
    {
        /* The outer variant parses into its fields */
        {
            S2N_BLOB_FROM_HEX(extension, TEST_ECH_CLIENT_HELLO_OUTER);
            S2N_BLOB_FROM_HEX(enc, TEST_ECH_ENC);
            S2N_BLOB_FROM_HEX(payload, TEST_ECH_PAYLOAD);

            struct s2n_ech_client_hello ech = { 0 };
            EXPECT_OK(s2n_ech_client_hello_parse(&extension, &ech));
            EXPECT_EQUAL(ech.type, S2N_ECH_CLIENT_HELLO_OUTER);
            EXPECT_EQUAL(ech.kdf_id, 0x0001);
            EXPECT_EQUAL(ech.aead_id, 0x0003);
            EXPECT_EQUAL(ech.config_id, 0x2a);
            EXPECT_EQUAL(ech.enc.size, enc.size);
            EXPECT_BYTEARRAY_EQUAL(ech.enc.data, enc.data, enc.size);
            EXPECT_EQUAL(ech.payload.size, payload.size);
            EXPECT_BYTEARRAY_EQUAL(ech.payload.data, payload.data, payload.size);

            /* The payload points into the extension, so that callers can
             * locate it within the ClientHelloOuter */
            EXPECT_EQUAL(ech.payload.data, extension.data + extension.size - payload.size);
        };

        /* An empty enc parses: the second ClientHelloOuter after a
         * HelloRetryRequest sends one */
        {
            /* clang-format off */
            S2N_BLOB_FROM_HEX(extension, "00" "0001" "0001" "2a" "0000" "0001" "ff");
            /* clang-format on */
            struct s2n_ech_client_hello ech = { 0 };
            EXPECT_OK(s2n_ech_client_hello_parse(&extension, &ech));
            EXPECT_EQUAL(ech.enc.size, 0);
            EXPECT_EQUAL(ech.payload.size, 1);
        };

        /* The inner variant parses */
        {
            S2N_BLOB_FROM_HEX(extension, "01");
            struct s2n_ech_client_hello ech = { 0 };
            EXPECT_OK(s2n_ech_client_hello_parse(&extension, &ech));
            EXPECT_EQUAL(ech.type, S2N_ECH_CLIENT_HELLO_INNER);
        };

        /* An empty ECHClientHello is rejected */
        {
            struct s2n_blob extension = { 0 };
            struct s2n_ech_client_hello ech = { 0 };
            EXPECT_ERROR_WITH_ERRNO(s2n_ech_client_hello_parse(&extension, &ech), S2N_ERR_BAD_MESSAGE);
        };

        /*
         *= https://www.rfc-editor.org/rfc/rfc9849#section-7
         *= type=test
         *# If ECHClientHello.type is not a valid ECHClientHelloType, then the
         *# server MUST abort with an "illegal_parameter" alert.
         */
        {
            const char *unknown_types[] = { "02", "ff", "02"
                                                        "00" };
            for (size_t i = 0; i < s2n_array_len(unknown_types); i++) {
                DEFER_CLEANUP(struct s2n_blob extension = { 0 }, s2n_free);
                EXPECT_OK(s2n_blob_alloc_from_hex_with_whitespace(&extension, unknown_types[i]));
                struct s2n_ech_client_hello ech = { 0 };
                EXPECT_ERROR_WITH_ERRNO(s2n_ech_client_hello_parse(&extension, &ech),
                        S2N_ERR_ECH_INVALID_CLIENT_HELLO);
            }
        };

        /* Malformed ECHClientHellos are rejected */
        /* clang-format off */
        const char *malformed[] = {
            /* inner with a body */
            "01" "00",
            /* outer, truncated cipher_suite */
            "00" "0001" "00",
            /* outer, missing config_id */
            "00" "0001" "0001",
            /* outer, truncated enc */
            "00" "0001" "0001" "2a" "0020" "a0a1",
            /* outer, missing payload */
            "00" "0001" "0001" "2a" "0000",
            /* outer, empty payload */
            "00" "0001" "0001" "2a" "0000" "0000",
            /* outer, truncated payload */
            "00" "0001" "0001" "2a" "0000" "0002" "ff",
            /* outer, trailing data */
            "00" "0001" "0001" "2a" "0000" "0001" "ff" "00",
        };
        /* clang-format on */
        for (size_t i = 0; i < s2n_array_len(malformed); i++) {
            DEFER_CLEANUP(struct s2n_blob extension = { 0 }, s2n_free);
            EXPECT_OK(s2n_blob_alloc_from_hex_with_whitespace(&extension, malformed[i]));
            struct s2n_ech_client_hello ech = { 0 };
            EXPECT_ERROR_WITH_ERRNO(s2n_ech_client_hello_parse(&extension, &ech), S2N_ERR_BAD_MESSAGE);
        }
    };

    /*
     *= https://www.rfc-editor.org/rfc/rfc9849#section-5.2
     *= type=test
     *# The ClientHelloOuterAAD is a serialized
     *# ClientHello structure, defined in Section 4.1.2 of [RFC8446] for TLS
     *# and Section 5.3 of [RFC9147] for DTLS, which matches the
     *# ClientHelloOuter except that the payload field of the
     *# "encrypted_client_hello" is replaced with a byte string of the same
     *# length but whose contents are zeros.  This value does not include the
     *# Handshake structure's four-byte header in TLS nor the twelve-byte
     *# header in DTLS.
     */
    {
        S2N_BLOB_FROM_HEX(message, TEST_CLIENT_HELLO_OUTER);
        S2N_BLOB_FROM_HEX(expected_aad, TEST_CLIENT_HELLO_OUTER_AAD);
        S2N_BLOB_FROM_HEX(random, TEST_CLIENT_HELLO_RANDOM);

        DEFER_CLEANUP(struct s2n_client_hello *client_hello = s2n_client_hello_parse_message(
                              message.data, message.size),
                s2n_client_hello_free);
        EXPECT_NOT_NULL(client_hello);
        struct s2n_blob *raw_message = &client_hello->raw_message;
        EXPECT_EQUAL(raw_message->size, expected_aad.size);

        /* The ECH payload is the last TEST_ECH_PAYLOAD_SIZE bytes of the
         * ClientHelloOuter, as s2n_ech_client_hello_parse would find it */
        struct s2n_blob payload = { 0 };
        EXPECT_SUCCESS(s2n_blob_slice(raw_message, &payload, raw_message->size - TEST_ECH_PAYLOAD_SIZE,
                TEST_ECH_PAYLOAD_SIZE));
        S2N_BLOB_FROM_HEX(expected_payload, TEST_ECH_PAYLOAD);
        EXPECT_BYTEARRAY_EQUAL(payload.data, expected_payload.data, expected_payload.size);

        /* The AAD is reconstructed byte-exact from the parsed ClientHelloOuter.
         *
         * If this fails after a change to s2n_client_hello_parse_raw, that
         * change probably modified raw_message in place, and
         * s2n_ech_build_outer_aad must undo it. */
        {
            DEFER_CLEANUP(struct s2n_blob aad = { 0 }, s2n_free);
            EXPECT_OK(s2n_ech_build_outer_aad(client_hello, &payload, &aad));
            EXPECT_EQUAL(aad.size, expected_aad.size);
            EXPECT_BYTEARRAY_EQUAL(aad.data, expected_aad.data, expected_aad.size);
        };

        /* Parsing erased the random from raw_message, so raw_message alone is
         * not the AAD */
        {
            uint8_t zeros[S2N_TLS_RANDOM_DATA_LEN] = { 0 };
            EXPECT_BYTEARRAY_EQUAL(raw_message->data + S2N_TLS_PROTOCOL_VERSION_LEN, zeros, sizeof(zeros));
            EXPECT_BYTEARRAY_EQUAL(client_hello->random, random.data, random.size);
        };

        /* Building the AAD does not modify the ClientHello */
        {
            DEFER_CLEANUP(struct s2n_blob raw_message_before = { 0 }, s2n_free);
            EXPECT_SUCCESS(s2n_dup(raw_message, &raw_message_before));

            DEFER_CLEANUP(struct s2n_blob aad = { 0 }, s2n_free);
            EXPECT_OK(s2n_ech_build_outer_aad(client_hello, &payload, &aad));
            EXPECT_BYTEARRAY_EQUAL(raw_message->data, raw_message_before.data, raw_message_before.size);
        };

        /* Once any extension of the ClientHello has been processed, the AAD
         * is refused. Processing the pre_shared_key extension decrypts session
         * tickets in place in raw_message, so the bytes may no longer be the
         * ones the client sealed. */
        {
            s2n_extension_type_id psk_id = 0;
            EXPECT_SUCCESS(s2n_extension_supported_iana_value_to_id(TLS_EXTENSION_PRE_SHARED_KEY, &psk_id));
            s2n_extension_type_id server_name_id = 0;
            EXPECT_SUCCESS(s2n_extension_supported_iana_value_to_id(TLS_EXTENSION_SERVER_NAME, &server_name_id));
            s2n_extension_type_id processed_ids[] = { psk_id, server_name_id };
            for (size_t i = 0; i < s2n_array_len(processed_ids); i++) {
                struct s2n_client_hello processed = *client_hello;
                processed.extensions.parsed_extensions[processed_ids[i]].processed = true;
                DEFER_CLEANUP(struct s2n_blob aad = { 0 }, s2n_free);
                EXPECT_ERROR_WITH_ERRNO(s2n_ech_build_outer_aad(&processed, &payload, &aad), S2N_ERR_SAFETY);
                EXPECT_EQUAL(aad.size, 0);
            }
        };

        /* An SSLv2 ClientHello is rejected: it cannot carry ECH */
        {
            struct s2n_client_hello sslv2_client_hello = *client_hello;
            sslv2_client_hello.sslv2 = true;
            DEFER_CLEANUP(struct s2n_blob aad = { 0 }, s2n_free);
            EXPECT_ERROR_WITH_ERRNO(s2n_ech_build_outer_aad(&sslv2_client_hello, &payload, &aad), S2N_ERR_SAFETY);
            EXPECT_EQUAL(aad.size, 0);
        };

        /* An AAD blob that is already allocated is rejected, rather than
         * leaked */
        {
            DEFER_CLEANUP(struct s2n_blob aad = { 0 }, s2n_free);
            EXPECT_SUCCESS(s2n_alloc(&aad, 1));
            uint8_t *allocated = aad.data;
            EXPECT_ERROR_WITH_ERRNO(s2n_ech_build_outer_aad(client_hello, &payload, &aad), S2N_ERR_SAFETY);
            EXPECT_EQUAL(aad.data, allocated);
        };

        /* A payload that is not inside the ClientHello's extensions is
         * rejected */
        {
            const struct s2n_blob *extensions = &client_hello->extensions.raw;
            uint32_t extensions_offset = extensions->data - raw_message->data;
            uint8_t elsewhere[TEST_ECH_PAYLOAD_SIZE] = { 0 };
            struct s2n_blob bad_payloads[] = {
                /* over legacy_version and the random */
                { .data = raw_message->data, .size = TEST_ECH_PAYLOAD_SIZE },
                /* over the session id */
                { .data = raw_message->data + S2N_TLS_PROTOCOL_VERSION_LEN + S2N_TLS_RANDOM_DATA_LEN,
                        .size = 1 },
                /* ending just before the extensions */
                { .data = raw_message->data + extensions_offset - 1, .size = 1 },
                /* starting just before the extensions */
                { .data = raw_message->data + extensions_offset - 1, .size = 2 },
                /* one byte past the end */
                { .data = payload.data + 1, .size = TEST_ECH_PAYLOAD_SIZE },
                /* past the end */
                { .data = raw_message->data + raw_message->size, .size = 1 },
                /* a size that would overflow */
                { .data = payload.data, .size = UINT32_MAX },
                /* another buffer */
                { .data = elsewhere, .size = sizeof(elsewhere) },
                /* no data */
                { .data = NULL, .size = 0 },
            };
            for (size_t i = 0; i < s2n_array_len(bad_payloads); i++) {
                DEFER_CLEANUP(struct s2n_blob aad = { 0 }, s2n_free);
                EXPECT_ERROR_WITH_ERRNO(s2n_ech_build_outer_aad(client_hello, &bad_payloads[i], &aad),
                        S2N_ERR_SAFETY);
                EXPECT_EQUAL(aad.size, 0);
            }

            /* The whole extension block is accepted */
            DEFER_CLEANUP(struct s2n_blob aad = { 0 }, s2n_free);
            EXPECT_OK(s2n_ech_build_outer_aad(client_hello, extensions, &aad));
        };
    };

    /*
     *= https://www.rfc-editor.org/rfc/rfc9849#section-5.1
     *= type=test
     *# Next, it makes a copy of the client_hello field and copies the
     *# legacy_session_id field from ClientHelloOuter.  It then looks for an
     *# "ech_outer_extensions" extension.  If found, it replaces the
     *# extension with the corresponding sequence of extensions in the
     *# ClientHelloOuter.
     */
    {
        /* clang-format off */
        struct {
            const char *encoded_inner;
            const char *expected;
        } test_cases[] = {
            /* No ech_outer_extensions: the extensions are copied unchanged */
            {
                    .encoded_inner = TEST_INNER_EXT_X TEST_INNER_EXT_ECH,
                    .expected = TEST_INNER_EXT_X TEST_INNER_EXT_ECH,
            },
            /* One reference */
            {
                    .encoded_inner = TEST_INNER_EXT_X "fd00" "0003" "02" "000a" TEST_INNER_EXT_ECH,
                    .expected = TEST_INNER_EXT_X TEST_OUTER_EXT_A TEST_INNER_EXT_ECH,
            },
            /* Several references, in order but not contiguous in the outer */
            {
                    .encoded_inner = TEST_INNER_EXT_X "fd00" "0007" "06" "000a" "000d" "0033" TEST_INNER_EXT_ECH,
                    .expected = TEST_INNER_EXT_X TEST_OUTER_EXT_A TEST_OUTER_EXT_B TEST_OUTER_EXT_C TEST_INNER_EXT_ECH,
            },
            /* ech_outer_extensions first and last */
            {
                    .encoded_inner = "fd00" "0003" "02" "000a",
                    .expected = TEST_OUTER_EXT_A,
            },
            /* References to extensions s2n does not recognize */
            {
                    .encoded_inner = TEST_INNER_EXT_ECH "fd00" "0005" "04" "0015" "1234",
                    .expected = TEST_INNER_EXT_ECH TEST_OUTER_EXT_D TEST_OUTER_EXT_E,
            },
            /* Every outer extension except encrypted_client_hello */
            {
                    .encoded_inner = "fd00" "000b" "0a" "000a" "0015" "000d" "0033" "1234",
                    .expected = TEST_OUTER_EXT_A TEST_OUTER_EXT_D TEST_OUTER_EXT_B TEST_OUTER_EXT_C TEST_OUTER_EXT_E,
            },
        };
        /* clang-format on */
        for (size_t i = 0; i < s2n_array_len(test_cases); i++) {
            S2N_BLOB_FROM_HEX(expected, test_cases[i].expected);
            DEFER_CLEANUP(struct s2n_stuffer out = { 0 }, s2n_stuffer_free);
            EXPECT_OK(s2n_test_decompress(test_cases[i].encoded_inner, &out));
            EXPECT_EQUAL(s2n_stuffer_data_available(&out), expected.size);
            EXPECT_BYTEARRAY_EQUAL(s2n_stuffer_raw_read(&out, expected.size), expected.data, expected.size);
        }

        /* An empty extension list decompresses to an empty list */
        {
            struct s2n_blob encoded_inner = { 0 };
            S2N_BLOB_FROM_HEX(outer, TEST_OUTER_EXTENSIONS);
            DEFER_CLEANUP(struct s2n_stuffer out = { 0 }, s2n_stuffer_free);
            EXPECT_OK(s2n_ech_decompress_extensions(&encoded_inner, &outer, &out));
            EXPECT_EQUAL(s2n_stuffer_data_available(&out), 0);
        };

        /* An output stuffer that is already allocated is rejected, rather than
         * leaked */
        {
            S2N_BLOB_FROM_HEX(encoded_inner, TEST_INNER_EXT_X);
            S2N_BLOB_FROM_HEX(outer, TEST_OUTER_EXTENSIONS);
            DEFER_CLEANUP(struct s2n_stuffer out = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_alloc(&out, 1));
            uint8_t *allocated = out.blob.data;
            EXPECT_ERROR_WITH_ERRNO(s2n_ech_decompress_extensions(&encoded_inner, &outer, &out), S2N_ERR_SAFETY);
            EXPECT_EQUAL(out.blob.data, allocated);
        };
    };

    /*
     *= https://www.rfc-editor.org/rfc/rfc9849#section-5.1
     *= type=test
     *# The server MUST abort the connection with an
     *# "illegal_parameter" alert if any of the following are true:
     *#
     *# *  Any referenced extension is missing in ClientHelloOuter.
     *#
     *# *  Any extension is referenced in OuterExtensions more than once.
     *#
     *# *  "encrypted_client_hello" is referenced in OuterExtensions.
     *#
     *# *  The extensions in ClientHelloOuter corresponding to those in
     *#    OuterExtensions do not occur in the same order.
     */
    {
        /* clang-format off */
        struct {
            const char *encoded_inner;
            s2n_error expected_error;
        } test_cases[] = {
            /* A referenced extension is missing from the outer */
            {
                    .encoded_inner = "fd00" "0003" "02" "0016",
                    .expected_error = S2N_ERR_ECH_INVALID_OUTER_EXTENSIONS,
            },
            /* An extension is referenced twice */
            {
                    .encoded_inner = "fd00" "0005" "04" "000a" "000a",
                    .expected_error = S2N_ERR_ECH_INVALID_OUTER_EXTENSIONS,
            },
            /* An extension is referenced twice, not adjacently */
            {
                    .encoded_inner = "fd00" "0007" "06" "000a" "000d" "000a",
                    .expected_error = S2N_ERR_ECH_INVALID_OUTER_EXTENSIONS,
            },
            /* The references are out of order */
            {
                    .encoded_inner = "fd00" "0005" "04" "000d" "000a",
                    .expected_error = S2N_ERR_ECH_INVALID_OUTER_EXTENSIONS,
            },
            /* References to extensions s2n does not recognize, out of order */
            {
                    .encoded_inner = "fd00" "0005" "04" "1234" "0015",
                    .expected_error = S2N_ERR_ECH_INVALID_OUTER_EXTENSIONS,
            },
            /* encrypted_client_hello is referenced */
            {
                    .encoded_inner = "fd00" "0003" "02" "fe0d",
                    .expected_error = S2N_ERR_ECH_INVALID_OUTER_EXTENSIONS,
            },
            /* encrypted_client_hello is referenced after a valid reference */
            {
                    .encoded_inner = "fd00" "0005" "04" "000a" "fe0d",
                    .expected_error = S2N_ERR_ECH_INVALID_OUTER_EXTENSIONS,
            },
            /* Two ech_outer_extensions */
            {
                    .encoded_inner = "fd00" "0003" "02" "000a" "fd00" "0003" "02" "000d",
                    .expected_error = S2N_ERR_DUPLICATE_EXTENSION,
            },
            /* An empty OuterExtensions */
            {
                    .encoded_inner = "fd00" "0001" "00",
                    .expected_error = S2N_ERR_BAD_MESSAGE,
            },
            /* An odd-length OuterExtensions */
            {
                    .encoded_inner = "fd00" "0004" "03" "0016" "00",
                    .expected_error = S2N_ERR_BAD_MESSAGE,
            },
            /* An empty ech_outer_extensions body */
            {
                    .encoded_inner = "fd00" "0000",
                    .expected_error = S2N_ERR_BAD_MESSAGE,
            },
            /* OuterExtensions longer than its extension */
            {
                    .encoded_inner = "fd00" "0003" "04" "000a",
                    .expected_error = S2N_ERR_BAD_MESSAGE,
            },
            /* Trailing data after OuterExtensions */
            {
                    .encoded_inner = "fd00" "0004" "02" "000a" "ff",
                    .expected_error = S2N_ERR_BAD_MESSAGE,
            },
            /* A truncated extension */
            {
                    .encoded_inner = TEST_INNER_EXT_X "0000" "0004" "1111",
                    .expected_error = S2N_ERR_BAD_MESSAGE,
            },
            /* A truncated extension header */
            {
                    .encoded_inner = TEST_INNER_EXT_X "00",
                    .expected_error = S2N_ERR_BAD_MESSAGE,
            },
        };
        /* clang-format on */
        for (size_t i = 0; i < s2n_array_len(test_cases); i++) {
            DEFER_CLEANUP(struct s2n_stuffer out = { 0 }, s2n_stuffer_free);
            EXPECT_ERROR_WITH_ERRNO(s2n_test_decompress(test_cases[i].encoded_inner, &out),
                    test_cases[i].expected_error);
            /* A failed call leaves the output untouched */
            EXPECT_NULL(out.blob.data);
        }

        /* A malformed outer extension list is rejected */
        {
            /* clang-format off */
            S2N_BLOB_FROM_HEX(encoded_inner, "fd00" "0003" "02" "000d");
            S2N_BLOB_FROM_HEX(outer, TEST_OUTER_EXT_A "000d" "0004" "bbbb");
            /* clang-format on */
            DEFER_CLEANUP(struct s2n_stuffer out = { 0 }, s2n_stuffer_free);
            EXPECT_ERROR_WITH_ERRNO(s2n_ech_decompress_extensions(&encoded_inner, &outer, &out),
                    S2N_ERR_BAD_MESSAGE);
        };

        /* A reference to ech_outer_extensions is rejected, even when the outer
         * carries one. s2n's extension parser ignores the type, so it does not
         * reject such an outer. */
        {
            /* clang-format off */
            S2N_BLOB_FROM_HEX(encoded_inner, "fd00" "0003" "02" "fd00");
            S2N_BLOB_FROM_HEX(outer, TEST_OUTER_EXT_A "fd00" "0002" "0000");
            /* clang-format on */
            DEFER_CLEANUP(struct s2n_stuffer out = { 0 }, s2n_stuffer_free);
            EXPECT_ERROR_WITH_ERRNO(s2n_ech_decompress_extensions(&encoded_inner, &outer, &out),
                    S2N_ERR_ECH_INVALID_OUTER_EXTENSIONS);
            EXPECT_NULL(out.blob.data);
        };

        /* A repeated reference is rejected even when the outer repeats the
         * extension. s2n's extension parser ignores extension types it does
         * not recognize, so it does not reject such an outer. */
        {
            /* clang-format off */
            const char *repeated[] = {
                "fd00" "0005" "04" "1234" "1234",
                "fd00" "0007" "06" "1234" "000d" "1234",
            };
            /* clang-format on */
            S2N_BLOB_FROM_HEX(outer, TEST_OUTER_EXT_E TEST_OUTER_EXT_B TEST_OUTER_EXT_E);
            for (size_t i = 0; i < s2n_array_len(repeated); i++) {
                DEFER_CLEANUP(struct s2n_blob encoded_inner = { 0 }, s2n_free);
                EXPECT_OK(s2n_blob_alloc_from_hex_with_whitespace(&encoded_inner, repeated[i]));
                DEFER_CLEANUP(struct s2n_stuffer out = { 0 }, s2n_stuffer_free);
                EXPECT_ERROR_WITH_ERRNO(s2n_ech_decompress_extensions(&encoded_inner, &outer, &out),
                        S2N_ERR_ECH_INVALID_OUTER_EXTENSIONS);
                EXPECT_NULL(out.blob.data);
            }
        };
    };

    /*
     *= https://www.rfc-editor.org/rfc/rfc9849#section-10.12.4
     *= type=test
     *# ECH mitigates this attack by requiring that OuterExtensions be
     *# referenced in order, that duplicate references be rejected, and by
     *# recommending that client-facing servers use a linear scan to perform
     *# decompression.
     */
    {
        /* A ClientHelloOuter with one large extension, referenced as many
         * times as OuterExtensions allows, cannot be copied more than once. */
        const uint16_t large_size = 60000;
        DEFER_CLEANUP(struct s2n_stuffer outer_in = { 0 }, s2n_stuffer_free);
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&outer_in, 0));
        EXPECT_SUCCESS(s2n_stuffer_write_uint16(&outer_in, 0x000a));
        EXPECT_SUCCESS(s2n_stuffer_write_uint16(&outer_in, large_size));
        EXPECT_SUCCESS(s2n_stuffer_skip_write(&outer_in, large_size));
        struct s2n_blob outer = { 0 };
        EXPECT_SUCCESS(s2n_blob_init(&outer, outer_in.blob.data, s2n_stuffer_data_available(&outer_in)));

        const uint8_t max_references = 127;
        DEFER_CLEANUP(struct s2n_stuffer inner_in = { 0 }, s2n_stuffer_free);
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&inner_in, 0));
        EXPECT_SUCCESS(s2n_stuffer_write_uint16(&inner_in, TLS_EXTENSION_ECH_OUTER_EXTENSIONS));
        EXPECT_SUCCESS(s2n_stuffer_write_uint16(&inner_in, 1 + max_references * 2));
        EXPECT_SUCCESS(s2n_stuffer_write_uint8(&inner_in, max_references * 2));
        for (size_t i = 0; i < max_references; i++) {
            EXPECT_SUCCESS(s2n_stuffer_write_uint16(&inner_in, 0x000a));
        }
        struct s2n_blob encoded_inner = { 0 };
        EXPECT_SUCCESS(s2n_blob_init(&encoded_inner, inner_in.blob.data, s2n_stuffer_data_available(&inner_in)));

        DEFER_CLEANUP(struct s2n_stuffer out = { 0 }, s2n_stuffer_free);
        EXPECT_ERROR_WITH_ERRNO(s2n_ech_decompress_extensions(&encoded_inner, &outer, &out),
                S2N_ERR_ECH_INVALID_OUTER_EXTENSIONS);

        /* Referenced once, it decompresses, and the output stays within
         * the size of the two inputs */
        /* clang-format off */
        S2N_BLOB_FROM_HEX(single_reference, "fd00" "0003" "02" "000a");
        /* clang-format on */
        DEFER_CLEANUP(struct s2n_stuffer single_out = { 0 }, s2n_stuffer_free);
        EXPECT_OK(s2n_ech_decompress_extensions(&single_reference, &outer, &single_out));
        EXPECT_EQUAL(s2n_stuffer_data_available(&single_out), outer.size);
    };

    /*
     *= https://www.rfc-editor.org/rfc/rfc9849#section-5.1
     *= type=test
     *# The client-facing server computes ClientHelloInner by reversing this
     *# process.
     */
    {
        S2N_BLOB_FROM_HEX(outer_message, TEST_CLIENT_HELLO_OUTER);
        DEFER_CLEANUP(struct s2n_client_hello *outer = s2n_client_hello_parse_message(
                              outer_message.data, outer_message.size),
                s2n_client_hello_free);
        EXPECT_NOT_NULL(outer);

        S2N_BLOB_FROM_HEX(expected_message, TEST_INNER_MESSAGE);
        S2N_BLOB_FROM_HEX(expected_body, TEST_INNER_BODY);

        /* The EncodedClientHelloInner decodes to the ClientHelloInner, with and
         * without the handshake header */
        {
            DEFER_CLEANUP(struct s2n_blob inner_message = { 0 }, s2n_free);
            DEFER_CLEANUP(struct s2n_blob inner_raw_message = { 0 }, s2n_free);
            EXPECT_OK(s2n_test_decode(TEST_ENCODED_INNER, outer, &inner_message, &inner_raw_message));
            EXPECT_EQUAL(inner_message.size, expected_message.size);
            EXPECT_BYTEARRAY_EQUAL(inner_message.data, expected_message.data, expected_message.size);
            EXPECT_EQUAL(inner_raw_message.size, expected_body.size);
            EXPECT_BYTEARRAY_EQUAL(inner_raw_message.data, expected_body.data, expected_body.size);

            /* The result is a ClientHello that s2n parses */
            DEFER_CLEANUP(struct s2n_client_hello *inner = s2n_client_hello_parse_message(
                                  inner_message.data, inner_message.size),
                    s2n_client_hello_free);
            EXPECT_NOT_NULL(inner);
            uint8_t server_name[sizeof("secret.example")] = { 0 };
            uint16_t server_name_length = 0;
            EXPECT_SUCCESS(s2n_client_hello_get_server_name(inner, server_name, sizeof(server_name),
                    &server_name_length));
            EXPECT_EQUAL(server_name_length, strlen("secret.example"));
            EXPECT_BYTEARRAY_EQUAL(server_name, "secret.example", server_name_length);
        };

        /*
         *= https://www.rfc-editor.org/rfc/rfc9849#section-5.1
         *= type=test
         *# Next, it makes a copy of the client_hello field and copies the
         *# legacy_session_id field from ClientHelloOuter.
         */
        {
            /* The outer's session id replaces the empty one */
            DEFER_CLEANUP(struct s2n_blob inner_message = { 0 }, s2n_free);
            DEFER_CLEANUP(struct s2n_blob inner_raw_message = { 0 }, s2n_free);
            EXPECT_OK(s2n_test_decode(TEST_ENCODED_INNER, outer, &inner_message, &inner_raw_message));
            DEFER_CLEANUP(struct s2n_client_hello *inner = s2n_client_hello_parse_message(
                                  inner_message.data, inner_message.size),
                    s2n_client_hello_free);
            EXPECT_NOT_NULL(inner);
            EXPECT_EQUAL(inner->session_id.size, outer->session_id.size);
            EXPECT_BYTEARRAY_EQUAL(inner->session_id.data, outer->session_id.data, outer->session_id.size);

            /* An outer with an empty session id gives an inner with an empty
             * session id */
            struct s2n_client_hello outer_without_session_id = *outer;
            outer_without_session_id.session_id = (struct s2n_blob){ 0 };
            DEFER_CLEANUP(struct s2n_blob message_without_session_id = { 0 }, s2n_free);
            DEFER_CLEANUP(struct s2n_blob raw_message_without_session_id = { 0 }, s2n_free);
            EXPECT_OK(s2n_test_decode(TEST_ENCODED_INNER, &outer_without_session_id,
                    &message_without_session_id, &raw_message_without_session_id));
            EXPECT_EQUAL(raw_message_without_session_id.size, expected_body.size - S2N_TLS_SESSION_ID_MAX_LEN);
            EXPECT_EQUAL(raw_message_without_session_id.data[S2N_TLS_PROTOCOL_VERSION_LEN + S2N_TLS_RANDOM_DATA_LEN], 0);
        };

        /*
         *= https://www.rfc-editor.org/rfc/rfc9849#section-5.1
         *= type=test
         *# First, it parses EncodedClientHelloInner, interpreting all
         *# bytes after client_hello as padding.  If any padding byte is non-
         *# zero, the server MUST abort the connection with an
         *# "illegal_parameter" alert.
         */
        {
            /* Zero padding of any length is stripped */
            /* clang-format off */
            const char *padded[] = {
                TEST_ENCODED_INNER "00",
                TEST_ENCODED_INNER "0000000000000000000000000000000000000000",
            };
            /* clang-format on */
            for (size_t i = 0; i < s2n_array_len(padded); i++) {
                DEFER_CLEANUP(struct s2n_blob inner_message = { 0 }, s2n_free);
                DEFER_CLEANUP(struct s2n_blob inner_raw_message = { 0 }, s2n_free);
                EXPECT_OK(s2n_test_decode(padded[i], outer, &inner_message, &inner_raw_message));
                EXPECT_EQUAL(inner_message.size, expected_message.size);
                EXPECT_BYTEARRAY_EQUAL(inner_message.data, expected_message.data, expected_message.size);
            }

            /* A non-zero padding byte anywhere is rejected */
            /* clang-format off */
            const char *bad_padding[] = {
                TEST_ENCODED_INNER "01",
                TEST_ENCODED_INNER "80000000",
                TEST_ENCODED_INNER "00000100",
                TEST_ENCODED_INNER "000000ff",
            };
            /* clang-format on */
            for (size_t i = 0; i < s2n_array_len(bad_padding); i++) {
                DEFER_CLEANUP(struct s2n_blob inner_message = { 0 }, s2n_free);
                DEFER_CLEANUP(struct s2n_blob inner_raw_message = { 0 }, s2n_free);
                EXPECT_ERROR_WITH_ERRNO(s2n_test_decode(bad_padding[i], outer, &inner_message, &inner_raw_message),
                        S2N_ERR_ECH_INVALID_CLIENT_HELLO);
                EXPECT_EQUAL(inner_message.size, 0);
                EXPECT_EQUAL(inner_raw_message.size, 0);
            }
        };

        /* A malformed EncodedClientHelloInner is rejected */
        {
            /* clang-format off */
            const char *malformed[] = {
                /* truncated legacy_version */
                "03",
                /* truncated random */
                "0303" "4041",
                /* missing legacy_session_id */
                "0303" TEST_INNER_RANDOM,
                /* legacy_session_id too long, followed by valid fields */
                "0303" TEST_INNER_RANDOM "21"
                "000000000000000000000000000000000000000000000000000000000000000000"
                "0002" "1301" "01" "00" "0000",
                /* truncated cipher_suites */
                "0303" TEST_INNER_RANDOM "00" "0004" "1301",
                /* truncated legacy_compression_methods */
                "0303" TEST_INNER_RANDOM "00" "0002" "1301" "02" "00",
                /* missing extensions */
                "0303" TEST_INNER_RANDOM "00" "0002" "1301" "01" "00",
                /* truncated extensions */
                "0303" TEST_INNER_RANDOM "00" "0002" "1301" "01" "00" "0023" TEST_INNER_EXT_SERVER_NAME,
                /* a malformed extension */
                "0303" TEST_INNER_RANDOM "00" "0002" "1301" "01" "00" "0002" "0000",
            };
            /* clang-format on */
            for (size_t i = 0; i < s2n_array_len(malformed); i++) {
                DEFER_CLEANUP(struct s2n_blob inner_message = { 0 }, s2n_free);
                DEFER_CLEANUP(struct s2n_blob inner_raw_message = { 0 }, s2n_free);
                EXPECT_ERROR_WITH_ERRNO(s2n_test_decode(malformed[i], outer, &inner_message, &inner_raw_message),
                        S2N_ERR_BAD_MESSAGE);
            }
        };

        /* Output blobs that are already allocated are rejected, rather than
         * leaked */
        {
            S2N_BLOB_FROM_HEX(encoded_inner, TEST_ENCODED_INNER);
            for (size_t i = 0; i < 2; i++) {
                DEFER_CLEANUP(struct s2n_blob inner_message = { 0 }, s2n_free);
                DEFER_CLEANUP(struct s2n_blob inner_raw_message = { 0 }, s2n_free);
                struct s2n_blob *allocated_blob = (i == 0) ? &inner_message : &inner_raw_message;
                EXPECT_SUCCESS(s2n_alloc(allocated_blob, 1));
                uint8_t *allocated = allocated_blob->data;
                EXPECT_ERROR_WITH_ERRNO(s2n_ech_encoded_inner_decode(&encoded_inner, outer,
                                                &inner_message, &inner_raw_message),
                        S2N_ERR_SAFETY);
                EXPECT_EQUAL(allocated_blob->data, allocated);
            }
        };

        /* A decompression error fails the decode */
        {
            DEFER_CLEANUP(struct s2n_blob inner_message = { 0 }, s2n_free);
            DEFER_CLEANUP(struct s2n_blob inner_raw_message = { 0 }, s2n_free);
            /* clang-format off */
            EXPECT_ERROR_WITH_ERRNO(s2n_test_decode("0303" TEST_INNER_RANDOM "00" "0002" "1301" "01" "00"
                                                    "0007" "fd00" "0003" "02" "0033",
                                            outer, &inner_message, &inner_raw_message),
                    S2N_ERR_ECH_INVALID_OUTER_EXTENSIONS);
            /* clang-format on */
        };
    };

    /* The size limits on the decoded ClientHelloInner. The ClientHelloOuter
     * has one 60000-byte extension. */
    {
        const uint16_t large_size = 60000;
        DEFER_CLEANUP(struct s2n_stuffer outer_extensions = { 0 }, s2n_stuffer_free);
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&outer_extensions, 0));
        EXPECT_SUCCESS(s2n_stuffer_write_uint16(&outer_extensions, 0x000a));
        EXPECT_SUCCESS(s2n_stuffer_write_uint16(&outer_extensions, large_size));
        EXPECT_SUCCESS(s2n_stuffer_skip_write(&outer_extensions, large_size));
        uint8_t session_id[S2N_TLS_SESSION_ID_MAX_LEN] = { 0 };
        struct s2n_client_hello outer = { 0 };
        EXPECT_SUCCESS(s2n_blob_init(&outer.extensions.raw, outer_extensions.blob.data,
                s2n_stuffer_data_available(&outer_extensions)));

        /* An EncodedClientHelloInner with `cipher_suites_size` bytes of
         * cipher_suites, an inner extension of `inner_size` bytes, and a
         * reference to the large outer extension */
        struct {
            uint16_t inner_size;
            uint16_t cipher_suites_size;
            uint8_t outer_session_id_size;
            bool expect_ok;
        } test_cases[] = {
            /* Extensions of 4 + 5000 + 4 + 60000 = 65008 bytes fit */
            { .inner_size = 5000, .cipher_suites_size = 2, .outer_session_id_size = 0, .expect_ok = true },
            /* Extensions of 66008 bytes do not fit in an extension list */
            { .inner_size = 6000, .cipher_suites_size = 2, .outer_session_id_size = 0, .expect_ok = false },
            /* With the outer's session id, a body of 2 + 32 + 1 + 32 + 2 + 455
             * + 2 + 2 + 65008 = 65536 bytes fits */
            { .inner_size = 5000, .cipher_suites_size = 455, .outer_session_id_size = 32, .expect_ok = true },
            /* One more byte of cipher_suites does not, though the extensions
             * still fit in an extension list */
            { .inner_size = 5000, .cipher_suites_size = 456, .outer_session_id_size = 32, .expect_ok = false },
        };
        for (size_t i = 0; i < s2n_array_len(test_cases); i++) {
            const uint16_t inner_size = test_cases[i].inner_size;
            const uint16_t cipher_suites_size = test_cases[i].cipher_suites_size;
            EXPECT_SUCCESS(s2n_blob_init(&outer.session_id, session_id, test_cases[i].outer_session_id_size));

            DEFER_CLEANUP(struct s2n_stuffer encoded = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&encoded, 0));
            EXPECT_SUCCESS(s2n_stuffer_write_uint16(&encoded, 0x0303));
            EXPECT_SUCCESS(s2n_stuffer_skip_write(&encoded, S2N_TLS_RANDOM_DATA_LEN));
            EXPECT_SUCCESS(s2n_stuffer_write_uint8(&encoded, 0));
            EXPECT_SUCCESS(s2n_stuffer_write_uint16(&encoded, cipher_suites_size));
            EXPECT_SUCCESS(s2n_stuffer_skip_write(&encoded, cipher_suites_size));
            EXPECT_SUCCESS(s2n_stuffer_write_uint8(&encoded, 1));
            EXPECT_SUCCESS(s2n_stuffer_write_uint8(&encoded, 0));
            EXPECT_SUCCESS(s2n_stuffer_write_uint16(&encoded, 4 + inner_size + 7));
            EXPECT_SUCCESS(s2n_stuffer_write_uint16(&encoded, 0x0001));
            EXPECT_SUCCESS(s2n_stuffer_write_uint16(&encoded, inner_size));
            EXPECT_SUCCESS(s2n_stuffer_skip_write(&encoded, inner_size));
            EXPECT_SUCCESS(s2n_stuffer_write_uint16(&encoded, TLS_EXTENSION_ECH_OUTER_EXTENSIONS));
            EXPECT_SUCCESS(s2n_stuffer_write_uint16(&encoded, 3));
            EXPECT_SUCCESS(s2n_stuffer_write_uint8(&encoded, 2));
            EXPECT_SUCCESS(s2n_stuffer_write_uint16(&encoded, 0x000a));
            struct s2n_blob encoded_inner = { 0 };
            EXPECT_SUCCESS(s2n_blob_init(&encoded_inner, encoded.blob.data, s2n_stuffer_data_available(&encoded)));

            DEFER_CLEANUP(struct s2n_blob inner_message = { 0 }, s2n_free);
            DEFER_CLEANUP(struct s2n_blob inner_raw_message = { 0 }, s2n_free);
            s2n_result result = s2n_ech_encoded_inner_decode(&encoded_inner, &outer, &inner_message, &inner_raw_message);
            if (!test_cases[i].expect_ok) {
                EXPECT_ERROR_WITH_ERRNO(result, S2N_ERR_BAD_MESSAGE);
                continue;
            }
            EXPECT_OK(result);
            EXPECT_TRUE(inner_raw_message.size <= S2N_MAXIMUM_HANDSHAKE_MESSAGE_LENGTH);

            /* The extensions length prefix is the decompressed size, not the
             * encoded one */
            const uint32_t extensions_offset = S2N_TLS_PROTOCOL_VERSION_LEN + S2N_TLS_RANDOM_DATA_LEN
                    + 1 + test_cases[i].outer_session_id_size + 2 + cipher_suites_size + 2;
            struct s2n_stuffer body = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_init_written(&body, &inner_raw_message));
            EXPECT_SUCCESS(s2n_stuffer_skip_read(&body, extensions_offset));
            uint16_t extensions_size = 0;
            EXPECT_SUCCESS(s2n_stuffer_read_uint16(&body, &extensions_size));
            EXPECT_EQUAL(extensions_size, 65008);
            EXPECT_EQUAL(s2n_stuffer_data_available(&body), 65008);

            /* The result parses with the decompressed extensions.
             * s2n_client_hello_parse_message limits the message with its
             * header to S2N_MAXIMUM_HANDSHAKE_MESSAGE_LENGTH, while a
             * ClientHello on the wire, like the decoded one, may have a body
             * of that size. */
            if (inner_message.size <= S2N_MAXIMUM_HANDSHAKE_MESSAGE_LENGTH) {
                DEFER_CLEANUP(struct s2n_client_hello *inner = s2n_client_hello_parse_message(
                                      inner_message.data, inner_message.size),
                        s2n_client_hello_free);
                EXPECT_NOT_NULL(inner);
                EXPECT_EQUAL(inner->extensions.raw.size, 65008);
            }
        }
    };

    END_TEST();
}
