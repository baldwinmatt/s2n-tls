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

/* Target Functions: s2n_ech_encoded_inner_decode s2n_ech_decompress_extensions s2n_ech_client_hello_parse */

#include <stdint.h>

#include "api/s2n.h"
#include "s2n_test.h"
#include "stuffer/s2n_stuffer.h"
#include "tls/s2n_client_hello.h"
#include "tls/s2n_ech_encoding.h"
#include "tls/s2n_tls_parameters.h"
#include "utils/s2n_safety.h"

/* The input is the length of the ClientHelloOuter's session id, the
 * extensions of the ClientHelloOuter prefixed with their uint16 length, and
 * an EncodedClientHelloInner:
 *
 *     uint8 outer_session_id_size;    (taken modulo 33)
 *     opaque outer_extensions<0..2^16-1>;
 *     opaque encoded_client_hello_inner[rest of input];
 *
 * The EncodedClientHelloInner bytes are also parsed as an ECHClientHello.
 */
int s2n_fuzz_test(const uint8_t *buf, size_t len)
{
    S2N_FUZZ_ENSURE_MIN_LEN(len, sizeof(uint8_t) + sizeof(uint16_t));

    /* Copy the input so that parsed blobs point into s2n-owned memory */
    DEFER_CLEANUP(struct s2n_stuffer input = { 0 }, s2n_stuffer_free);
    POSIX_GUARD(s2n_stuffer_alloc(&input, len));
    POSIX_GUARD(s2n_stuffer_write_bytes(&input, buf, len));

    uint8_t session_id_size = 0;
    POSIX_GUARD(s2n_stuffer_read_uint8(&input, &session_id_size));
    session_id_size %= S2N_TLS_SESSION_ID_MAX_LEN + 1;

    uint16_t outer_extensions_size = 0;
    POSIX_GUARD(s2n_stuffer_read_uint16(&input, &outer_extensions_size));
    uint8_t *outer_extensions = s2n_stuffer_raw_read(&input, outer_extensions_size);
    if (outer_extensions == NULL) {
        return S2N_SUCCESS;
    }

    uint8_t session_id[S2N_TLS_SESSION_ID_MAX_LEN] = { 0 };
    struct s2n_client_hello outer = { 0 };
    POSIX_GUARD(s2n_blob_init(&outer.extensions.raw, outer_extensions, outer_extensions_size));
    POSIX_GUARD(s2n_blob_init(&outer.session_id, session_id, session_id_size));

    uint32_t encoded_inner_size = s2n_stuffer_data_available(&input);
    struct s2n_blob encoded_inner = { 0 };
    POSIX_GUARD(s2n_blob_init(&encoded_inner, s2n_stuffer_raw_read(&input, encoded_inner_size),
            encoded_inner_size));

    /* Parse the same bytes as an ECHClientHello. Malformed input is expected
     * to fail, but only with an error for malformed input. */
    struct s2n_ech_client_hello ech = { 0 };
    if (s2n_result_is_ok(s2n_ech_client_hello_parse(&encoded_inner, &ech))) {
        /* The parsed fields fit within the input */
        EXPECT_TRUE(ech.payload.size > 0 || ech.type == S2N_ECH_CLIENT_HELLO_INNER);
        EXPECT_TRUE(ech.enc.size + ech.payload.size <= encoded_inner_size);
    } else {
        EXPECT_TRUE(s2n_errno == S2N_ERR_BAD_MESSAGE || s2n_errno == S2N_ERR_ECH_INVALID_CLIENT_HELLO);
    }

    DEFER_CLEANUP(struct s2n_blob inner_message = { 0 }, s2n_free);
    DEFER_CLEANUP(struct s2n_blob inner_raw_message = { 0 }, s2n_free);

    /* Malformed input is expected to fail, but only with an error for
     * malformed input. Any other error, such as S2N_ERR_SAFETY or a full
     * stuffer, means an internal invariant broke. */
    if (s2n_result_is_error(s2n_ech_encoded_inner_decode(&encoded_inner, &outer,
                &inner_message, &inner_raw_message))) {
        EXPECT_TRUE(s2n_errno == S2N_ERR_BAD_MESSAGE
                || s2n_errno == S2N_ERR_ECH_INVALID_CLIENT_HELLO
                || s2n_errno == S2N_ERR_ECH_INVALID_OUTER_EXTENSIONS
                || s2n_errno == S2N_ERR_DUPLICATE_EXTENSION);
        EXPECT_NULL(inner_message.data);
        EXPECT_NULL(inner_raw_message.data);
        return S2N_SUCCESS;
    }

    /* The two copies hold the same ClientHello, one with a handshake header */
    EXPECT_EQUAL(inner_message.size, inner_raw_message.size + TLS_HANDSHAKE_HEADER_LENGTH);
    EXPECT_BYTEARRAY_EQUAL(inner_message.data + TLS_HANDSHAKE_HEADER_LENGTH, inner_raw_message.data,
            inner_raw_message.size);

    /* A decoded ClientHelloInner need not be a valid ClientHello, but parsing
     * it must be safe */
    struct s2n_client_hello *inner = s2n_client_hello_parse_message(inner_message.data, inner_message.size);
    EXPECT_SUCCESS(s2n_client_hello_free(&inner));

    return S2N_SUCCESS;
}

S2N_FUZZ_TARGET(NULL, s2n_fuzz_test, NULL)
