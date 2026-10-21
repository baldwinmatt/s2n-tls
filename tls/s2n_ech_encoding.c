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

#include "stuffer/s2n_stuffer.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_crypto_constants.h"
#include "tls/s2n_ech_parse.h"
#include "tls/s2n_tls_parameters.h"
#include "utils/s2n_mem.h"
#include "utils/s2n_safety.h"

S2N_RESULT s2n_ech_client_hello_parse(const struct s2n_blob *extension_data, struct s2n_ech_client_hello *ech)
{
    RESULT_ENSURE_REF(extension_data);
    RESULT_ENSURE_REF(ech);
    *ech = (struct s2n_ech_client_hello){ 0 };

    struct s2n_blob extension_copy = *extension_data;
    struct s2n_stuffer in = { 0 };
    RESULT_GUARD_POSIX(s2n_stuffer_init_written(&in, &extension_copy));

    /*
     *= https://www.rfc-editor.org/rfc/rfc9849#section-5
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
    RESULT_GUARD(s2n_ech_read_uint8(&in, &ech->type, S2N_ERR_BAD_MESSAGE));
    switch (ech->type) {
        case S2N_ECH_CLIENT_HELLO_OUTER:
            RESULT_GUARD(s2n_ech_read_uint16(&in, &ech->kdf_id, S2N_ERR_BAD_MESSAGE));
            RESULT_GUARD(s2n_ech_read_uint16(&in, &ech->aead_id, S2N_ERR_BAD_MESSAGE));
            RESULT_GUARD(s2n_ech_read_uint8(&in, &ech->config_id, S2N_ERR_BAD_MESSAGE));
            RESULT_GUARD(s2n_ech_read_uint16_vector(&in, &ech->enc, S2N_ERR_BAD_MESSAGE));
            RESULT_GUARD(s2n_ech_read_uint16_vector(&in, &ech->payload, S2N_ERR_BAD_MESSAGE));
            RESULT_ENSURE(ech->payload.size >= 1, S2N_ERR_BAD_MESSAGE);
            break;
        case S2N_ECH_CLIENT_HELLO_INNER:
            break;
        default:
            /*
             *= https://www.rfc-editor.org/rfc/rfc9849#section-7
             *# If ECHClientHello.type is not a valid ECHClientHelloType, then the
             *# server MUST abort with an "illegal_parameter" alert.
             */
            RESULT_BAIL(S2N_ERR_ECH_INVALID_CLIENT_HELLO);
    }
    RESULT_ENSURE(s2n_stuffer_data_available(&in) == 0, S2N_ERR_BAD_MESSAGE);

    return S2N_RESULT_OK;
}

/* Checks that `inner` lies entirely within `outer` */
static bool s2n_ech_blob_is_within(const struct s2n_blob *inner, const struct s2n_blob *outer)
{
    if (inner->data == NULL || outer->data == NULL) {
        return false;
    }
    uintptr_t inner_start = (uintptr_t) inner->data;
    uintptr_t outer_start = (uintptr_t) outer->data;
    if (inner_start < outer_start) {
        return false;
    }
    uintptr_t offset = inner_start - outer_start;
    return offset <= outer->size && inner->size <= outer->size - offset;
}

S2N_RESULT s2n_ech_build_outer_aad(const struct s2n_client_hello *client_hello,
        const struct s2n_blob *payload, struct s2n_blob *aad)
{
    RESULT_ENSURE_REF(client_hello);
    RESULT_ENSURE_REF(payload);
    RESULT_ENSURE_REF(aad);
    /* `aad` is allocated here, so an allocated one would be leaked */
    RESULT_ENSURE(aad->data == NULL, S2N_ERR_SAFETY);
    /* An SSLv2 ClientHello has no extensions and a different layout */
    RESULT_ENSURE(!client_hello->sslv2, S2N_ERR_SAFETY);

    /* raw_message must still hold the bytes the client sent, apart from the
     * random. Processing the extensions changes it in place: the
     * pre_shared_key extension decrypts session tickets inside raw_message.
     * So the AAD must be built before any extension of this ClientHello is
     * processed. */
    for (size_t i = 0; i < S2N_PARSED_EXTENSIONS_COUNT; i++) {
        RESULT_ENSURE(!client_hello->extensions.parsed_extensions[i].processed, S2N_ERR_SAFETY);
    }

    const struct s2n_blob *raw_message = &client_hello->raw_message;
    RESULT_ENSURE_REF(raw_message->data);

    /* The body starts with legacy_version followed by the random */
    const uint32_t random_offset = S2N_TLS_PROTOCOL_VERSION_LEN;
    RESULT_ENSURE(raw_message->size >= random_offset + S2N_TLS_RANDOM_DATA_LEN, S2N_ERR_SAFETY);

    /* The payload is part of the encrypted_client_hello extension, so it
     * must lie within the extensions, which lie within raw_message */
    RESULT_ENSURE(s2n_ech_blob_is_within(&client_hello->extensions.raw, raw_message), S2N_ERR_SAFETY);
    RESULT_ENSURE(s2n_ech_blob_is_within(payload, &client_hello->extensions.raw), S2N_ERR_SAFETY);
    const uintptr_t payload_offset = (uintptr_t) payload->data - (uintptr_t) raw_message->data;
    RESULT_ENSURE(payload_offset >= random_offset + S2N_TLS_RANDOM_DATA_LEN, S2N_ERR_SAFETY);

    DEFER_CLEANUP(struct s2n_blob out = { 0 }, s2n_free);
    RESULT_GUARD_POSIX(s2n_alloc(&out, raw_message->size));
    RESULT_CHECKED_MEMCPY(out.data, raw_message->data, raw_message->size);

    /* Restore the random that s2n_client_hello_parse_raw erased */
    RESULT_CHECKED_MEMCPY(out.data + random_offset, client_hello->random, S2N_TLS_RANDOM_DATA_LEN);

    /*
     *= https://www.rfc-editor.org/rfc/rfc9849#section-5.2
     *# The ClientHelloOuterAAD is a serialized
     *# ClientHello structure, defined in Section 4.1.2 of [RFC8446] for TLS
     *# and Section 5.3 of [RFC9147] for DTLS, which matches the
     *# ClientHelloOuter except that the payload field of the
     *# "encrypted_client_hello" is replaced with a byte string of the same
     *# length but whose contents are zeros.  This value does not include the
     *# Handshake structure's four-byte header in TLS nor the twelve-byte
     *# header in DTLS.
     *
     * raw_message is the body without the handshake header.
     */
    RESULT_CHECKED_MEMSET(out.data + payload_offset, 0, payload->size);

    *aad = out;
    ZERO_TO_DISABLE_DEFER_CLEANUP(out);
    return S2N_RESULT_OK;
}

/* Copies the ClientHelloOuter extensions referenced by one
 * "ech_outer_extensions" extension body to `out`.
 *
 * `outer` is a single forward cursor over the ClientHelloOuter extensions,
 * and it is never rewound. That enforces two of the Section 10.12.4
 * defences:
 * - A reference that is out of order walks the cursor past its target, so
 *   the target is never found.
 * - Each outer extension is copied at most once, which bounds the output by
 *   the size of the two inputs and makes the walk linear. No counter of
 *   copied bytes is needed.
 *
 * The cursor alone does not reject a repeated reference: s2n's extension
 * parser ignores extension types it does not recognize, so a ClientHelloOuter
 * can carry two extensions of an unrecognized type, and a second reference
 * would find the second copy ahead of the cursor. Repeated references are
 * therefore checked against the types already read. OuterExtensions holds at
 * most 127 types, so the check is cheap.
 */
static S2N_RESULT s2n_ech_copy_outer_extensions(struct s2n_blob *outer_extensions_body,
        struct s2n_stuffer *outer, struct s2n_stuffer *out) /* NOLINT(bugprone-easily-swappable-parameters) */
{
    struct s2n_stuffer in = { 0 };
    RESULT_GUARD_POSIX(s2n_stuffer_init_written(&in, outer_extensions_body));

    /*
     *= https://www.rfc-editor.org/rfc/rfc9849#section-5.1
     *#     ExtensionType OuterExtensions<2..254>;
     */
    uint8_t types_size = 0;
    RESULT_GUARD(s2n_ech_read_uint8(&in, &types_size, S2N_ERR_BAD_MESSAGE));
    RESULT_ENSURE(types_size >= sizeof(uint16_t), S2N_ERR_BAD_MESSAGE);
    RESULT_ENSURE(types_size % sizeof(uint16_t) == 0, S2N_ERR_BAD_MESSAGE);
    RESULT_ENSURE(s2n_stuffer_data_available(&in) == types_size, S2N_ERR_BAD_MESSAGE);

    uint16_t referenced_types[UINT8_MAX / sizeof(uint16_t)] = { 0 };
    size_t referenced_count = 0;
    while (s2n_stuffer_data_available(&in)) {
        uint16_t referenced_type = 0;
        RESULT_GUARD(s2n_ech_read_uint16(&in, &referenced_type, S2N_ERR_BAD_MESSAGE));

        /*
         *= https://www.rfc-editor.org/rfc/rfc9849#section-5.1
         *# The server MUST abort the connection with an
         *# "illegal_parameter" alert if any of the following are true:
         *#
         *# *  Any referenced extension is missing in ClientHelloOuter.
         *#
         *# *  Any extension is referenced in OuterExtensions more than once.
         */
        for (size_t i = 0; i < referenced_count; i++) {
            RESULT_ENSURE(referenced_types[i] != referenced_type, S2N_ERR_ECH_INVALID_OUTER_EXTENSIONS);
        }
        RESULT_ENSURE_LT(referenced_count, s2n_array_len(referenced_types));
        referenced_types[referenced_count] = referenced_type;
        referenced_count++;

        /*
         *= https://www.rfc-editor.org/rfc/rfc9849#appendix-A
         *# *  If E is "encrypted_client_hello", abort the connection with an
         *#    "illegal_parameter" alert and terminate this procedure.
         */
        RESULT_ENSURE(referenced_type != TLS_EXTENSION_ECH, S2N_ERR_ECH_INVALID_OUTER_EXTENSIONS);

        /* A ClientHelloOuter must not carry ech_outer_extensions, but s2n's
         * extension parser ignores the type, so nothing rejects one. Refuse
         * to reference it, so that it is never copied into ClientHelloInner.
         *
         *= https://www.rfc-editor.org/rfc/rfc9849#section-5.1
         *= type=exception
         *= reason=s2n does not reject a ClientHelloOuter that carries ech_outer_extensions; it only refuses to copy it into ClientHelloInner.
         *# The "ech_outer_extensions" extension can only be included in
         *# EncodedClientHelloInner and MUST NOT appear in either
         *# ClientHelloOuter or ClientHelloInner.
         */
        RESULT_ENSURE(referenced_type != TLS_EXTENSION_ECH_OUTER_EXTENSIONS, S2N_ERR_ECH_INVALID_OUTER_EXTENSIONS);

        /*
         *= https://www.rfc-editor.org/rfc/rfc9849#appendix-A
         *# *  While I is less than N and the I-th extension of
         *#    ClientHelloOuter does not have type E, increment I.
         *#
         *# *  If I is equal to N, abort the connection with an
         *#    "illegal_parameter" alert and terminate this procedure.
         *#
         *# *  Otherwise, the I-th extension of ClientHelloOuter has type E.
         *#    Copy it to the EncodedClientHelloInner and increment I.
         */
        while (true) {
            RESULT_ENSURE(s2n_stuffer_data_available(outer) > 0, S2N_ERR_ECH_INVALID_OUTER_EXTENSIONS);
            uint16_t outer_type = 0;
            struct s2n_blob outer_body = { 0 };
            struct s2n_blob outer_extension = { 0 };
            RESULT_GUARD(s2n_ech_read_extension(outer, &outer_type, &outer_body, &outer_extension,
                    S2N_ERR_BAD_MESSAGE));
            if (outer_type == referenced_type) {
                RESULT_GUARD_POSIX(s2n_stuffer_write(out, &outer_extension));
                break;
            }
        }
    }

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_ech_decompress_extensions(const struct s2n_blob *encoded_inner_extensions,
        const struct s2n_blob *outer_extensions, struct s2n_stuffer *out)
{
    RESULT_ENSURE_REF(encoded_inner_extensions);
    RESULT_ENSURE_REF(outer_extensions);
    RESULT_ENSURE_REF(out);
    /* `out` is allocated here, so an allocated one would be leaked */
    RESULT_ENSURE(out->blob.data == NULL, S2N_ERR_SAFETY);

    /* Each input byte is copied at most once (see
     * s2n_ech_copy_outer_extensions), so the output never exceeds the size of
     * the two inputs. Allocate that once and never grow it. */
    uint32_t max_size = 0;
    RESULT_GUARD_POSIX(s2n_add_overflow(encoded_inner_extensions->size, outer_extensions->size, &max_size));
    /* Built here and moved to `out` only on success */
    DEFER_CLEANUP(struct s2n_stuffer decompressed = { 0 }, s2n_stuffer_free);
    RESULT_GUARD_POSIX(s2n_stuffer_alloc(&decompressed, max_size));

    struct s2n_blob inner_copy = *encoded_inner_extensions;
    struct s2n_stuffer inner = { 0 };
    RESULT_GUARD_POSIX(s2n_stuffer_init_written(&inner, &inner_copy));

    struct s2n_blob outer_copy = *outer_extensions;
    struct s2n_stuffer outer = { 0 };
    RESULT_GUARD_POSIX(s2n_stuffer_init_written(&outer, &outer_copy));

    bool found_outer_extensions = false;
    while (s2n_stuffer_data_available(&inner)) {
        uint16_t type = 0;
        struct s2n_blob body = { 0 };
        struct s2n_blob extension = { 0 };
        RESULT_GUARD(s2n_ech_read_extension(&inner, &type, &body, &extension, S2N_ERR_BAD_MESSAGE));

        if (type != TLS_EXTENSION_ECH_OUTER_EXTENSIONS) {
            RESULT_GUARD_POSIX(s2n_stuffer_write(&decompressed, &extension));
            continue;
        }

        /* 0xfd00 has no s2n extension id, so the usual duplicate extension
         * check does not cover it. Fail the same way it would. */
        RESULT_ENSURE(!found_outer_extensions, S2N_ERR_DUPLICATE_EXTENSION);
        found_outer_extensions = true;

        RESULT_GUARD(s2n_ech_copy_outer_extensions(&body, &outer, &decompressed));
    }

    /*
     *= https://www.rfc-editor.org/rfc/rfc9849#section-5.1
     *# The "ech_outer_extensions" extension can only be included in
     *# EncodedClientHelloInner and MUST NOT appear in either
     *# ClientHelloOuter or ClientHelloInner.
     *
     * This enforces the ClientHelloInner half. Neither loop above can copy
     * ech_outer_extensions to the output. Check it anyway, since the result
     * is about to become ClientHelloInner.
     */
    struct s2n_stuffer result = decompressed;
    while (s2n_stuffer_data_available(&result)) {
        uint16_t type = 0;
        struct s2n_blob body = { 0 };
        RESULT_GUARD(s2n_ech_read_extension(&result, &type, &body, NULL, S2N_ERR_BAD_MESSAGE));
        RESULT_ENSURE(type != TLS_EXTENSION_ECH_OUTER_EXTENSIONS, S2N_ERR_SAFETY);
    }

    *out = decompressed;
    ZERO_TO_DISABLE_DEFER_CLEANUP(decompressed);
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_ech_encoded_inner_decode(const struct s2n_blob *encoded_inner,
        const struct s2n_client_hello *outer, struct s2n_blob *inner_message, struct s2n_blob *inner_raw_message)
{
    RESULT_ENSURE_REF(encoded_inner);
    RESULT_ENSURE_REF(outer);
    RESULT_ENSURE_REF(inner_message);
    RESULT_ENSURE_REF(inner_raw_message);
    /* Both are allocated here, so allocated ones would be leaked */
    RESULT_ENSURE(inner_message->data == NULL, S2N_ERR_SAFETY);
    RESULT_ENSURE(inner_raw_message->data == NULL, S2N_ERR_SAFETY);
    RESULT_ENSURE(outer->session_id.size <= S2N_TLS_SESSION_ID_MAX_LEN, S2N_ERR_SAFETY);

    struct s2n_blob encoded_copy = *encoded_inner;
    struct s2n_stuffer in = { 0 };
    RESULT_GUARD_POSIX(s2n_stuffer_init_written(&in, &encoded_copy));

    /*
     *= https://www.rfc-editor.org/rfc/rfc9849#section-5.1
     *#     struct {
     *#         ClientHello client_hello;
     *#         uint8 zeros[length_of_padding];
     *#     } EncodedClientHelloInner;
     *
     * The ClientHello fields are only split apart here. The ClientHelloInner
     * is validated when it is parsed as a ClientHello.
     */
    struct s2n_blob version_and_random = { 0 };
    RESULT_GUARD(s2n_ech_read_bytes(&in, S2N_TLS_PROTOCOL_VERSION_LEN + S2N_TLS_RANDOM_DATA_LEN,
            &version_and_random, S2N_ERR_BAD_MESSAGE));
    struct s2n_blob session_id = { 0 };
    RESULT_GUARD(s2n_ech_read_uint8_vector(&in, &session_id, S2N_ERR_BAD_MESSAGE));
    RESULT_ENSURE(session_id.size <= S2N_TLS_SESSION_ID_MAX_LEN, S2N_ERR_BAD_MESSAGE);
    struct s2n_blob cipher_suites = { 0 };
    RESULT_GUARD(s2n_ech_read_uint16_vector(&in, &cipher_suites, S2N_ERR_BAD_MESSAGE));
    struct s2n_blob compression_methods = { 0 };
    RESULT_GUARD(s2n_ech_read_uint8_vector(&in, &compression_methods, S2N_ERR_BAD_MESSAGE));
    struct s2n_blob encoded_extensions = { 0 };
    RESULT_GUARD(s2n_ech_read_uint16_vector(&in, &encoded_extensions, S2N_ERR_BAD_MESSAGE));

    /*
     *= https://www.rfc-editor.org/rfc/rfc9849#section-5.1
     *# First, it parses EncodedClientHelloInner, interpreting all
     *# bytes after client_hello as padding.  If any padding byte is non-
     *# zero, the server MUST abort the connection with an
     *# "illegal_parameter" alert.
     */
    while (s2n_stuffer_data_available(&in)) {
        uint8_t padding = 0;
        RESULT_GUARD(s2n_ech_read_uint8(&in, &padding, S2N_ERR_BAD_MESSAGE));
        RESULT_ENSURE(padding == 0, S2N_ERR_ECH_INVALID_CLIENT_HELLO);
    }

    DEFER_CLEANUP(struct s2n_stuffer extensions = { 0 }, s2n_stuffer_free);
    RESULT_GUARD(s2n_ech_decompress_extensions(&encoded_extensions, &outer->extensions.raw, &extensions));
    uint32_t extensions_size = s2n_stuffer_data_available(&extensions);
    RESULT_ENSURE(extensions_size <= UINT16_MAX, S2N_ERR_BAD_MESSAGE);

    /*
     *= https://www.rfc-editor.org/rfc/rfc9849#section-5.1
     *# Next, it makes a copy of the client_hello field and copies the
     *# legacy_session_id field from ClientHelloOuter.
     */
    const struct s2n_blob *outer_session_id = &outer->session_id;

    uint32_t body_size = version_and_random.size
            + sizeof(uint8_t) + outer_session_id->size
            + sizeof(uint16_t) + cipher_suites.size
            + sizeof(uint8_t) + compression_methods.size
            + sizeof(uint16_t) + extensions_size;
    /* The same limit as for a ClientHello received on the wire */
    RESULT_ENSURE(body_size <= S2N_MAXIMUM_HANDSHAKE_MESSAGE_LENGTH, S2N_ERR_BAD_MESSAGE);

    DEFER_CLEANUP(struct s2n_stuffer message = { 0 }, s2n_stuffer_free);
    RESULT_GUARD_POSIX(s2n_stuffer_alloc(&message, TLS_HANDSHAKE_HEADER_LENGTH + body_size));
    RESULT_GUARD_POSIX(s2n_stuffer_write_uint8(&message, TLS_CLIENT_HELLO));
    RESULT_GUARD_POSIX(s2n_stuffer_write_uint24(&message, body_size));
    RESULT_GUARD_POSIX(s2n_stuffer_write(&message, &version_and_random));
    RESULT_GUARD_POSIX(s2n_stuffer_write_uint8(&message, outer_session_id->size));
    RESULT_GUARD_POSIX(s2n_stuffer_write(&message, outer_session_id));
    RESULT_GUARD_POSIX(s2n_stuffer_write_uint16(&message, cipher_suites.size));
    RESULT_GUARD_POSIX(s2n_stuffer_write(&message, &cipher_suites));
    RESULT_GUARD_POSIX(s2n_stuffer_write_uint8(&message, compression_methods.size));
    RESULT_GUARD_POSIX(s2n_stuffer_write(&message, &compression_methods));
    RESULT_GUARD_POSIX(s2n_stuffer_write_uint16(&message, extensions_size));
    RESULT_GUARD_POSIX(s2n_stuffer_copy(&extensions, &message, extensions_size));
    RESULT_ENSURE(s2n_stuffer_space_remaining(&message) == 0, S2N_ERR_SAFETY);

    DEFER_CLEANUP(struct s2n_blob raw_message = { 0 }, s2n_free);
    RESULT_GUARD_POSIX(s2n_alloc(&raw_message, body_size));
    RESULT_CHECKED_MEMCPY(raw_message.data, message.blob.data + TLS_HANDSHAKE_HEADER_LENGTH, body_size);

    *inner_message = message.blob;
    ZERO_TO_DISABLE_DEFER_CLEANUP(message);
    *inner_raw_message = raw_message;
    ZERO_TO_DISABLE_DEFER_CLEANUP(raw_message);
    return S2N_RESULT_OK;
}
