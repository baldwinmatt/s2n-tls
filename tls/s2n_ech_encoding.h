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

#pragma once

#include "stuffer/s2n_stuffer.h"
#include "tls/s2n_client_hello.h"
#include "utils/s2n_blob.h"
#include "utils/s2n_result.h"

/* ECHClientHelloType (RFC 9849, Section 5) */
#define S2N_ECH_CLIENT_HELLO_OUTER 0
#define S2N_ECH_CLIENT_HELLO_INNER 1

/* The payload of an "encrypted_client_hello" extension in a ClientHello
 * (RFC 9849, Section 5).
 *
 * The blobs are not owned: after s2n_ech_client_hello_parse they point into
 * the parsed extension data, which must outlive this struct.
 */
struct s2n_ech_client_hello {
    uint8_t type;
    /* The fields below are set only for the outer variant */
    uint16_t kdf_id;
    uint16_t aead_id;
    uint8_t config_id;
    struct s2n_blob enc;
    struct s2n_blob payload;
};

/* Parses `extension_data`, the body of an "encrypted_client_hello"
 * extension.
 *
 * An unknown ECHClientHelloType fails with S2N_ERR_ECH_INVALID_CLIENT_HELLO,
 * which maps to the "illegal_parameter" alert. Other malformed input fails with
 * S2N_ERR_BAD_MESSAGE.
 */
S2N_RESULT s2n_ech_client_hello_parse(const struct s2n_blob *extension_data, struct s2n_ech_client_hello *ech);

/* Reconstructs ClientHelloOuterAAD (RFC 9849, Section 5.2): the
 * ClientHelloOuter body, without the handshake header, with the ECH payload
 * replaced by the same number of zeros.
 *
 * `payload` is the ECHClientHello payload as s2n_ech_client_hello_parse
 * returns it from the ClientHelloOuter's "encrypted_client_hello" extension,
 * so it points into client_hello->extensions.raw. Anything else fails with
 * S2N_ERR_SAFETY. `aad` must be a zeroed blob: it is allocated here and owned
 * by the caller.
 *
 * The AAD is rebuilt from client_hello->raw_message, so it is only right while
 * raw_message holds the bytes the client sent:
 * - s2n_client_hello_parse_raw erases the 32 random bytes from raw_message in
 *   place, so they are restored here from client_hello->random. If further
 *   in-place erasure is ever added to s2n_client_hello_parse_raw, this must be
 *   updated: s2n_ech_encoding_test asserts the reconstruction is byte-exact.
 * - Processing the ClientHello's extensions also changes raw_message in place:
 *   the pre_shared_key extension decrypts session tickets there. So this must
 *   run before s2n_extension_list_process on this ClientHello, and it fails
 *   with S2N_ERR_SAFETY once any extension has been processed.
 */
S2N_RESULT s2n_ech_build_outer_aad(const struct s2n_client_hello *client_hello,
        const struct s2n_blob *payload, struct s2n_blob *aad);

/* Replaces the "ech_outer_extensions" extension in the extensions of an
 * EncodedClientHelloInner with the extensions of ClientHelloOuter that it
 * references (RFC 9849, Section 5.1 and Appendix A).
 *
 * Both inputs are extension lists without their length prefix. `out` must be
 * a zeroed stuffer: it is allocated here, once, at the largest size the
 * output can reach, and owned by the caller.
 *
 * A reference to an extension that is not in `outer_extensions`, that is out
 * of order or repeated, or that names "encrypted_client_hello" or
 * "ech_outer_extensions" fails with S2N_ERR_ECH_INVALID_OUTER_EXTENSIONS, which
 * maps to the "illegal_parameter" alert. A second "ech_outer_extensions" fails
 * with S2N_ERR_DUPLICATE_EXTENSION, like any other duplicate extension. Other
 * malformed input fails with S2N_ERR_BAD_MESSAGE. On failure `out` is left
 * unchanged.
 */
S2N_RESULT s2n_ech_decompress_extensions(const struct s2n_blob *encoded_inner_extensions,
        const struct s2n_blob *outer_extensions, struct s2n_stuffer *out);

/* Decodes an EncodedClientHelloInner (RFC 9849, Section 5.1) into the
 * ClientHelloInner, using the ClientHelloOuter it arrived in.
 *
 * The legacy_session_id is copied from `outer`, the padding is checked and
 * removed, and "ech_outer_extensions" is decompressed against the extensions
 * of `outer`.
 *
 * Two copies of ClientHelloInner are allocated here and owned by the caller:
 * `inner_message` includes the handshake header and is the form the
 * transcript hashes, and `inner_raw_message` is the body only, the form
 * s2n_client_hello_parse_raw takes. They are separate allocations because
 * s2n_client_hello_parse_raw modifies its input: the transcript needs the
 * random it erases. The server uses `inner_raw_message` as the inner
 * ClientHello's raw_message directly, rather than copying it again through
 * s2n_collect_client_hello. Both must be zeroed blobs.
 *
 * Fails with S2N_ERR_ECH_INVALID_CLIENT_HELLO, which maps to the
 * "illegal_parameter" alert, for non-zero padding; with S2N_ERR_BAD_MESSAGE
 * for other malformed input; and as s2n_ech_decompress_extensions does for a
 * bad "ech_outer_extensions".
 */
S2N_RESULT s2n_ech_encoded_inner_decode(const struct s2n_blob *encoded_inner,
        const struct s2n_client_hello *outer, struct s2n_blob *inner_message, struct s2n_blob *inner_raw_message);
