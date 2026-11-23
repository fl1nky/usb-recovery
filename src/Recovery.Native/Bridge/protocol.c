/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "protocol.h"
#include <string.h>

static int fail(struct urc_channel *channel, int code)
{
    if (channel != NULL && channel->failed == URC_OK) channel->failed = code;
    return code;
}

static int valid_type(unsigned int type)
{
    return type >= URC_HELLO && type <= URC_OUTPUT;
}

static void put32(unsigned char *out, uint32_t value)
{
    unsigned int i;
    for (i = 0; i < 4; ++i) out[i] = (unsigned char)(value >> (8u * i));
}

static void put64(unsigned char *out, uint64_t value)
{
    unsigned int i;
    for (i = 0; i < 8; ++i) out[i] = (unsigned char)(value >> (8u * i));
}

static uint32_t get32(const unsigned char *in)
{
    uint32_t value = 0;
    unsigned int i;
    for (i = 0; i < 4; ++i) value |= (uint32_t)in[i] << (8u * i);
    return value;
}

static uint64_t get64(const unsigned char *in)
{
    uint64_t value = 0;
    unsigned int i;
    for (i = 0; i < 8; ++i) value |= (uint64_t)in[i] << (8u * i);
    return value;
}

static int read_exact(struct urc_channel *channel, void *payload, uint32_t size)
{
    unsigned char *bytes = payload;
    uint32_t done = 0;
    while (done < size) {
        size_t count = fread(bytes + done, 1, size - done, channel->input);
        if (count == 0) return fail(channel, ferror(channel->input) ? URC_IO : URC_EOF);
        done += (uint32_t)count;
    }
    return URC_OK;
}

static int write_exact(struct urc_channel *channel, const void *payload, uint32_t size)
{
    const unsigned char *bytes = payload;
    uint32_t done = 0;
    while (done < size) {
        size_t count = fwrite(bytes + done, 1, size - done, channel->output);
        if (count == 0) return fail(channel, URC_IO);
        done += (uint32_t)count;
    }
    return URC_OK;
}

int urc_init(struct urc_channel *channel, FILE *input, FILE *output,
             uint32_t max_payload)
{
    if (channel == NULL) return URC_INVALID;
    memset(channel, 0, sizeof(*channel));
    if (input == NULL || output == NULL || input == output ||
        max_payload == 0 || max_payload > URC_MAX_PAYLOAD) return fail(channel, URC_INVALID);
    channel->input = input;
    channel->output = output;
    channel->next_sequence = 1;
    channel->max_payload = max_payload;
    return URC_OK;
}

int urc_emit(struct urc_channel *channel, enum urc_message type,
             const void *payload, uint32_t length, uint64_t *sequence)
{
    unsigned char header[URC_HEADER_BYTES] = {'U','R','C','1',1,0,0,0};
    if (channel == NULL) return URC_INVALID;
    if (channel->failed != URC_OK) return channel->failed;
    if (channel->input == NULL || channel->output == NULL || !valid_type(type) ||
        sequence == NULL || (length != 0 && payload == NULL)) return fail(channel, URC_INVALID);
    if (length > channel->max_payload) return fail(channel, URC_TOO_LARGE);
    if (channel->next_sequence == 0 || channel->next_sequence == UINT64_MAX)
        return fail(channel, URC_SEQUENCE);
    header[5] = (unsigned char)type;
    put64(header + 8, channel->next_sequence);
    put32(header + 16, length);
    if (write_exact(channel, header, URC_HEADER_BYTES) != URC_OK ||
        write_exact(channel, payload, length) != URC_OK) return channel->failed;
    if (fflush(channel->output) != 0) return fail(channel, URC_IO);
    *sequence = channel->next_sequence++;
    return URC_OK;
}

int urc_reply(struct urc_channel *channel, enum urc_message expected,
              uint64_t sequence, void *payload, uint32_t capacity,
              uint32_t *length)
{
    unsigned char header[URC_HEADER_BYTES];
    uint32_t size;
    if (channel == NULL) return URC_INVALID;
    if (channel->failed != URC_OK) return channel->failed;
    if (!valid_type(expected) || sequence == 0 || length == NULL ||
        (capacity != 0 && payload == NULL)) return fail(channel, URC_INVALID);
    *length = 0;
    if (!channel->input_started) {
        /* .NET Framework Process.StandardInput writes its UTF-8 preamble when
         * its StreamWriter is created, even if the caller uses BaseStream.
         * Accept that exact prefix once at connection start, never in a frame. */
        channel->input_started = 1;
        if (read_exact(channel,header,3) != URC_OK) return channel->failed;
        if (header[0] == 0xef && header[1] == 0xbb && header[2] == 0xbf) {
            if (read_exact(channel,header,URC_HEADER_BYTES) != URC_OK) return channel->failed;
        } else if (read_exact(channel,header+3,URC_HEADER_BYTES-3) != URC_OK) return channel->failed;
    } else if (read_exact(channel,header,URC_HEADER_BYTES) != URC_OK) return channel->failed;
    if (memcmp(header,"URC1",4) != 0 || header[4] != 1 || !valid_type(header[5]) ||
        header[6] != 0 || header[7] != 0 || get32(header + 20) != 0)
        return fail(channel, URC_PROTOCOL);
    if (get64(header + 8) != sequence) return fail(channel, URC_SEQUENCE);
    size = get32(header + 16);
    if (size > channel->max_payload || size > capacity) return fail(channel, URC_TOO_LARGE);
    if (header[5] == URC_CANCEL && size == 0) return fail(channel, URC_CANCELLED);
    if (header[5] != expected) return fail(channel, URC_PROTOCOL);
    if (read_exact(channel, payload, size) != URC_OK) return channel->failed;
    *length = size;
    return URC_OK;
}

int urc_exchange(struct urc_channel *channel, enum urc_message request,
                 const void *data, uint32_t size, enum urc_message expected,
                 void *reply, uint32_t capacity, uint32_t *received)
{
    uint64_t sequence;
    int status = urc_emit(channel,request,data,size,&sequence);
    if (status != URC_OK) return status;
    return urc_reply(channel,expected,sequence,reply,capacity,received);
}
