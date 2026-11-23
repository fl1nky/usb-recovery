/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef USB_RECOVERY_PROTOCOL_H
#define USB_RECOVERY_PROTOCOL_H

#include <stdint.h>
#include <stdio.h>

/* Owned parent/child pipes only. No paths, credentials or recovery state are
 * inferred from this framing layer. Checkpoints are acknowledged by the parent. */
#define URC_HEADER_BYTES 24u
#define URC_MAX_PAYLOAD (1024u * 1024u)

enum urc_message {
    URC_HELLO = 1, URC_READ = 2, URC_BYTES = 3, URC_RECORD = 4,
    URC_STREAM = 5, URC_END_RECORD = 6, URC_ACK = 7, URC_DONE = 8,
    URC_FAIL = 9, URC_CANCEL = 10, URC_SNAPSHOT = 11, URC_OUTPUT = 12
};

enum urc_status {
    URC_OK = 0, URC_INVALID = 1, URC_IO = 2, URC_EOF = 3,
    URC_PROTOCOL = 4, URC_TOO_LARGE = 5, URC_SEQUENCE = 6,
    URC_CANCELLED = 7
};

struct urc_channel {
    FILE *input, *output;
    uint64_t next_sequence;
    uint32_t max_payload;
    int failed, input_started;
};

int urc_init(struct urc_channel *channel, FILE *input, FILE *output,
             uint32_t max_payload);
int urc_emit(struct urc_channel *channel, enum urc_message type,
             const void *payload, uint32_t length, uint64_t *sequence);
int urc_reply(struct urc_channel *channel, enum urc_message expected,
              uint64_t sequence, void *payload, uint32_t capacity,
              uint32_t *length);
int urc_exchange(struct urc_channel *channel, enum urc_message request,
                 const void *data, uint32_t size, enum urc_message expected,
                 void *reply, uint32_t capacity, uint32_t *received);

#endif
