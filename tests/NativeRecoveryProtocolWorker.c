/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "../src/Recovery.Native/Bridge/protocol.h"
#include <fcntl.h>
#include <io.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    struct urc_channel channel;
    const unsigned char request[12] = {0,2,0,0,0,0,0,0,4,0,0,0};
    unsigned char reply[4];
    uint32_t length = 0;
    int status;
    if (setmode(STDIN_FILENO,O_BINARY) < 0 || setmode(STDOUT_FILENO,O_BINARY) < 0) return 90;
    status = urc_init(&channel,stdin,stdout,URC_MAX_PAYLOAD);
    if (status != URC_OK) return status;
    if (argc == 2 && strcmp(argv[1],"--overflow") == 0) channel.next_sequence = UINT64_MAX;
    if (argc == 2 && strcmp(argv[1],"--too-large") == 0) {
        uint64_t sequence;
        return urc_emit(&channel,URC_READ,request,URC_MAX_PAYLOAD+1,&sequence);
    }
    status = urc_exchange(&channel,URC_READ,request,sizeof(request),URC_BYTES,reply,sizeof(reply),&length);
    if (status != URC_OK) return status;
    if (length != sizeof(reply)) return 91;
    status = urc_exchange(&channel,URC_SNAPSHOT,reply,length,URC_ACK,NULL,0,&length);
    if (status != URC_OK) return status;
    return urc_exchange(&channel,URC_DONE,NULL,0,URC_ACK,NULL,0,&length);
}
