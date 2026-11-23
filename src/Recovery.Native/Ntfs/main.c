/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <errno.h>
#include <fcntl.h>
#include <io.h>
#include <locale.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "types.h"
#include "common.h"
#include "hdaccess.h"
#include "../Bridge/protocol.h"

int urc_testdisk_ntfs_scan(disk_t *,const partition_t *,uint64_t,struct urc_channel *);
static struct urc_channel *active;
static uint64_t source_begin,source_end;

static void put32(unsigned char *out,uint32_t value)
{unsigned i;for(i=0;i<4;i++)out[i]=(unsigned char)(value>>(i*8));}
static void put64(unsigned char *out,uint64_t value)
{unsigned i;for(i=0;i<8;i++)out[i]=(unsigned char)(value>>(i*8));}

static int number(const char *text,uint64_t *value)
{
  const char *p=text;char *end;
  if(text==NULL || *text=='\0')return 0;
  while(*p){if(*p<'0' || *p>'9')return 0;p++;}
  errno=0;*value=strtoull(text,&end,10);return errno==0 && *end=='\0';
}
static int parent_read(disk_t *disk,void *data,unsigned count,uint64_t offset)
{
  unsigned done=0;(void)disk;
  if(active==NULL || offset<source_begin || offset>source_end || count>source_end-offset || count>INT32_MAX){
    if(active!=NULL)active->failed=URC_INVALID;
    errno=EIO;return -1;
  }
  while(done<count){
    unsigned n=count-done;unsigned char request[12];uint32_t received;int status;
    if(n>URC_MAX_PAYLOAD)n=URC_MAX_PAYLOAD;
    put64(request,offset+done);put32(request+8,n);
    status=urc_exchange(active,URC_READ,request,sizeof(request),URC_BYTES,(unsigned char*)data+done,n,&received);
    if(status!=URC_OK || received!=n){active->failed=status==URC_OK?URC_PROTOCOL:status;errno=EIO;return -1;}
    done+=n;
  }
  return (int)count;
}
static int deny_write(disk_t *disk,const void *data,unsigned count,uint64_t offset)
{(void)disk;(void)data;(void)count;(void)offset;if(active!=NULL)active->failed=URC_INVALID;errno=EROFS;return -1;}

int main(int argc,char **argv)
{
  struct stat info;struct urc_channel channel;disk_t *disk;partition_t partition;
  uint64_t offset,length,start,sector;unsigned char hello[40];uint32_t received;int status;
  /* This worker has no legacy CLI dispatch and never enumerates host devices. */
  if(argc!=6 || argv[1][0]=='\0' || strncmp(argv[1],"\\\\",2)==0 ||
     lstat(argv[1],&info)!=0 || !S_ISREG(info.st_mode) || info.st_size<512 ||
     !number(argv[2],&offset) || !number(argv[3],&length) ||
     !number(argv[4],&start) || !number(argv[5],&sector) ||
     offset>(uint64_t)info.st_size || length>(uint64_t)info.st_size-offset || length<512 ||
     (sector!=512 && sector!=1024 && sector!=2048 && sector!=4096) ||
     offset%sector!=0 || length%sector!=0)return URC_INVALID;
  if(setmode(STDIN_FILENO,O_BINARY)<0 || setmode(STDOUT_FILENO,O_BINARY)<0)return URC_IO;
  signal(SIGPIPE,SIG_IGN);setlocale(LC_ALL,"C.UTF-8");
  status=urc_init(&channel,stdin,stdout,URC_MAX_PAYLOAD);if(status!=URC_OK)return status;
  put64(hello,(uint64_t)info.st_size);put64(hello+8,offset);put64(hello+16,length);
  put64(hello+24,start);put32(hello+32,(uint32_t)sector);put32(hello+36,1);
  status=urc_exchange(&channel,URC_HELLO,hello,sizeof(hello),URC_ACK,NULL,0,&received);
  if(status!=URC_OK)return status;
  disk=file_test_availability(argv[1],0,TESTDISK_O_RDONLY);if(disk==NULL)return URC_IO;
  if(disk->disk_size!=(uint64_t)info.st_size || (disk->access_mode&TESTDISK_O_RDWR)!=0){disk->clean(disk);return URC_INVALID;}
  memset(&partition,0,sizeof(partition));partition.part_offset=offset;partition.part_size=length;
  partition.upart_type=UP_NTFS;disk->sector_size=(unsigned)sector;
  active=&channel;source_begin=offset;source_end=offset+length;
  disk->pread=parent_read;disk->pwrite=deny_write;
  status=urc_testdisk_ntfs_scan(disk,&partition,start,&channel);
  disk->clean(disk);active=NULL;
  if(status!=URC_OK)return status;
  return urc_exchange(&channel,URC_DONE,NULL,0,URC_ACK,NULL,0,&received);
}
