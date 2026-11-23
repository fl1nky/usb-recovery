/* SPDX-License-Identifier: GPL-3.0-or-later
 * Includes the pinned GPL-2.0-or-later TestDisk reader in this translation unit
 * so its existing read_record/calc_percentage code supplies the plans. The
 * original source archive and build patch are kept separately, unchanged.
 */
#include "ntfs_udl.c"
#include "../Bridge/protocol.h"
#include <stdint.h>

#define URC_NTFS_MAX_RECORDS UINT64_C(2000000)
#define URC_NTFS_MAX_RUNS 32768u
#define URC_NTFS_MAX_STRING 16384u

struct urc_plan_buffer { unsigned char data[URC_MAX_PAYLOAD]; uint32_t size; int error; };

static void plan_bytes(struct urc_plan_buffer *b,const void *data,uint32_t size)
{
  if(b->error)return;
  if(size>URC_MAX_PAYLOAD-b->size || (size!=0 && data==NULL)){b->error=1;return;}
  if(size!=0)memcpy(b->data+b->size,data,size);
  b->size+=size;
}
static void plan32(struct urc_plan_buffer *b,uint32_t value)
{
  unsigned char out[4];unsigned i;
  for(i=0;i<4;i++)out[i]=(unsigned char)(value>>(8*i));
  plan_bytes(b,out,4);
}
static void plan64(struct urc_plan_buffer *b,uint64_t value)
{
  unsigned char out[8];unsigned i;
  for(i=0;i<8;i++)out[i]=(unsigned char)(value>>(8*i));
  plan_bytes(b,out,8);
}
static void plan_text(struct urc_plan_buffer *b,const char *text)
{
  size_t size=text==NULL?0:strnlen(text,URC_NTFS_MAX_STRING+1);
  if(size>URC_NTFS_MAX_STRING){b->error=1;return;}
  plan32(b,(uint32_t)size);plan_bytes(b,text,(uint32_t)size);
}
static int send_plan(struct urc_channel *channel,enum urc_message type,struct urc_plan_buffer *b)
{
  uint32_t received;
  if(b->error)return URC_TOO_LARGE;
  return urc_exchange(channel,type,b->data,b->size,URC_ACK,NULL,0,&received);
}

static int emit_file(struct urc_channel *channel,struct ufile *file,unsigned percent,uint32_t record_bytes)
{
  struct urc_plan_buffer *b=calloc(1,sizeof(*b));
  struct td_list_head *item;uint32_t streams=0,index=0;int status;
  if(b==NULL)return URC_IO;
  td_list_for_each(item,&file->data){if(++streams>4096){free(b);return URC_TOO_LARGE;}}
  plan32(b,1);plan64(b,file->inode);plan32(b,le16_to_cpu(file->mft->sequence_number));
  plan32(b,le16_to_cpu(file->mft->flags));plan32(b,percent);plan32(b,streams);
  plan_text(b,file->pref_name);plan_text(b,file->pref_pname);
  status=send_plan(channel,URC_RECORD,b);
  if(status!=URC_OK){free(b);return status;}
  td_list_for_each(item,&file->data){
    const struct data *d=td_list_entry_const(item,struct data,list);uint32_t runs=0,i;
    b->size=0;b->error=0;
    plan64(b,file->inode);plan32(b,index++);
    plan32(b,(d->resident?1u:0u)|(d->compressed?2u:0u)|(d->encrypted?4u:0u));
    plan64(b,d->size_data);plan64(b,d->size_alloc);plan64(b,d->size_init);plan32(b,d->percent);
    plan_text(b,d->name);
    if(d->resident){
      uintptr_t base=(uintptr_t)file->mft,pointer=(uintptr_t)d->data;
      if(pointer<base || pointer-base>record_bytes || d->size_data>record_bytes-(pointer-base)){
        free(b);return URC_PROTOCOL;
      }
      plan32(b,(uint32_t)d->size_data);plan_bytes(b,d->data,(uint32_t)d->size_data);
    }else{
      if(d->runlist!=NULL){
        while(d->runlist[runs].length>0){if(runs==URC_NTFS_MAX_RUNS){free(b);return URC_TOO_LARGE;}runs++;}
      }
      plan32(b,runs);
      for(i=0;i<runs;i++){
        plan64(b,(uint64_t)d->runlist[i].vcn);plan64(b,(uint64_t)d->runlist[i].lcn);
        plan64(b,(uint64_t)d->runlist[i].length);
      }
    }
    status=send_plan(channel,URC_STREAM,b);
    if(status!=URC_OK){free(b);return status;}
  }
  free(b);return URC_OK;
}

/* The caller replaces disk I/O with the bounded parent read bridge. Nothing in
 * this function creates output files. END_RECORD is sent only after all plans
 * of that ordinal have been acknowledged; the parent decides when to commit it. */
int urc_testdisk_ntfs_scan(disk_t *disk,const partition_t *partition,uint64_t start,
                          struct urc_channel *channel)
{
  dir_data_t dir;struct ntfs_dir_struct *state;ntfs_attr *bitmap;
  uint64_t records,ordinal,bitmap_at=UINT64_MAX;
  struct urc_plan_buffer *end=NULL;
  unsigned char bits[8192];s64 bitmap_size=0;int status=URC_OK;
  memset(&dir,0,sizeof(dir));
  if(dir_partition_ntfs_init(disk,partition,&dir,0,0)!=DIR_PART_OK)return URC_IO;
  state=(struct ntfs_dir_struct*)dir.private_dir_data;
  if(state->vol->mft_record_size_bits>16){dir.close(&dir);return URC_TOO_LARGE;}
  records=state->vol->mft_na->initialized_size>>state->vol->mft_record_size_bits;
  if(records>URC_NTFS_MAX_RECORDS || start>records){dir.close(&dir);return URC_TOO_LARGE;}
  /* Profile-1 geometry binds stream run lengths and proves complete traversal.
   * Bootstrap reads precede this frame; no record is emitted before its ACK. */
  end=calloc(1,sizeof(*end));if(end==NULL){dir.close(&dir);return URC_IO;}
  plan64(end,records);plan32(end,state->vol->cluster_size);
  plan32(end,state->vol->mft_record_size);plan32(end,state->vol->sector_size);plan32(end,1);
  status=send_plan(channel,URC_SNAPSHOT,end);free(end);end=NULL;
  if(status!=URC_OK){dir.close(&dir);return status;}
  bitmap=ntfs_attr_open(state->vol->mft_ni,AT_BITMAP,AT_UNNAMED,0);
  if(bitmap==NULL){dir.close(&dir);return URC_IO;}
  if(bitmap->initialized_size<0 || (uint64_t)bitmap->initialized_size<(records+7)/8){status=URC_IO;goto done;}
  end=calloc(1,sizeof(*end));if(end==NULL){status=URC_IO;goto done;}
  for(ordinal=start;ordinal<records;ordinal++){
    uint64_t byte=ordinal/8,block=byte/sizeof(bits)*sizeof(bits);struct ufile *file=NULL;
    unsigned outcome=0;end->size=0;end->error=0;
    if(block!=bitmap_at){
      uint64_t count=(uint64_t)bitmap->initialized_size-block;if(count>sizeof(bits))count=sizeof(bits);
      bitmap_size=ntfs_attr_pread(bitmap,block,count,bits);bitmap_at=block;
      if(bitmap_size!=(s64)count){status=URC_IO;goto done;}
    }
    if(channel->failed!=URC_OK){status=channel->failed;goto done;}
    if((bits[byte-bitmap_at]&(1u<<(ordinal%8)))==0){
      file=read_record(state->vol,ordinal);outcome=1;
      if(channel->failed!=URC_OK){free_file(file);status=channel->failed;goto done;}
      if(file!=NULL){
        unsigned percent=calc_percentage(file,state->vol);outcome=2;
        if(channel->failed!=URC_OK){free_file(file);status=channel->failed;goto done;}
        if(percent>0 && (le16_to_cpu(file->mft->flags)&MFT_RECORD_IN_USE)==0){
          status=emit_file(channel,file,percent,state->vol->mft_record_size);free_file(file);file=NULL;
          if(status!=URC_OK)goto done;
        }
        free_file(file);
      }
    }
    plan64(end,ordinal+1);plan32(end,outcome);
    status=send_plan(channel,URC_END_RECORD,end);if(status!=URC_OK)goto done;
  }
done:
  free(end);ntfs_attr_close(bitmap);dir.close(&dir);return status;
}
