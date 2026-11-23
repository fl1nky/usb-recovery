/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "config.h"
#include <stddef.h>
#include <stdio.h>
#include <ntfs-3g/types.h>
#include <ntfs-3g/compat.h>
#include <ntfs-3g/layout.h>

/* Build with the same generated configuration as the linked library. A library
 * that silently loses GCC packed attributes must fail before reading a source. */
_Static_assert(sizeof(NTFS_BOOT_SECTOR)==512,"NTFS boot sector must be exactly 512 bytes");
_Static_assert(offsetof(NTFS_BOOT_SECTOR,oem_id)==3,"NTFS OEM signature offset");
_Static_assert(offsetof(NTFS_BOOT_SECTOR,end_of_sector_marker)==510,"NTFS sector marker offset");
_Static_assert(offsetof(MFT_RECORD,flags)==22,"MFT allocation flags offset");
_Static_assert(sizeof(MFT_RECORD_FLAGS)==2,"MFT flags must retain the on-disk width");
int main(void)
{
  puts("PASS NativeNtfsLayout: 5 compile-time checks; packed boot/MFT ABI, not filesystem recovery");
  return 0;
}
