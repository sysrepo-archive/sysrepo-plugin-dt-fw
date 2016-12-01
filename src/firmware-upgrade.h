/*
 * Copyright (C) 2016 Deutsche Telekom AG.
 *
 * Author: Mislav Novakovic <mislav.novakovic@sartura.hr>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *	http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __FIRMWARE_UPGRADE_H__
#define __FIRMWARE_UPGRADE_H__

#include <inttypes.h>
#include <libubox/list.h>

/* Firmware download input information. */
typedef struct download_info_s
{
  char *address;
  char *password;
  char *certificate;
  char *ssh_key;

  char *install_target;
  int32_t timeframe;
  uint8_t retry_count;
  uint32_t retry_interval;
  uint8_t retry_interval_increment;
} download_info;

typedef struct firmware_job_s
{
    struct list_head head;
    int id;
    char *install_target;       /* refers to a slot sys_state.slot.name */
    struct firmware_job_status
    {
        enum
        {
            PLANNED,
            IN_PROGRESS,
            DL_FAILED,
            VERIFICATION_FAILED,
            DONE,
        } status;

        char *status_msg;
        uint8_t progress;
    } status;
    download_info dw;
} firmware_job;

typedef struct sys_platform_t
{
    char *os_name;
    char *os_release;
    char *os_version;
    char *machine;
    char *firmware_version;
} sys_platform;

#endif /* __FIRMWARE_UPGRADE_H__ */
