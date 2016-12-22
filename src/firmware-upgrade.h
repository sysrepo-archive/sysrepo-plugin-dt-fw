#include <inttypes.h>
#include <libubox/list.h>

struct firmware_job
{
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

    struct list_head head;
};

struct sys_platform
{
    char *os_name;
    char *os_release;
    char *os_version;
    char *machine;
    char *firmware_version;
};

struct sys_state
{

    struct platform_
    {
        char *os_name;
        char *os_release;
        char *os_version;
        char *machine;
    } platform;

    struct clock_
    {
        char *current_datetime;
        char *boot_datetime;
    } clock;

    struct firmware_slot_
    {
        char *name;
        char *version;
        bool active;
        char *path;

        struct list_head list;
    } slot;

    struct list_head jobs;   /* list */
};

/* Firmware download input information. */
struct dl_info
{
    char *address;
    union {
        char *password;
        char *certificate;
        char *ssh_key;
    } credentials;

    char *install_target;
    int32_t timeframe;
    uint8_t retry_count;
    uint32_t retry_interval;
    uint8_t retry_interval_increment;
};

struct model
{
    struct list_head *jobs;
    struct sys_platform *platform;
    struct sys_state *state;
};

struct rpc_method {
    char *name;
    int (*method)(const char *xpath, const sr_val_t *input, const size_t input_cnt,
                  sr_val_t **output, size_t *output_cnt, void *private_ctx);
};
