/**
 * @file firmware-upgrade.c
 * @author Antonio Paunovic <antonio.paunovic@sartura.hr>
 * @brief Plugin for sysrepo datastore for management of firmware on device.
 *
 * @copyright
 * Copyright (C) 2016 Deutsche Telekom AG.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include <syslog.h>
#include <unistd.h>
#include <inttypes.h>
#include <time.h>
#include <sys/utsname.h>
#include <sys/sysinfo.h>

#include "sysrepo.h"
#include "sysrepo/plugins.h"

#include <curl/curl.h>
#include <openssl/ssl.h>

#include "firmware-upgrade.h"

#define XPATH_MAX_LEN 100

struct server_data {
    char *address;
    char *password;
    char *certificate;
    char *ssh_key;
};

struct curl_ctx {
    struct server_data *server;
    const char *path;
    size_t n_filesize;
    size_t n_downloaded;
    /* datastore_t *progress; */
    FILE *stream;
};

static size_t
firmware_download_(void *buffer, size_t size, size_t nmemb, void *stream)
{
    struct curl_ctx *ctx = (struct curl_ctx *) stream;

    if (ctx && !ctx->stream) {
        ctx->stream = fopen(ctx->path, "wb");
        if(!ctx->stream) {
            return -1;
        }
    }

    ctx ->n_downloaded = ctx->n_downloaded + (size * nmemb);
    int percent = (int) (100 * ((double) ctx->n_downloaded / (double) ctx->n_filesize));
    if (0 == percent % 10) {
        char str[4];
        sprintf(str, "%d", percent);
    }

    return fwrite(buffer, size, nmemb, ctx->stream);
}

static CURLcode
firmware_download_ssl(CURL *curl, void *sslctx, void *parm)
{
    /* X509_STORE *store; */
    /* X509 *cert=NULL; */
    /* BIO *bio; */
    /* char *mypem = NULL; */

    /* struct curl_data *data = (struct curl_data *)parm; */
    /* mypem = (char *) data->server->certificate; */

    /* bio = BIO_new_mem_buf(mypem, -1); */

    /* PEM_read_bio_X509(bio, &cert, 0, NULL); */
    /* if (NULL == cert) */
    /*     DEBUG("PEM_read_bio_X509 failed...\n"); */

    /* store=SSL_CTX_get_cert_store((SSL_CTX *) sslctx); */

    /* if (0 == X509_STORE_add_cert(store, cert)) */
    /*     DEBUG("error adding certificate\n"); */

    /* X509_free(cert); */
    /* BIO_free(bio); */

    return CURLE_OK ;
}


static int
firmware_download(struct dl_info *dl_info)
{
    CURL *curl;
    CURLcode rc;
    FILE *fd_data;
    const char *cert_type = "PEM";
    const char *public_keyfile_path = "";
    const char *private_keyfile_path = "";

    curl = curl_easy_init();

    if (!curl) {
        goto cleanup;
    }

    if (dl_info->credentials.password) {
        curl_easy_setopt(curl, CURLOPT_USERPWD, "pass"); /* todo real pass */
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, firmware_download_);

    } else if (dl_info->credentials.certificate) {
        curl_easy_setopt(curl, CURLOPT_SSLCERTTYPE, cert_type);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
        curl_easy_setopt(curl, CURLOPT_SSL_CTX_FUNCTION, firmware_download_ssl);

    } else if (dl_info->credentials.ssh_key) {
        curl_easy_setopt(curl, CURLOPT_TRANSFERTEXT, 0);
        curl_easy_setopt(curl, CURLOPT_SSH_AUTH_TYPES, CURLSSH_AUTH_PUBLICKEY);
        curl_easy_setopt(curl, CURLOPT_SSH_PUBLIC_KEYFILE, public_keyfile_path);
        curl_easy_setopt(curl, CURLOPT_SSH_PRIVATE_KEYFILE, public_keyfile_path);
        curl_easy_setopt(curl, CURLOPT_DIRLISTONLY, 1);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, firmware_download_);
    }

    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
    curl_easy_setopt(curl, CURLOPT_URL, dl_info->address);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, fd_data);

    rc = curl_easy_perform(curl);

  cleanup:
    if (fd_data) {
        fclose(fd_data);
    }
    curl_easy_cleanup(curl);

    return rc;
}

static char *
get_current_datetime()
{
    time_t t = time(NULL);
    struct tm *tm = localtime(&t);
    char s[64];
    strftime(s, sizeof(s), "%c", tm);
    printf("%s\n", s);
    return strdup(s);
}

static char *
get_boot_datetime()
{
    struct sysinfo info;
    char s[64];
    sysinfo(&info);
    sprintf(s, "%02ld:%02ld:%02ld", info.uptime/3600, info.uptime%3600/60, info.uptime%60); 
    return strdup(s);
}

static void
get_platform_info(struct sys_state *sys_state)
{
    struct utsname u;
    uname(&u);
    sys_state->platform.os_name = u.sysname;
    sys_state->platform.os_release = u.release;
    sys_state->platform.os_version = u.version;
    sys_state->platform.machine = u.machine;
}

static void
init_data(struct sys_state *sys_state)
{
    printf("init_data\n");
    sys_state->clock.current_datetime = get_current_datetime();
    sys_state->clock.boot_datetime = get_boot_datetime();
    get_platform_info(sys_state);
}

static int
firmware_commit(int job_id, struct model *ctx)
{
    bool found = false;
    struct firmware_job *job;
    list_for_each_entry(job, ctx->jobs, head) {
        if (job->id == job_id) {
            found = true;
            break;
        }
    }

    if (found) {
        execl("/sbin/sysupgrade", "sysupgrade", job->install_target, (char *) NULL);
    } else {
        return -1;
    }

    return 0;
}

static int
module_change_cb(sr_session_ctx_t *session, const char *module_name, sr_notif_event_t event, void *private_ctx)
{
    SRP_LOG_DBG_MSG("opencpe-firmware-mgmt configuration has changed.");

    return SR_ERR_OK;
}

static char *
xpath_suffix(char *str)
{
    char *ptr = strrchr(str, '/') + 1;
    return strdup(ptr);
}

static int
input_to_dl_info(sr_session_ctx_t *sess, const sr_val_t *input, struct dl_info *info)
{
    int rc = SR_ERR_OK;
    int i = 0;
    char *xpath, *suff;
    sr_val_t in_val;

    info = calloc(1, sizeof(*info));
    info->address = input[i++].data.string_val;

    in_val = input[i++];
    xpath = in_val.xpath;

    suff = xpath_suffix(xpath);
    if        (!strcmp(suff, "password")) {
        info->credentials.password = in_val.data.string_val;
    } else if (!strcmp(suff, "certificate")) {
        info->credentials.certificate = in_val.data.string_val;
    } else if (!strcmp(suff, "ssh-key")) {
        info->credentials.ssh_key = in_val.data.string_val;
    }

    in_val = input[i++];
    info->install_target = in_val.data.string_val;

    in_val = input[i++];
    info->timeframe = in_val.data.int32_val;

    in_val = input[i++];
    info->retry_count= in_val.data.uint8_val;

    in_val = input[i++];
    info->retry_interval= in_val.data.uint32_val;

    in_val = input[i++];
    info->retry_interval_increment = (uint8_t) in_val.data.uint32_val;

    return rc;
}

static int
rpc_firmware_download_cb(const char *xpath, const sr_val_t *input, const size_t input_cnt,
                         sr_val_t **output, size_t *output_cnt, void *private_ctx)
{
    int rc = SR_ERR_OK;
    sr_session_ctx_t *session = (sr_session_ctx_t *)private_ctx;

    SRP_LOG_DBG_MSG("'firmware-download' RPC called.");

    int32_t job_id = 0;
    (*output)[0].type = SR_INT32_T;
    (*output)[0].data.int32_val = job_id;
    *output_cnt = 1;

    return rc;
}

static int
rpc_firmware_commit_cb(const char *xpath, const sr_val_t *input, const size_t input_cnt,
                       sr_val_t **output, size_t *output_cnt, void *private_ctx)
{
    SRP_LOG_DBG_MSG("'firmware-commit' RPC called.");

    int job_id = (int) (input->data.uint32_val);

    return firmware_commit(job_id, (struct model *) private_ctx);
}

static int
rpc_set_bootorder_cb(const char *xpath, const sr_val_t *input, const size_t input_cnt,
                     sr_val_t **output, size_t *output_cnt, void *private_ctx)
{
    int rc = SR_ERR_OK;

    SRP_LOG_DBG_MSG("'set-bootorder' RPC called.");

    rc = sr_new_values(1, output);
    if (SR_ERR_OK != rc) {
        return rc;
    }

    *output_cnt = 1;
    (*output)[0].type = SR_STRING_T;
    (*output)[0].data.string_val = "Board specific";

    return rc;
}

static const size_t n_rpc_method = 3;
static const struct rpc_method rpc[] = {
    {"firmware-download", rpc_firmware_download_cb},
    {"firmware-commit", rpc_firmware_commit_cb},
    {"set-bootorder", rpc_set_bootorder_cb},
};

static int
init_rpc_cb(sr_session_ctx_t *session, sr_subscription_ctx_t *subscription)
{
    int rc = SR_ERR_OK;
    char path[XPATH_MAX_LEN];

    for (int i = 0; i < n_rpc_method; i++) {
        snprintf(path, XPATH_MAX_LEN, "/opencpe-firmware-mgmt:%s", rpc[i].name);
        printf("PATH: %s\n", path);
        rc = sr_rpc_subscribe(session, path, rpc[i].method, NULL,
                              SR_SUBSCR_CTX_REUSE, &subscription);
        if (SR_ERR_OK != rc) {
            break;
        }
    }

    return rc;
}

int
sr_plugin_init_cb(sr_session_ctx_t *session, void **private_ctx)
{
    sr_subscription_ctx_t *subscription = NULL;
    struct model *model;
    int rc = SR_ERR_OK;

    rc = sr_module_change_subscribe(session, "opencpe-firmware-mgmt", module_change_cb, NULL,
                                    0, SR_SUBSCR_DEFAULT, &subscription);
    if (SR_ERR_OK != rc) {
        goto error;
    }

    rc = init_rpc_cb(session, subscription);
    if (SR_ERR_OK != rc) {
        goto error;
    }

    SRP_LOG_DBG_MSG("firmware plugin initialized successfully");

    model = calloc(1, sizeof(*model));

    struct list_head jobs = LIST_HEAD_INIT(jobs);
    /* set subscription as our private context */
    *private_ctx = subscription;

    struct sys_state *sys_state = calloc(1, sizeof(*sys_state));
    init_data(sys_state);
    fprintf(stderr, "current time %s\n" "boot time %s\n",
            sys_state->clock.current_datetime,
            sys_state->clock.boot_datetime);

    return SR_ERR_OK;

  error:
    SRP_LOG_ERR("firmware-commit plugin initialization failed: %s", sr_strerror(rc));
    sr_unsubscribe(session, subscription);
    return rc;
}

void
sr_plugin_cleanup_cb(sr_session_ctx_t *session, void *private_ctx)
{
    /* subscription was set as our private context */
    sr_unsubscribe(session, private_ctx);

    SRP_LOG_DBG_MSG("opencpe-firmware-mgmt plugin cleanup finished.");
}
