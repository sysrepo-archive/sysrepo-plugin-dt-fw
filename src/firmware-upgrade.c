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

#include <syslog.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/stat.h>

#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>
#include <curl/curl.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

#include "sysrepo/plugins.h"
#include "sysrepo/trees.h"

#include "firmware-upgrade.h"

#define XPATH_MAX_LEN 100
#define FWSLOT_MAXLEN 100
#define SSH_PUBLIC_KEYFILE_PATH "/etc/cert/sysrep-plugin-fw.pub"
#define SSH_PRIVATE_KEYFILE_PATH "/etc/cert/sysrepo-plugin-fw.pem"

static const char *module_name = "opencpe-firmware-mgmt";
static const char *firmware_slot_dir = "/tmp";

static int32_t id = 0;
static firmware_job jobs  = { .head = LIST_HEAD_INIT(jobs.head) };
struct firmware_slot slots = { .head = LIST_HEAD_INIT(slots.head) };

void
curl_cleanup()
{
    curl_global_cleanup();
}

void
curl_init()
{
    curl_global_init(CURL_GLOBAL_DEFAULT);
}

static size_t
throw_away(void *ptr, size_t size, size_t nmemb, void *data)
{
    (void)ptr;
    (void)data;
    return (size_t)(size * nmemb);
}

static size_t
firmware_fwrite(void *buffer, size_t size, size_t nmemb, void *stream)
{
    curl_data *data = (curl_data *)stream;
    if(data && !data->stream) {
        data->stream = fopen(data->filename, "wb");
        if(!data->stream)
            return -1;
    }

    data->downloaded = data->downloaded + (size * nmemb);
    int percent = (int)(100 * ((double) data->downloaded / (double) data->filesize));
    if (0 == percent % 10) {
        char str[20];
        sprintf(str, "%d", percent);
    }

    return fwrite(buffer, size, nmemb, data->stream);
}

static CURLcode
sslctx_function(CURL *curl, void *sslctx, void *parm)
{
    X509_STORE *store;
    X509 *cert=NULL;
    BIO *bio;
    char *mypem = NULL;

    curl_data *data = (curl_data *)parm;
    mypem = (char *) data->dw.certificate;

    bio = BIO_new_mem_buf(mypem, -1);

    PEM_read_bio_X509(bio, &cert, 0, NULL);
    if (NULL == cert)
        SRP_LOG_DBG_MSG("PEM_read_bio_X509 failed...\n");

    store=SSL_CTX_get_cert_store((SSL_CTX *) sslctx);

    if (0 == X509_STORE_add_cert(store, cert))
        SRP_LOG_DBG_MSG("error adding certificate\n");

    X509_free(cert);
    BIO_free(bio);

    return CURLE_OK ;
}

static int
curl_get(curl_data data, double *filesize)
{
    CURL *curl;
    CURLcode res;

    curl = curl_easy_init();
    if(!curl) {
        return SR_ERR_INTERNAL;
    }

    if (data.dw.password) {
        char *tmp =strchr(data.dw.address, '/');
        char *start = (tmp + 1);
        if (!tmp)
            return SR_ERR_INTERNAL;
        char *stop = strchr(data.dw.address, '@');
        if (!stop)
            return SR_ERR_INTERNAL;
        int len = stop - start;
        char username[len +1];
        snprintf(username, len, "%s", (start + 1));
        char auth[len + strlen(data.dw.password) + 1];
        snprintf(auth, (len + strlen(data.dw.password) + 2), "%s:%s", username, data.dw.password);
        curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
        curl_easy_setopt(curl, CURLOPT_URL, data.dw.address);
        curl_easy_setopt(curl, CURLOPT_USERPWD, auth);
        if (filesize) {
            curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
            curl_easy_setopt(curl, CURLOPT_FILETIME, 1L);
            curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, throw_away);
            curl_easy_setopt(curl, CURLOPT_HEADER, 0L);
        } else {
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, firmware_fwrite);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &data);
        }
        curl_easy_setopt(curl, CURLOPT_FAILONERROR, true);
        res = curl_easy_perform(curl);

        if(CURLE_OK != res)
            SRP_LOG_DBG_MSG("Curl error\n");
        else if (filesize)
            res = curl_easy_getinfo(curl, CURLINFO_CONTENT_LENGTH_DOWNLOAD, filesize);

        curl_easy_cleanup(curl);
    } else if (data.dw.certificate) {
        curl_easy_setopt(curl, CURLOPT_URL, data.dw.address);
        curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
        curl_easy_setopt(curl, CURLOPT_HEADER, 0L);
        curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1L);
        curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
        curl_easy_setopt(curl, CURLOPT_SSLCERTTYPE,"PEM");
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
        curl_easy_setopt(curl, CURLOPT_SSL_CTX_FUNCTION, *sslctx_function);
        curl_easy_setopt(curl, CURLOPT_SSL_CTX_DATA, &data);
        // 2L -> it has to have the same name in the certificate as is in the URL you operate against.
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
        curl_easy_setopt(curl, CURLOPT_FAILONERROR, true);

        if (filesize) {
            curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
            curl_easy_setopt(curl, CURLOPT_FILETIME, 1L);
            curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, throw_away);
        } else {
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, firmware_fwrite);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &data);
            //curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, firmware_fwrite);
            //curl_easy_setopt(curl, CURLOPT_HEADERDATA, stderr);
        }
        res = curl_easy_perform(curl);

        if(CURLE_OK != res)
            SRP_LOG_DBG_MSG("Curl error\n");
        else if (filesize)
            res = curl_easy_getinfo(curl, CURLINFO_CONTENT_LENGTH_DOWNLOAD, filesize);

        curl_easy_cleanup(curl);
    } else if (data.dw.ssh_key) {
        //Prior to 7.39.0, curl was not computing the public key and it had to be provided manually
        curl_easy_setopt(curl, CURLOPT_URL, data.dw.address);
        curl_easy_setopt(curl, CURLOPT_TRANSFERTEXT, 0);
        curl_easy_setopt(curl, CURLOPT_SSH_AUTH_TYPES, CURLSSH_AUTH_PUBLICKEY);
        curl_easy_setopt(curl, CURLOPT_SSH_PUBLIC_KEYFILE, SSH_PUBLIC_KEYFILE_PATH);
        curl_easy_setopt(curl, CURLOPT_SSH_PRIVATE_KEYFILE, "");
        curl_easy_setopt(curl, CURLOPT_DIRLISTONLY, 1);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, firmware_fwrite);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &data);
        res = curl_easy_perform(curl);

        curl_easy_cleanup(curl);

        if(CURLE_OK != res)
            SRP_LOG_DBG_MSG("Curl error\n");
    }

    if(data.stream)
        fclose(data.stream); /* close the local file */

    return SR_ERR_OK;
}

static int
set_value_str(sr_session_ctx_t *sess, char *val_str, char *set_path)
{
    fprintf(stderr, "setting %s to %s\n", set_path, val_str);
    sr_val_t val = { 0 };

    val.type = SR_STRING_T;
    val.data.string_val = val_str;

    return sr_set_item(sess, set_path, &val, SR_EDIT_DEFAULT);
}

static int
set_value_bool(sr_session_ctx_t *sess, bool val_bool, char *set_path)
{
    fprintf(stderr, "setting %s to %d\n", set_path, val_bool);
    sr_val_t val = { 0 };

    val.type = SR_BOOL_T;
    val.data.bool_val = val_bool;

    return sr_set_item(sess, set_path, &val, SR_EDIT_DEFAULT);
}

/* On firmware-download RPC, update sysrepo running and synchronize it with startup so slots would stay. */
int
firmware_slot_to_sysrepo(sr_session_ctx_t *sess, struct firmware_slot *fw_slot)
{
    int rc = SR_ERR_OK;

    const char *xpath_fmt = "/sys:system-state/firmware-slot[name='%s']/%s";
    char xpath[XPATH_MAX_LEN];

    if (fw_slot->version) {
        snprintf(xpath, XPATH_MAX_LEN, xpath_fmt, fw_slot->name, "version");
        rc = set_value_str(sess, fw_slot->version, xpath);
        if (SR_ERR_OK != rc) {
            goto cleanup;
        }
    }

    if (fw_slot->path) {
        snprintf(xpath, XPATH_MAX_LEN, xpath_fmt, fw_slot->name, "path");
        rc = set_value_str(sess, fw_slot->path, xpath);
        if (SR_ERR_OK != rc) {
            goto cleanup;
        }
    }

    if (fw_slot->active) {
        snprintf(xpath, XPATH_MAX_LEN, xpath_fmt, fw_slot->name, "active");
        rc = set_value_bool(sess, fw_slot->active, xpath);
        if (SR_ERR_OK != rc) {
            goto cleanup;
        }
    }

    rc = sr_commit(sess);
    if (SR_ERR_OK != rc) {
        printf("Error by sr_commit: %s\n", sr_strerror(rc));
        goto cleanup;
    }

    return SR_ERR_OK;

  cleanup:
    fprintf(stderr, "Error by sr_set_item: %s\n", sr_strerror(rc));
    return rc;
}

int firmware_slots_to_sysrepo(struct plugin_ctx *ctx)
{
    int rc = SR_ERR_OK;
    struct firmware_slot *slot;

    list_for_each_entry(slot, &jobs.head, head) {
        firmware_slot_to_sysrepo(ctx->session, slot);
    }

    rc = sr_copy_config(ctx->session, module_name, SR_DS_RUNNING, SR_DS_STARTUP);
    if (SR_ERR_OK != rc) {
        SRP_LOG_DBG_MSG("firmware_slot_to_sysrepo: sr_copy_config_errror");
        goto cleanup;
    }

  cleanup:
    fprintf(stderr, "Error by sr_copy_config %s\n", sr_strerror(rc));
    return rc;
}

int
firmware_commit_cb(const char *xpath, const sr_node_t *input, const size_t input_cnt,
                   sr_node_t **output, size_t *output_cnt, void *private_ctx)
{
    SRP_LOG_DBG_MSG("RPC firmware_commit_cb called");
    bool found = false;
    firmware_job *job, *tmp;

    struct plugin_ctx *ctx = (struct plugin_ctx *) private_ctx;

    if (!ctx) {
        goto cleanup;
    }

    int32_t job_id = input->data.int32_val;

    list_for_each_entry_safe(job, tmp, &jobs.head, head) {
        if (job->id == job_id) {
            found = true;
            break;
        }
    }

    if (!found) {
        goto cleanup;
    }

    execl("/sbin/sysupgrade", "sysupgrade", job->install_target, (char *) NULL);

    /* Active target in firmware slot has to be updated. */
    struct firmware_slot *slot;
    list_for_each_entry(slot, &jobs.head, head) {
        if (!strcmp(job->install_target, slot->path)) {
            slot->active = true;
            break;
        }
    }
    firmware_slots_to_sysrepo(ctx);

    /* No output for RPC. */
    (void) output;
    (void) output_cnt;

    return SR_ERR_OK;
  cleanup:
    return SR_ERR_NOT_FOUND;
}

void
free_job(firmware_job *job) {
    if (!job) return;
    if (job->install_target) free(job->install_target);
    if (job->dw.address) free(job->dw.address);
    if (job->dw.password) free(job->dw.password);
    if (job->dw.certificate) free(job->dw.certificate);
    if (job->dw.ssh_key) free(job->dw.ssh_key);
    if (job->dw.install_target) free(job->dw.install_target);
    free(job);
    job = NULL;
}

void
flush_jobs()
{
    firmware_job *elem, *tmp;

    list_for_each_entry_safe(elem, tmp, &jobs.head, head) {
        free_job(elem);
        list_del(&elem->head);
    }
}

static void
firmware_slot_add(struct firmware_slot *slots, char *slot_name)
{
    char target[FWSLOT_MAXLEN];
    struct firmware_slot *slot;

    slot = calloc(1, sizeof(*slot));
    slot->name = strdup(slot_name);
    sprintf(target, "%s/%s", firmware_slot_dir, slot->name);
    slot->path = strdup(target);
    slot->version = strdup(slot_name);
    slot->active = false;

    list_add(&slot->head, &slots->head);
}

int
firmware_download_cb(const char *xpath, const sr_node_t *input,
                     const size_t input_cnt, sr_node_t **output,
                     size_t *output_cnt, void *private_ctx)
{
    int rc = SR_ERR_OK;
    struct plugin_ctx *ctx = (struct plugin_ctx *) private_ctx;
    firmware_job *new_job = calloc(1, sizeof(firmware_job));

    SRP_LOG_DBG_MSG("RPC firmware_download_cb called");

    // init char data
    new_job->dw.address = NULL;
    new_job->dw.password = NULL;
    new_job->dw.certificate = NULL;
    new_job->dw.ssh_key = NULL;
    new_job->dw.install_target = NULL;


    for (size_t i = 0; i < input_cnt; ++i) {
        sr_node_t *tmp = (sr_node_t *) &input[i];

        if (strcmp(tmp->name, "address") == 0) {
            new_job->dw.address = strdup(tmp->data.string_val);
        } else if (strcmp(tmp->name, "password") == 0) {
            new_job->dw.password = strdup(tmp->first_child->data.string_val);
        } else if (strcmp(tmp->name, "certificate") == 0) {
            new_job->dw.certificate = strdup(tmp->first_child->data.string_val);
        } else if (strcmp(tmp->name, "ssh-key") == 0) {
            new_job->dw.ssh_key = strdup(tmp->first_child->data.string_val);
        } else if (strcmp(tmp->name, "install-target") == 0) {
            firmware_slot_add(ctx->fw_slots, tmp->name);
            new_job->dw.install_target = strdup(tmp->data.string_val);
        } else if (strcmp(tmp->name, "timeframe") == 0) {
            new_job->dw.timeframe = tmp->data.int32_val;
        } else if (strcmp(tmp->name, "retry-count") == 0) {
            new_job->dw.retry_count = tmp->data.uint8_val;
        } else if (strcmp(tmp->name, "retry-interval") == 0) {
            new_job->dw.retry_interval = tmp->data.uint32_val;
        } else if (strcmp(tmp->name, "retry-interval-increment") == 0) {
            new_job->dw.retry_interval_increment = tmp->data.uint8_val;
        }
    }

    curl_data data = {new_job->dw, NULL, 0, 0, NULL};
    double filesize = 0.0;
    rc = curl_get(data, &filesize);
    if (SR_ERR_OK != rc) goto error;

    ++id;
    char str_id[20];
    sprintf(str_id, "%d", id);
    char filename[25];
    sprintf(filename, "%s/%s", firmware_slot_dir, str_id);

    data.filename = strdup(filename);
    new_job->install_target = strdup(filename);
    data.filesize = (int) filesize;
    rc = curl_get(data, NULL);
    if (SR_ERR_OK != rc) goto error;

    rc = sr_new_trees(1, output);
    if (SR_ERR_OK != rc) goto error;
    *output_cnt = 1;

    rc = sr_node_set_name(&(*output)[0], "job-id");
    if (SR_ERR_OK != rc) goto error;
    (*output)[0].type = SR_INT32_T;
    (*output)[0].data.int32_val = id;

    new_job->id = id;

    list_add_tail(&new_job->head, &jobs.head);

    rc = firmware_slots_to_sysrepo(ctx);
    if (SR_ERR_OK != rc) goto error;

    return SR_ERR_OK;

  error:
    free_job(new_job);
    return rc;
}

static int
module_change_cb(sr_session_ctx_t *session, const char *module_name, sr_notif_event_t event, void *private_ctx)
{
    printf("Module %s changed!\n", module_name);
    return SR_ERR_OK;
}

int
sr_plugin_init_cb(sr_session_ctx_t *session, void **private_ctx)
{
    sr_subscription_ctx_t *subscription = NULL;
    int rc = SR_ERR_OK;

    rc = sr_module_change_subscribe(session, "opencpe-firmware-mgmt", module_change_cb, NULL, 0,
                                    SR_SUBSCR_CTX_REUSE, &subscription);
    if (SR_ERR_OK != rc) {
        goto error;
    }

    struct plugin_ctx *ctx = calloc(1, sizeof(*ctx));
    ctx->subscription = subscription;
    ctx->session = session;
    *private_ctx = ctx;

    rc = sr_rpc_subscribe_tree(session, "/opencpe-firmware-mgmt:firmware-commit",
                               firmware_commit_cb, *private_ctx,
                               SR_SUBSCR_CTX_REUSE, &subscription);
    if (SR_ERR_OK != rc) goto error;

    rc = sr_rpc_subscribe_tree(session, "/opencpe-firmware-mgmt:firmware-download",
                               firmware_download_cb, *private_ctx,
                               SR_SUBSCR_CTX_REUSE, &subscription);
    if (SR_ERR_OK != rc) goto error;

    return SR_ERR_OK;

  error:
    SRP_LOG_ERR("plugin initialization failed: %s", sr_strerror(rc));
    sr_unsubscribe(session, subscription);
    return rc;
}

void
sr_plugin_cleanup_cb(sr_session_ctx_t *session, void *private_ctx)
{
    struct plugin_ctx *ctx = (struct plugin_ctx *) private_ctx;
    sr_unsubscribe(session, ctx->subscription);

    flush_jobs();
    SRP_LOG_ERR_MSG("plugin cleanup finished");
}

#ifdef DEBUG
volatile int exit_application = 0;

static void
sigint_handler(int signum)
{
    fprintf(stderr, "Sigint called, exiting...\n");
    exit_application = 1;
}

int
main(int argc, char *argv[])
{
    sr_conn_ctx_t *connection = NULL;
    sr_session_ctx_t *session = NULL;
    int rc = SR_ERR_OK;

    /* connect to sysrepo */
    rc = sr_connect("", SR_CONN_DEFAULT, &connection);
    if (SR_ERR_OK != rc) {
        fprintf(stderr, "Error by sr_connect: %s\n", sr_strerror(rc));
        goto cleanup;
    }

    /* start session */
    rc = sr_session_start(connection, SR_DS_RUNNING, SR_SESS_DEFAULT, &session);
    if (SR_ERR_OK != rc) {
        fprintf(stderr, "Error by sr_session_start: %s\n", sr_strerror(rc));
        goto cleanup;
    }

    void *ptr = NULL;
    sr_plugin_init_cb(session, &ptr);

    /* loop until ctrl-c is pressed / SIGINT is received */
    signal(SIGINT, sigint_handler);
    signal(SIGPIPE, SIG_IGN);
    while (!exit_application) {
        sleep(1000);  /* or do some more useful work... */
    }

  cleanup:
    sr_plugin_cleanup_cb(session, ptr);
}
#endif
