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
#include <sys/stat.h>

#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>
#include <curl/curl.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

#include "sysrepo.h"
#include "sysrepo/plugins.h"
#include "sysrepo/trees.h"

#include "firmware-upgrade.h"

static int32_t id = 0;

static firmware_job jobs  = { .head = LIST_HEAD_INIT(jobs.head) };

typedef struct curl_data_t {
    download_info dw;
    const char *filename;
    int filesize;
    int downloaded;
    FILE *stream;
} curl_data;

void curl_cleanup()
{
    curl_global_cleanup();
}

void curl_init()
{
    curl_global_init(CURL_GLOBAL_DEFAULT);
}

static size_t throw_away(void *ptr, size_t size, size_t nmemb, void *data)
{
    (void)ptr;
    (void)data;
    return (size_t)(size * nmemb);
}

static size_t firmware_fwrite(void *buffer, size_t size, size_t nmemb, void *stream)
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
        //ds_set_value(data->progress, str);
    }

    return fwrite(buffer, size, nmemb, data->stream);
}

static CURLcode sslctx_function(CURL *curl, void *sslctx, void *parm)
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

static int curl_get(curl_data data, double *filesize)
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
        curl_easy_setopt(curl, CURLOPT_SSH_PUBLIC_KEYFILE, "/home/mislav/.ssh/cacert.pem");
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

int
firmware_commit_cb(const char *xpath, const sr_node_t *input, const size_t input_cnt, sr_node_t **output, size_t *output_cnt, void *private_ctx)
{
    SRP_LOG_DBG_MSG("RPC firmware_commit_cb called");
    bool found = false;
    firmware_job *job, *tmp;

    int32_t job_id = input->data.int32_val;

    list_for_each_entry_safe(job, tmp, &jobs.head, head) {
        if (job->id == job_id) {
            found = true;
            break;
        }
    }

    if (found) {
        execl("/sbin/sysupgrade", "sysupgrade", job->install_target, (char *) NULL);
    } else {
        return SR_ERR_NOT_FOUND;
    }

    return SR_ERR_OK;
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

int
firmware_download_cb(const char *xpath, const sr_node_t *input, const size_t input_cnt, sr_node_t **output, size_t *output_cnt, void *private_ctx)
{
    int rc = SR_ERR_OK;

    SRP_LOG_DBG_MSG("RPC firmware_download_cb called");
    firmware_job *new_job = calloc(1, sizeof(firmware_job));

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

    const char *firmware_slot = "/tmp";

    ++id;
    char str_id[20];
    sprintf(str_id, "%d", id);
    char filename[25];
    sprintf(filename, "%s/%s", firmware_slot, str_id);

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

    return SR_ERR_OK;
error:
    free_job(new_job);
    return rc;
}

static void
retrieve_current_config(sr_session_ctx_t *session)
{
    return SR_ERR_OK;
}

static int
module_change_cb(sr_session_ctx_t *session, const char *module_name, sr_notif_event_t event, void *private_ctx)
{
    retrieve_current_config(session);
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

    rc = sr_rpc_subscribe_tree(session, "/opencpe-firmware-mgmt:firmware-commit", firmware_commit_cb, "shutdown -h now", SR_SUBSCR_CTX_REUSE, &subscription);
    if (SR_ERR_OK != rc) goto error;

    rc = sr_rpc_subscribe_tree(session, "/opencpe-firmware-mgmt:firmware-download", firmware_download_cb, "shutdown -h now", SR_SUBSCR_CTX_REUSE, &subscription);
    if (SR_ERR_OK != rc) goto error;

    *private_ctx = subscription;

    return SR_ERR_OK;

error:
    SRP_LOG_ERR("plugin initialization failed: %s", sr_strerror(rc));
    sr_unsubscribe(session, subscription);
    return rc;
}

void
sr_plugin_cleanup_cb(sr_session_ctx_t *session, void *private_ctx)
{
    /* subscription was set as our private context */
    sr_unsubscribe(session, private_ctx);

    flush_jobs();
    SRP_LOG_ERR_MSG("plugin cleanup finished");
}
