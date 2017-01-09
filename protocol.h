//
// Created by Francesco Laurita on 12/31/16.
//

#ifndef SPEEDTESTSERVER_PROTOCOL_H
#define SPEEDTESTSERVER_PROTOCOL_H


#include <stddef.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <errno.h>
#include <syslog.h>

#define PROTO_VER "2.4"
#define PROTO_BANNER "unofficial_open_source_server"
typedef struct _protocol_config {
    size_t upload_max;
    size_t download_max;
    size_t idle_timeout;
    int max_client_error;
    char *junk_data;
    size_t junk_data_len;
    int backlog;
    int tcp_port;
} protocol_config;

typedef struct _server_context {
    size_t started_at;
    size_t total_client;
    size_t current_connected_client;
    size_t byte_sent;
    size_t byte_received;
    const protocol_config *config;
} server_context;


typedef struct _client {
    char hoststr[NI_MAXHOST];
    char portstr[NI_MAXSERV];
    size_t connected_at;
    size_t idle;
    bool quitting;
    int errors_no;
    struct event *read_event;
    struct event *write_event;
    struct event *timeout_event;
    char *buffer;
    size_t buffer_len;
    size_t buffer_size;
    size_t initial_buffer_size;
    size_t request_download_size;
    bool download_started;
    size_t request_upload_size;
    size_t request_upload_size_missing;
    server_context *srv_ctx;
} client;

size_t now(){
    struct timeval tp;
    gettimeofday(&tp, NULL);
    return (size_t)tp.tv_sec * 1000 + tp.tv_usec / 1000;
}

server_context* server_context_new(const protocol_config *config){
    server_context *ctx = malloc(sizeof(server_context));
    if (ctx == NULL){
        perror("malloc");
        return NULL;
    }
    ctx->config = config;
    ctx->byte_received = 0;
    ctx->byte_sent = 0;
    ctx->current_connected_client = 0;
    ctx->total_client = 0;
    ctx->started_at = now();
    return ctx;

}

void server_context_free(server_context *ctx){
    if (ctx != NULL)
        free(ctx);
}

protocol_config* protocol_config_new(){
    protocol_config *cfg = malloc(sizeof(protocol_config));
    if (cfg == NULL){
        perror("malloc");
        return NULL;
    }

    const char *pseudo_rnd_data = "ABCDEFGH";
    cfg->junk_data_len = 2097152;
    cfg->junk_data = malloc(cfg->junk_data_len);
//    for (size_t i = 0; i != 2097152/8; i += 8){
//        memmove(cfg->junk_data + i, pseudo_rnd_data, 8);
//    }
    memset(cfg->junk_data, 'A', cfg->junk_data_len);
    return cfg;
}

void protocol_config_free(protocol_config *cfg){
    free(cfg->junk_data);
    free(cfg);
}

client* client_new(
        struct event_base *evb,
        int fd,
        server_context *srv_ctx,
        void *read_cb,
        void *write_cb,
        void *timeout_cb
){
    client *c = malloc(sizeof(client));
    if (c == NULL){
        perror("malloc");
        return NULL;
    }
    struct timeval tv;
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    c->idle = 0;
    c->quitting = false;
    c->errors_no = 0;
    c->read_event = event_new(evb, fd, EV_READ|EV_PERSIST, read_cb, c);
    c->write_event = event_new(evb, fd, EV_WRITE|EV_PERSIST, write_cb, c);
    c->timeout_event = event_new(evb, fd, EV_TIMEOUT|EV_PERSIST, timeout_cb, c);
    c->buffer = malloc(1024);
    c->buffer_len = 0;
    c->buffer_size = 1024;
    c->initial_buffer_size = c->buffer_size;
    c->request_download_size = 0;
    c->download_started = false;
    c->request_upload_size = 0;
    c->request_upload_size_missing = 0;
    c->srv_ctx = srv_ctx;
    event_add(c->timeout_event, &tv);
    return c;
}


void client_free(client *c){
    c->srv_ctx->current_connected_client--;
    event_del(c->write_event);
    event_del(c->read_event);
    event_del(c->timeout_event);
    event_free(c->write_event);
    event_free(c->read_event);
    event_free(c->timeout_event);
    free(c->buffer);
    free(c);
}

bool client_get_state(const client *c){
    if (c == NULL)
        return false;
    return !c->quitting && c->errors_no < c->srv_ctx->config->max_client_error;
}

char* parse_command(void *ctx){
    client *c = (client *)ctx;
    char *command = calloc(c->buffer_size, 1);
    // A command should be found between the first c->buffer_len bytes
    char *pch = (char*) memchr(c->buffer, '\n', c->buffer_len);
    if (pch != NULL){
        memmove(command, c->buffer, pch - c->buffer);
        return command;
    }
    free(command);
    return NULL;
}

void error_handler(void *ctx){
    client *c = (client *)ctx;
    c->errors_no++;
    const char *err_str = "ERROR\n";
    memmove(c->buffer, err_str, strlen(err_str));
    c->buffer_len = strlen(err_str);
}

void ping_handler(void *ctx){
    client *c = (client *)ctx;
    char *response = calloc(100, 1);
    snprintf(response, 100, "PONG %zu\n", now());
    memmove(c->buffer, response, strlen(response));
    c->buffer_len = strlen(response);
    free(response);
}

void hi_handler(void *ctx){
    client *c = (client *)ctx;
    char *response = calloc(100, 1);
    snprintf(response, 100, "HELLO %s %s\n", PROTO_VER, PROTO_BANNER);
    memmove(c->buffer, response, strlen(response));
    c->buffer_len = strlen(response);
    free(response);
}

void getip_handler(void *ctx){
    client *c = (client *)ctx;

    char *response = calloc(100, 1);
    snprintf(response, 100, "YOURIP %s\n", c->hoststr);
    memmove(c->buffer, response, strlen(response));
    c->buffer_len = strlen(response);
    free(response);
}

void quit_handler(void *ctx){
    client *c = (client *)ctx;
    c->quitting = true;
}

void download_request_handler(const size_t download, void *ctx){
    client *c = (client *)ctx;
    const char *payload = "DOWNLOAD ";
    if (download == 0 || download > c->srv_ctx->config->download_max || download < strlen(payload)){
        error_handler(ctx);
        return;
    }
    c->request_download_size = download;
    c->download_started = false;
}

void upload_request_handler(const size_t upload, const size_t cmd_size, void *ctx){
    client *c = (client *)ctx;
    if (upload == 0 || upload > c->srv_ctx->config->upload_max || upload <= cmd_size || (upload - cmd_size) == 0){
        error_handler(ctx);
        c->request_upload_size = 0;
        c->request_upload_size_missing = 0;
        return;
    }
    c->request_upload_size = upload;
    c->request_upload_size_missing = c->request_upload_size - cmd_size;
    // XXX Check
    c->buffer = realloc(c->buffer, 8192);
    if (c->buffer != NULL){
        c->buffer_size = 8192;
        c->buffer_len = 0;
    }
    event_del(c->write_event);
}


void upload_complete_handler(void *ctx){
    client *c = (client *)ctx;
    if (c->buffer[c->buffer_len - 1] == '\n'){
//        printf("Upload terminated OK!\n");
    } else {
        printf("Upload terminated KO!\n");
    }
    if (c->buffer_size != c->initial_buffer_size){
        // XXX Check
        c->buffer = realloc(c->buffer, c->initial_buffer_size);
        if (c->buffer != NULL){
            c->buffer_size = c->initial_buffer_size;
            c->buffer_len = 0;
        }
    }
    char *response = calloc(100, 1);
    snprintf(response, 100, "OK %zu %zu\n", c->request_upload_size, now());
    memmove(c->buffer, response, strlen(response));
    c->buffer_len = strlen(response);
    free(response);
    c->request_upload_size = 0;
    event_add(c->write_event, NULL);
}

void download_execute_handler(void *ctx){

    client *c = (client *)ctx;
    const char *payload = "DOWNLOAD ";
    ssize_t result;
    int wfd = event_get_fd(c->write_event);
    if (!c->download_started){
        size_t hdr_len = strlen(payload);
        result = send(wfd, payload, hdr_len, 0);
        if (result == hdr_len){
            c->download_started = true;
            c->request_download_size -= result;
            c->srv_ctx->byte_sent += result;
            return;
        } else {
            if (errno == EAGAIN)
                return;
            else {
                syslog(LOG_ERR, "%s:%s send error on download_execute_handler: %s", c->hoststr, c->portstr, strerror(errno));
                evutil_closesocket(wfd);
                client_free(c);
                return;
            }

        }
    }

    size_t missing = c->request_download_size - 1;

    if (missing == 0){
        result = send(wfd, "\n", 1, 0);
        if (result == 1){
            c->srv_ctx->byte_sent += result;
            c->request_download_size = 0;
            c->download_started = false;
            event_del(c->write_event);
        } else {
            if (errno == EAGAIN)
                return;
            else {
                syslog(LOG_ERR, "%s:%s send error on download_execute_handler: %s", c->hoststr, c->portstr, strerror(errno));
                evutil_closesocket(wfd);
                client_free(c);
                return;
            }

        }
    } else {
        size_t to_send = (missing >= c->srv_ctx->config->junk_data_len) ? c->srv_ctx->config->junk_data_len : missing;
        result = send(wfd, c->srv_ctx->config->junk_data, to_send, 0);
        if (result == to_send){
            c->srv_ctx->byte_sent += result;
            c->request_download_size -= result;
        } else {
            if (errno == EAGAIN)
                return;
            else {
                syslog(LOG_ERR, "%s:%s send error on download_execute_handler: %s", c->hoststr, c->portstr, strerror(errno));
                evutil_closesocket(wfd);
                client_free(c);
                return;
            }

        }
    }

}

#endif //SPEEDTESTSERVER_PROTOCOL_H
