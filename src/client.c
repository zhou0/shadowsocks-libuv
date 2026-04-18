//
//  local.c
//  shadowsocks-libuv
//
//  Created by Cube on 14-9-15.
//  Copyright (c) 2014年 Cube. All rights reserved.
//
#include "utils.h"
#include "shadow.h"
#include "localser.h"
#include "client.h"
#include "crypt.h"
#include "remote.h"

extern config_t conf;

enum conn_state {
    c_busy, /* Busy; waiting for incoming data or for a write to complete. */
    c_done, /* Done; read incoming data or write finished. */
    c_stop, /* Stopped. */
    c_dead
};

/* Session states. */
enum sess_state {
    s_handshake, /* Wait for client handshake. */
    s_handshake_auth, /* Wait for client authentication data. */
    s_req_start, /* Start waiting for request data. */
    s_req_parse, /* Wait for request data. */
    s_req_lookup, /* Wait for upstream hostname DNS lookup to complete. */
    s_req_connect, /* Wait for uv_tcp_connect() to complete. */
    s_proxy_start, /* Connected. Start piping data. */
    s_proxy, /* Connected. Pipe data back and forth. */
    s_kill, /* Tear down session. */
    s_almost_dead_0, /* Waiting for finalizers to complete. */
    s_almost_dead_1, /* Waiting for finalizers to complete. */
    s_almost_dead_2, /* Waiting for finalizers to complete. */
    s_almost_dead_3, /* Waiting for finalizers to complete. */
    s_almost_dead_4, /* Waiting for finalizers to complete. */
    s_dead /* Dead. Safe to free now. */
};


void
client_read_cb(uv_stream_t * stream, ssize_t nread, const uv_buf_t * buf) {
    pr_info("%s %zd", __FUNCTION__, nread);

    do {
        if (nread <= 0) {
            if (buf->base) free(buf->base);
            break;
        }
        if (nread == 0) return;
        // printf("%s\n", buf.base);
        //        write->data = buf.base = cipher_encrypt(shadow, &buf.len, buf.base, nread);
        shadow_t * shadow = stream->data;
        uv_write_t * write = malloc(sizeof (uv_write_t));
//        uv_buf_t * enc_buf;
//        cipher_encrypt(shadow, nread,buf, enc_buf);
//    write->data = cipher_encrypt(shadow, &buf->len, buf->base, nread);
       uv_buf_t ebuf = cipher_encrypt(shadow, (size_t *)&buf->len, buf->base, nread);
        write->data = ebuf.base;
        if (buf->base) free(buf->base);
        // printf("client: %s\n", buf.base);
        //        if (uv_write(write, (uv_stream_t *)shadow->remote, &buf, 1, remote_write_cb)) break;
        if (uv_write(write, (uv_stream_t *) shadow->remote, &ebuf, 1, remote_write_cb)) break;
        return;
    }    while (0);

    //pr_info("client EOF\n");
    uv_close((uv_handle_t *) stream, client_close_cb);
}

void
client_write_cb(uv_write_t * write, int status) {
    pr_info("%s %zd", __FUNCTION__, (ssize_t)status);
    shadow_t * shadow = (shadow_t *) write->handle->data;


    if (!status) status = uv_read_start((uv_stream_t *) shadow->remote,
            shadow_alloc_cb,
            remote_read_cb);

    free(write->data);
    free(write);

    if (status) uv_close((uv_handle_t *) shadow->client, client_close_cb);
}

void
client_shutdown_cb(uv_shutdown_t * shutdown, int status) {
    shadow_t * shadow = (shadow_t *) shutdown->data;
    // shadow_free(shadow);
    uv_close((uv_handle_t *) shadow->client, shadow_free_cb);
    free(shutdown);
}

void
client_close_cb(uv_handle_t * handle) {
    shadow_t * shadow = (shadow_t *) handle->data;
    uv_read_stop((uv_stream_t *) shadow->remote);

    uv_shutdown_t * shutdown = malloc(sizeof (uv_shutdown_t));
    shutdown->data = shadow;

    if (!uv_shutdown(shutdown, (uv_stream_t *) shadow->remote,
            remote_shutdown_cb)) return;

    uv_close((uv_handle_t *) shadow->remote, shadow_free_cb);
    free(shutdown);
}
