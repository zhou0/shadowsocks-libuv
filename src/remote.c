//
//  remote.c
//  shadowsocks-libuv
//
//  Created by Cube on 14-9-15.
//  Copyright (c) 2014年 Cube. All rights reserved.
//
#include "utils.h"
#include "shadow.h"
#include "remote.h"
#include "client.h"
#include "crypt.h"

void
remote_connect_cb(uv_connect_t * req, int status)
{
    pr_info("%s %zd", __FUNCTION__, (ssize_t)status);
    shadow_t    * shadow = (shadow_t    *)req->data;
    uv_stream_t * stream = (uv_stream_t *)shadow->client;

    if (!status)
    {

        socks5_s * fake = calloc(1, sizeof(socks5_s) + 6);
        fake->ver  = 5;
        fake->cmd  = 0;
        fake->rsv  = 0;
        fake->atyp = 1;

        uv_buf_t buf;
        buf.len  = sizeof(socks5_s) + 6;
        buf.base = (char *)fake;

        uv_write_t * write = malloc(sizeof(uv_write_t));
        write->data = fake;

        status = uv_write(write, stream, &buf, 1, fakereply_write_cb);
    }

    if (status) uv_close((uv_handle_t *)shadow->remote, remote_close_cb);
    free(req);
}

void
remote_write_cb(uv_write_t * write, int status)
{
    pr_info("%s %zd", __FUNCTION__, (ssize_t)status);
    shadow_t * shadow = (shadow_t *)write->handle->data;

    if (!status) status = uv_read_start((uv_stream_t *)shadow->remote,
                                            shadow_alloc_cb,
                                            remote_read_cb);
    if (write->data) free(write->data);
    if (write) free(write);

    if (status) uv_close((uv_handle_t *)shadow->remote, remote_close_cb);
}

void
remote_read_cb(uv_stream_t * stream, ssize_t nread, const uv_buf_t * buf)
{
    pr_info("%s %zd", __FUNCTION__, nread);

    do
    {
        if (nread <  0) break;
        if (nread == 0) return;
            shadow_t  * shadow = (shadow_t *)stream->data;
    uv_write_t * write = malloc(sizeof(uv_write_t));
 //   uv_buf_t * obuf = malloc(sizeof(uv_buf_t));

 //       write->data = buf->base = cipher_decrypt(shadow, &buf->len, buf->base, nread);
    uv_buf_t dbuf = cipher_decrypt(shadow, (size_t *)&buf->len, buf->base, nread);
        write->data = dbuf.base;
        if (buf->base) free(buf->base);
//        cipher_decrypt(shadow, nread,buf, obuf);
//        dump("CIPHER", buf->base,buf->len);
//       dump("PLAIN",obuf->base,obuf->len);
//        if (uv_write(write, (uv_stream_t *)shadow->client, &buf, 1, shadow_write_cb)) break;
        if (uv_write(write, (uv_stream_t *)shadow->client, &dbuf, 1, shadow_write_cb)) break;
        return;
    }
    while (0);

    printf("remote EOF\n");
    uv_close((uv_handle_t *)stream, remote_close_cb);
}

void
remote_shutdown_cb(uv_shutdown_t * shutdown, int status)
{
    shadow_t * shadow = (shadow_t *)shutdown->data;
    // shadow_free(shadow);
    uv_close((uv_handle_t *)shadow->remote, shadow_free_cb);
    free(shutdown);
}

void
remote_close_cb(uv_handle_t * handle)
{
    shadow_t * shadow = (shadow_t *)handle->data;
    uv_read_stop((uv_stream_t *)shadow->client);

    uv_shutdown_t *
    shutdown = malloc(sizeof(uv_shutdown_t));
    shutdown->data = shadow;

    if (!uv_shutdown(shutdown, (uv_stream_t *)shadow->client,
                     client_shutdown_cb)) return;

    uv_close((uv_handle_t *)shadow->client, shadow_free_cb);
    free(shutdown);
}

void
fakereply_write_cb(uv_write_t * write, int status)
{
    pr_info("%s %zd", __FUNCTION__, (ssize_t)status);
    shadow_t * shadow = write->handle->data;
    if (shadow->data) free(shadow->data);

    shadow->data = NULL;
    shadow->size = 0;

    if (!status) uv_read_start((uv_stream_t *)shadow->client,
                                   shadow_alloc_cb,
                                   client_read_cb);

    free(write->data);
    free(write);

    if (status) uv_close((uv_handle_t *)shadow->client, shadow_free_cb);
}