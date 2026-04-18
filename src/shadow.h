//
//  shadow.h
//  shadowsocks-libuv
//
//  Created by Cube on 14-9-14.
//  Copyright (c) 2014年 Cube. All rights reserved.
//

#ifndef _SHADOW_H
#define _SHADOW_H

#include <uv.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/rand.h>


#define SS_ERROR    -1
#define KEEP_READ 1

//#define PASS "hourui.me@gmail.com"

// struct
typedef struct
{
    uint8_t ver, cmd, rsv, atyp, body[0];
} socks5_s;

typedef struct
{
    socks5_s * data;
    size_t      len;
} socks5_t;

#define socks5_max_len sizeof(socks5_t) + 255 + 2

//typedef struct {
////  uv_tcp_t * tcp;
////   uint8_t  * ip;
////  uint16_t port;
////  uint8_t  resolved;
//} remote_t;

typedef struct
{
    uint8_t ver, nmethod, method[255];
} handshake_request_t;

typedef struct
{
    uint8_t ver, method;
} handshake_reply_t;

typedef struct
{
    void * data;
    size_t size, step;
} handshake_t;

typedef struct
{

    size_t        keyl;
//    uint8_t    *  key;
    unsigned char *key;
    const EVP_CIPHER     * type;

    struct
    {
        int init;
        EVP_CIPHER_CTX *ctx;
    } encrypt, decrypt;

} cipher_t;

typedef struct
{
    void * data;
    size_t size;
    uv_tcp_t * client;
    uv_tcp_t * remote;
    socks5_t * socks5;
    cipher_t * cipher;
} shadow_t;

typedef struct
{
    char * pass, * method;
    struct
    {
        char * ip;
        unsigned int port;
    } local, remote;
    unsigned int idle_timeout;
} config_t;



/* connection */
//shadow_t * shadow_new     (void);
shadow_t * shadow_new     (const config_t *cf);
void       shadow_free    (shadow_t    *);
void       shadow_free_cb (uv_handle_t *);
void       shadow_timer_cb(uv_timer_t  *, int);
//uv_buf_t   shadow_alloc_cb(uv_handle_t *, size_t);
void       shadow_alloc_cb(uv_handle_t *, size_t,uv_buf_t *);
void     shadow_write_cb(uv_write_t  *, int);
//void   connect_client_cb(uv_stream_t *, int);
//
//
//void          establish_remote_cb(uv_connect_t *, int);
//void    close_establish_client_cb(uv_handle_t *);
//void    close_establish_remote_cb(uv_handle_t *);
//void shutdown_establish_client_cb(uv_shutdown_t *, int);
//void shutdown_establish_remote_cb(uv_shutdown_t *, int);





/* handshake 2nd */
//uv_buf_t handshake_2nd_alloc_cb(uv_handle_t *, size_t);
//void     handshake_2nd_readd_cb(uv_stream_t *, ssize_t, uv_buf_t);
//void     handshake_2nd_write_cb(uv_write_t  *, int);
//void     handshake_2nd_rsolv_cb(uv_getaddrinfo_t *, int, struct addrinfo *);
//int      handshake_2nd         (uv_stream_t *);



/* max domain: byte(255), 2 byte */
// #define handshake_2nd_max_size sizeof(handshake_2nd_head_t) + 255 + 2

/* remote */
//void client_readd_cb(uv_stream_t *, ssize_t, uv_buf_t);

/* remote */
//void remote_read_cb(uv_stream_t *, ssize_t, uv_buf_t);
typedef struct {
  unsigned int idle_timeout;  /* Connection idle timeout in ms. */
  uv_tcp_t tcp_handle;
  uv_loop_t *loop;
} server_ctx;

typedef struct {
  unsigned char rdstate;
  unsigned char wrstate;
  unsigned int idle_timeout;
  struct client_ctx *client;  /* Backlink to owning client context. */
  ssize_t result;
  union {
    uv_handle_t handle;
    uv_stream_t stream;
    uv_tcp_t tcp;
    uv_udp_t udp;
  } handle;
  uv_timer_t timer_handle;  /* For detecting timeouts. */
  uv_write_t write_req;
  /* We only need one of these at a time so make them share memory. */
  union {
    uv_getaddrinfo_t addrinfo_req;
    uv_connect_t connect_req;
    uv_req_t req;
    struct sockaddr_in6 addr6;
    struct sockaddr_in addr4;
    struct sockaddr addr;
    char buf[2048];  /* Scratch space. Used to read data into. */
  } t;
} conn;

#endif /* defined(_SHADOW_H) */
