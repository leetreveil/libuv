/* Copyright Joyent, Inc. and other Node contributors. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include "../uv.h"
#include "task.h"
#include <stdio.h>
#include <stdlib.h>


typedef struct {
  uv_req_t req;
  uv_buf_t buf;
} write_req_t;


static int server_closed;
static uv_tcp_t server;


static void after_write(uv_req_t* req, int status);
static void after_read(uv_tcp_t*, ssize_t nread, uv_buf_t buf);
static void on_close(uv_handle_t* peer);
static void on_server_close(uv_handle_t* handle);
static void on_connection(uv_tcp_t*, int status);

#define LEN_OFFSET 0
#define QUERYID_OFFSET 2
unsigned char DNSRsp[] = {0, 43, 0, 0, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0 };
unsigned char qrecord[] = {5, 'e', 'c', 'h', 'o', 's', 3, 's', 'r', 'v', 0, 0, 1, 0, 1};
unsigned char arecord[] = {0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 5, 0xbd, 0, 4, 10, 0, 1, 1 };


static void after_write(uv_req_t* req, int status) {
  write_req_t* wr;

  if (status) {
    uv_err_t err = uv_last_error();
    fprintf(stderr, "uv_write error: %s\n", uv_strerror(err));
    ASSERT(0);
  }

  wr = (write_req_t*) req;

  /* Free the read/write buffer and the request */
  free(wr->buf.base);
  free(wr);
}


static void after_shutdown(uv_req_t* req, int status) {
  uv_close(req->handle, on_close);
  free(req);
}


static void after_read(uv_tcp_t* handle, ssize_t nread, uv_buf_t buf) {
  unsigned char * dnsreq;
  unsigned char * rsp;
  int rsplen;

  write_req_t *wr;
  uv_req_t* req;

  if (nread < 0) {

    if (buf.base) {
      free(buf.base);
    }

    req = (uv_req_t*) malloc(sizeof *req);
    uv_req_init(req, (uv_handle_t*)handle, after_shutdown);
    uv_shutdown(req);

    return;
  }

  if (nread == 0) {
    /* Everything OK, but nothing read. */
    free(buf.base);
    return;
  }

  dnsreq = (unsigned char *)buf.base;

  wr = (write_req_t*) malloc(sizeof *wr);

  uv_req_init(&wr->req, (uv_handle_t*)handle, after_write);

  /* prepare DNS response */
  rsplen = sizeof(DNSRsp) + sizeof(qrecord) + sizeof(arecord);
  wr->buf.base = (char *)malloc(rsplen);
  rsp = (unsigned char *)wr->buf.base;
  memcpy(rsp, DNSRsp, sizeof(DNSRsp));
  memcpy(rsp + sizeof(DNSRsp), qrecord, sizeof(qrecord));
  memcpy(rsp + sizeof(DNSRsp) + sizeof(qrecord), arecord, sizeof(arecord));

  rsp[LEN_OFFSET] = (char) ((rsplen-2) >> 8);
  rsp[LEN_OFFSET+1] = (char)(rsplen - 2);
  rsp[QUERYID_OFFSET] = dnsreq[QUERYID_OFFSET];
  rsp[QUERYID_OFFSET+1] = dnsreq[QUERYID_OFFSET+1];

  free(buf.base);

  wr->buf.len = rsplen;
  if (uv_write(&wr->req, &wr->buf, 1)) {
    FATAL("uv_write failed");
  }
}


static void on_close(uv_handle_t* peer) {
  free(peer);
}


static uv_buf_t echo_alloc(uv_tcp_t* handle, size_t suggested_size) {
  uv_buf_t buf;
  buf.base = (char*) malloc(suggested_size);
  buf.len = suggested_size;
  return buf;
}


static void on_connection(uv_tcp_t* server, int status) {
  uv_tcp_t* handle;
  int r;

  ASSERT(status == 0);

  handle = (uv_tcp_t*) malloc(sizeof *handle);
  ASSERT(handle != NULL);

  uv_tcp_init(handle);

  r = uv_accept(server, handle);
  ASSERT(r == 0);

  r = uv_read_start(handle, echo_alloc, after_read);
  ASSERT(r == 0);
}


static void on_server_close(uv_handle_t* handle) {
  ASSERT(handle == (uv_handle_t*)&server);
}


static int dns_start(int port) {
  struct sockaddr_in addr = uv_ip4_addr("0.0.0.0", port);
  int r;

  r = uv_tcp_init(&server);
  if (r) {
    /* TODO: Error codes */
    fprintf(stderr, "Socket creation error\n");
    return 1;
  }

  r = uv_bind(&server, addr);
  if (r) {
    /* TODO: Error codes */
    fprintf(stderr, "Bind error\n");
    return 1;
  }

  r = uv_listen(&server, 128, on_connection);
  if (r) {
    /* TODO: Error codes */
    fprintf(stderr, "Listen error\n");
    return 1;
  }

  return 0;
}


HELPER_IMPL(dns_server) {
  uv_init();
  if (dns_start(TEST_PORT_2))
    return 1;

  uv_run();
  return 0;
}
