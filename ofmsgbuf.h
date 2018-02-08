/* Copyright (c) 2017 Northbound Networks
 *
 * Written By Paul Zanna (paul@northboundnetworks.com)
 *
 */

#define msgbuf_count_buffered(mbuf) ((mbuf->end - mbuf->start))

struct ofmsgbuf
{
        char * buf;
        int len, start, end;
};

struct ofmsgbuf *msgbuf_new(int bufsize);
int              msgbuf_read(struct ofmsgbuf *mbuf, int sock);
int              msgbuf_read_all(struct ofmsgbuf *mbuf, int sock, int len);
int              msgbuf_write(struct ofmsgbuf *mbuf, int sock, int len);
int              msgbuf_write_all(struct ofmsgbuf *mbuf, int sock, int len);
void             msgbuf_grow(struct ofmsgbuf *mbuf);
void             msgbuf_clear(struct ofmsgbuf *mbuf);
void            *msgbuf_peek(struct ofmsgbuf *mbuf);
int              msgbuf_pull(struct ofmsgbuf *mbuf, char * buf, int count);
void             msgbuf_push(struct ofmsgbuf *mbuf, char * buf, int count);



