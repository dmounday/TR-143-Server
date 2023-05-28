/*----------------------------------------------------------------------*
 * Gatespace
 * Copyright 2006-2015 Gatespace Networks, Inc., All Rights Reserved.
 * Gatespace Networks, Inc. confidential material.
 *----------------------------------------------------------------------*
 * File Name  : wget.h
 * Description:	http get/post implementation
 *----------------------------------------------------------------------*
 * $Revision: 1.18 $
 *
 * $Id: wget.c,v 1.18 2015/09/23 22:23:17 dmounday Exp $
 *----------------------------------------------------------------------*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <signal.h>
#include <ctype.h>
#include <syslog.h>

#ifdef DMALLOC
#include "dmalloc.h"
#endif
#ifdef USE_SSL
#include <openssl/ssl.h>
#endif
#include "utils.h"
#include "event.h"
#include "protocol.h"
#include "www.h"
#include "wget.h"

void cpeLog(int level, const char *fmt, ...);
int dns_lookup(const char *name, int socktype, InAddr *res);
int dns_get_next_ip(const char *name, InAddr *res);

static void do_resolve(void *handle);
#define BUF_SIZE 1024
//#define DEBUG

/*>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>*/
#ifdef  DEBUG
#define mkstr(S) # S
#define setListener(A, B, C) {fprintf(stderr, mkstr(%s %s:%d setListener B fd=%d\n), getticks(), __FILE__, __LINE__, A);\
        setListener( A, B, C);}

#define setListenerType(A, B, C, E) {fprintf(stderr, mkstr(%s %s:%d setListenerType B-E fd=%d\n), getticks(), __FILE__, __LINE__, A);\
        setListenerType( A, B, C, E);}

#define stopListener(A) {fprintf(stderr, "%s %s:%d stopListener fd=%d\n", getticks(), __FILE__, __LINE__, A);\
        stopListener( A );}

static char timestr[40];
static char *getticks() {
	struct timeval now;
	gettimeofday(&now, NULL);
	sprintf(timestr, "%04ld.%06ld", now.tv_sec % 1000, now.tv_usec);
	return timestr;
}
#endif
#ifdef DEBUG
#define DBGPRINT(X) fprintf X
#else
#define DBGPRINT(X)
#endif
#ifdef __MACH__
#include <sys/time.h>
//clock_gettime is not implemented on OSX
#define CLOCK_REALTIME 1
int clock_gettime(int clk_id, struct timespec* t) {
    struct timeval now;
    int rv = gettimeofday(&now, NULL);
    if (rv) return rv;
    t->tv_sec  = now.tv_sec;
    t->tv_nsec = now.tv_usec * 1000;
    return 0;
}
#endif
/*<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<*/

/*----------------------------------------------------------------------*
 * forwards
 *----------------------------------------------------------------------*/
static void timer_connect(void *p);
static void do_connect(void *p);
static void timer_response(void *p);
static void do_response(void *p);
#ifdef USE_SSL
static void do_chk_cert_send_request(void *p, int errorcode);
#endif
static void do_send_request(void *p, int errorcode);
static const char noHostConnectMsg[] =
		"Could not establish connection to host %s(%s):%d";
static const char noHostResolve[] = "Could not resolve host %s";

/*
 * local variables
 */
static char userAgent[256] = "GatespaceUA";
static char lastErrorMsg[256];
static int serverTimeout = 60 * 1000; /* default to 60 seconds */

static void freeHdrs(XtraPostHdr **p) {
	XtraPostHdr *next = *p;
	while (next) {
		XtraPostHdr *temp;
		temp = next->next;
		GS_FREE(next->hdr);
		GS_FREE(next->value);
		GS_FREE(next);
		next = temp;
	}
}

void wget_freeCookies(CookieHdr **p) {
	CookieHdr *next = *p;
	while (next) {
		CookieHdr *temp;
		temp = next->next;
		GS_FREE(next->name);
		GS_FREE(next->value);
		GS_FREE(next);
		next = temp;
	}
}
/*----------------------------------------------------------------------*/
/* Release resources associated with the connection, includes socket	*/
static void freeData(tWgetInternal *wg) {
	if (wg != NULL) {
		if (wg->pc != NULL) {
			proto_FreeCtx(wg->pc);
			wg->pc = NULL;
		}
		freeHdrs(&wg->xtraPostHdrs);
		wget_freeCookies(&wg->cookieHdrs);
		if (wg->hdrs != NULL)
			proto_FreeHttpHdrs(wg->hdrs);
		GS_FREE(wg->rspBuf);
		GS_FREE(wg);
	}
}

typedef enum {
	REPLACE, ADDTOLIST
} eHdrOp;

static int addCookieHdr(CookieHdr **hdrQp, char *cookieName, char *value,
		eHdrOp replaceDups) {
	CookieHdr *xh;
	CookieHdr **p = hdrQp;
	xh = (CookieHdr *) GS_MALLOC(sizeof(struct CookieHdr));
	if (xh) {
		memset(xh, 0, sizeof(struct CookieHdr));
		xh->name = GS_STRDUP(cookieName);
		xh->value = GS_STRDUP(value);
		if (xh->name == NULL || xh->value == NULL) {
			GS_FREE(xh->name);
			GS_FREE(xh->value);
			GS_FREE(xh);
			return 0;
		}
		if (replaceDups == REPLACE) {
			while (*p) {
				CookieHdr *xp = *p;
				if (strcasecmp(xp->name, xh->name) == 0) {
					/* replace header */
					xh->next = xp->next;
					GS_FREE(xp->name);
					GS_FREE(xp->value);
					GS_FREE(xp);
					*p = xh;
					return 1;
				}
				p = &xp->next;
			}
		}
		/* just stick it at beginning of list */
		xh->next = *hdrQp;
		*hdrQp = xh;
		return 1;
	}
	return 0;
}

static int addPostHdr(XtraPostHdr **hdrQp, char *xhdrname, char *value,
		eHdrOp replaceDups) {
	XtraPostHdr *xh;
	XtraPostHdr **p = hdrQp;
	xh = (XtraPostHdr *) GS_MALLOC(sizeof(struct XtraPostHdr));
	if (xh) {
		memset(xh, 0, sizeof(struct XtraPostHdr));
		xh->hdr = GS_STRDUP(xhdrname);
		xh->value = GS_STRDUP(value);
		if (xh->hdr == NULL || xh->value == NULL) {
			GS_FREE(xh->hdr);
			GS_FREE(xh->value);
			GS_FREE(xh);
			return 0;
		}
		if (replaceDups == REPLACE) {
			while (*p) {
				XtraPostHdr *xp = *p;
				if (strcmp(xp->hdr, xh->hdr) == 0) {
					/* replace header */
					xh->next = xp->next;
					GS_FREE(xp->hdr);
					GS_FREE(xp->value);
					GS_FREE(xp);
					*p = xh;
					return 1;
				}
				p = &xp->next;
			}
		}
		/* just stick it at beginning of list */
		xh->next = *hdrQp;
		*hdrQp = xh;
		return 1;
	}
	return 0;
}

static int readChunkSz(tWgetInternal *wg, char *buf) {
	int chksz = 0;
	if (sscanf(buf, "%x", &chksz) == 1)
		return chksz;
	return -1;
}

/*----------------------------------------------------------------------*/
/* Update status in tWgetInternal state data and then call handler */
static void report_status(tWgetInternal *wg, tWgetStatus status,
		const char *msg) {
#ifdef DEBUG
	fprintf(stderr, "report_status(): %d %s\n", status, msg? msg: "");
#endif
	wg->status = status;
	wg->msg = msg;
	wg->cbActive = 1;
	(*wg->cb)(wg);
	wg->cbActive = 0;
	if (wg->keepConnection == eCloseConnection)
		freeData(wg);
	return;
}

/*----------------------------------------------------------------------*
 * returns
 *   0 if ok
 *  -1 if WAN interface is not active
 */
static int send_get_request(tWgetInternal *p, const char *host, int port,
		const char *uri) {
	tProtoCtx *pc = p->pc;
	XtraPostHdr *next;
	char buf[HOSTNAME_SZ + 10];

	p->totBytesTX += proto_SendRequest(pc, "GET", uri);
	clock_gettime(CLOCK_REALTIME, &p->ROMTime);
	if (strchr(host, ':')) {
		/* simple test if host is an IPv6 address string */
		snprintf(buf, sizeof(buf), "[%s]:%d", host, port);
	} else {
		snprintf(buf, sizeof(buf), "%s:%d", host, port);
	}
	p->totBytesTX += proto_SendHeader(pc, "Host", host);
	p->totBytesTX += proto_SendHeader(pc, "User-Agent", userAgent);
	if (p->keepConnection == eCloseConnection)
		p->totBytesTX += proto_SendHeader(pc, "Connection", "close");
	else
		p->totBytesTX += proto_SendHeader(pc, "Connection", "keep-alive");

	next = p->xtraPostHdrs;
	while (next) {
		p->totBytesTX += proto_SendHeader(pc, next->hdr, next->value);
		next = next->next;
	}
	p->totBytesTX += proto_SendEndHeaders(pc);
	p->httpState = eREAD_STATUS;
	return 0;
}
#define CHUNKLTHSZ	6
//static void do_response(void *p);
static void putWriteComplete(void *handle){
	tWgetInternal *p = (tWgetInternal*)handle;
	tProtoCtx *pc = p->pc;
	char	chunklth[CHUNKLTHSZ+1];
	unsigned chunksz;
	char	*c;
	int		n, i;
	if ( p->httpState == eWRITE_HEADERS ){
		clock_gettime(CLOCK_REALTIME, &p->BOMTime);
		p->httpState = eWRITE_CHUNKDATA;
	}
	if ( p->httpState == eWRITE_CHUNKDATA){
		if ( p->bufCnt == 0){
			/* empty buffer -- fill chunk */
			chunksz= p->cpeBufCB(p->handle, p->buf+CHUNKLTHSZ, HTTP_HDR_SIZE);
			p->totBytesTX += chunksz;
			snprintf(chunklth, CHUNKLTHSZ+1, "%04x\r\n", chunksz);
			for (i=0; i<CHUNKLTHSZ; ++i)
				p->buf[i] = chunklth[i];
			/* add cr lf to end of buffer */
			c = p->buf+CHUNKLTHSZ+chunksz;
			*c++ = '\r';
			*c = '\n';
			p->bufCnt = chunksz + CHUNKLTHSZ + CHUNKCRLF;
			n = proto_Writen(pc, p->buf, p->bufCnt);
			if ( n == -1 ){
				;/* need to wait */
			} else if ( n>=0 ){
				p->bindex = n;
				p->bufCnt -= n;
			} else {
				stopListener(p->pc->fd);
				report_status(p, iWgetStatus_HttpStateError, "HTTP write Error");
			}
			if (chunksz==0 && p->bufCnt==0 ) {
				p->bindex =0;
				p->httpState = eWRITE_CHUNKSZ;
			}
		} else {
			/* write remainder of chunk */
			n = proto_Writen(pc, p->buf+p->bindex, p->bufCnt);
			if ( n >= 0 ){
				p->bindex += n;
				p->bufCnt -= n;
				if ( p->bufCnt == 0 ){
					p->bindex = 0;
					p->httpState = eWRITE_CHUNKSZ;
				}
			} else {
				stopListener(p->pc->fd);
				report_status(p, iWgetStatus_HttpStateError, "HTTP write Error");
			}
		}
	} else if (p->httpState == eWRITE_CHUNKSZ){
		/* all that's needed is a ending CRLF */
		p->buf[0] = '\r';
		p->buf[1] = '\n';
		p->bufCnt =2;
		n = proto_Writen(pc, p->buf, p->bufCnt);
		if ( n == -1 ){
			;/* need to wait */
		} else if ( n>=0 ){
			p->bindex +=n;
			p->bufCnt -= n;
			if ( p->bufCnt == 0 ){
				p->httpState = eREAD_STATUS;
				p->bindex =0;
				setListener(pc->fd, do_response, p);
			}
		} else {
			stopListener(p->pc->fd);
			report_status(p, iWgetStatus_HttpStateError, "HTTP write Error");
		}
	} else if (p->httpState == eWRITE_CONTENTDATA){
		p->httpState = eREAD_STATUS;
		setListener(pc->fd, do_response, p);
	} else if (p->httpState == eREAD_STATUS){
		setListener(pc->fd, do_response, p);
	} else {
		stopListener(p->pc->fd);
		report_status(p, iWgetStatus_HttpStateError, "HTTP state error");
	}
}
/*----------------------------------------------------------------------*
 * returns
 *   0 if ok
 *  -1 if WAN interface is not active
 *  arg_keys is a NULL terminated array of (char *)
 *  arg_values is a NULL terminated array of (char *) of same length as arg_keys
 */
static int send_post_request(tWgetInternal *p, tRequest putPost,
		const char *host, int port, const char *uri, const char *data,
		int datalen, const char *content_type) {
	tProtoCtx *pc = p->pc;
	char buf[HOSTNAME_SZ + 10];
	XtraPostHdr *next;
	CookieHdr *cookie;

	p->totBytesTX += proto_SendRequest(pc, putPost == ePostData ? "POST" : "PUT", uri);
	clock_gettime(CLOCK_REALTIME, &p->ROMTime);
	if (strchr(host, ':')) {
		/* simple test if host is an IPv6 address string */
		snprintf(buf, sizeof(buf), "[%s]:%d", host, port);
	} else {
		snprintf(buf, sizeof(buf), "%s:%d", host, port);
	}
	p->totBytesTX += proto_SendHeader(pc, "Host", buf);
	p->totBytesTX += proto_SendHeader(pc, "User-Agent", userAgent);
	if (p->keepConnection == eCloseConnection)
		p->totBytesTX += proto_SendHeader(pc, "Connection", "close");
	else
		p->totBytesTX += proto_SendHeader(pc, "Connection", "keep-alive");
	next = p->xtraPostHdrs;
	while (next) {
		p->totBytesTX += proto_SendHeader(pc, next->hdr, next->value);
		next = next->next;
	}
	cookie = p->cookieHdrs;
	while (cookie) {
		proto_SendCookie(pc, cookie);
		cookie = cookie->next;
	}
	if (content_type)
		p->totBytesTX += proto_SendHeader(pc, "Content-Type", content_type);
	if ( data==NULL && p->cpeBufCB!=NULL){
		/* used chunked encoding and get data from cpeCB function */
		p->totBytesTX += proto_SendHeader(pc, "Transfer-Encoding", "chunked");
		p->totBytesTX += proto_SendEndHeaders(pc);
		p->httpState = eWRITE_HEADERS;

	} else {
		snprintf(buf, sizeof(buf), "%d", datalen);
		p->totBytesTX += proto_SendHeader(pc, "Content-Length", buf);
		p->totBytesTX += proto_SendEndHeaders(pc);
		if (data && datalen) {
			p->totBytesTX += proto_SendRaw(pc, data, datalen);
			p->totBytesTX += datalen;
		}
		p->httpState = eREAD_STATUS;
	}
	/* setup to start processing HTTP response */
	p->buf[0] = '\0';
	p->bindex = 0;
	if (p->hdrs){
		proto_FreeHttpHdrs(p->hdrs);
		p->hdrs = NULL;
	}
	return 0;
}

/*----------------------------------------------------------------------
 * connect timeout
 */
static void timer_connect(void *p) {
	tWgetInternal *data = (tWgetInternal *) p;
	char buf[256];
	InAddr nxtIp;
	stopListener(data->pc->fd);
	/* try next IP if any */
	if (dns_get_next_ip(data->host, &nxtIp)) {
		data->host_addr = nxtIp;
		close(data->pc->fd);
		data->pc->fd = 0;
		do_resolve((void*) data);
		return;
	}
	snprintf(buf, sizeof(buf), "Connection timed out to host %s:%d", data->host,
			data->port);
	report_status(data, iWgetStatus_ConnectionError, buf);
}

/*----------------------------------------------------------------------*/
static void timer_response(void *p) {
	tWgetInternal *data = (tWgetInternal *) p;
	char buf[512];
	stopListener(data->pc->fd);
	snprintf(buf, sizeof(buf), "Host (%s:%d) is not responding, timeout",
			data->host, data->port);
	report_status(data, iWgetStatus_ConnectionError, buf);
}

/*----------------------------------------------------------------------*/
static void do_connect(void *p) {
	tWgetInternal *data = (tWgetInternal *) p;
	int err;
	u_int n;

	stopTimer(timer_connect, data);
	stopListener(data->pc->fd);
	clock_gettime(CLOCK_REALTIME, &data->ORspTime);
	/* check fd status */
	n = sizeof(int);
	if (getsockopt(data->pc->fd, SOL_SOCKET, SO_ERROR, &err, &n) < 0) {
		report_status(data, iWgetStatus_InternalError,
				"internal error: do_connect(): getsockopt failed");

		return;
	}

	if (err != 0) {
		/* connection not established */
		char buf[512];

		snprintf(buf, sizeof(buf),
				"Connection to host %s(%s):%d failed %d (%s)", data->host,
				writeInIPAddr(&data->host_addr), data->port, err,
				strerror(err));
		report_status(data, iWgetStatus_ConnectionError, buf);
		return;
	}
	/* return at this point if function is connect only */
	if (data->request == eConnect) {
		report_status(data, iWgetStatus_Ok, NULL);
		return;
	}

#ifdef USE_SSL
	/* init ssl if proto is https */
	if (strcmp(data->proto, "https") == 0) {
		proto_SetSslCtx(data->pc, do_chk_cert_send_request, data);
	} else {
		do_send_request(data, PROTO_OK);
	}
#else
	do_send_request(data, PROTO_OK);
#endif
}

#ifdef USE_SSL
/*
 * called immediately following a connect to an https server to check
 * the certificate.
 */
/*----------------------------------------------------------------------*/
static void do_chk_cert_send_request(void *p, int errorcode) {
	tWgetInternal *data = (tWgetInternal *) p;
#ifdef DEBUG
	fprintf(stderr, "do_chk_cert_send_request\n");
#endif
	if (errorcode < 0) {
		report_status(data, iWgetStatus_ConnectionError, "Failed to establish SSL connection");
		return;
	}
	if (!proto_CheckCertificate(data->pc, data->host)) {
		report_status(data, iWgetStatus_ConnectionError, "Certificate miss-match");
		return;
	}
	do_send_request(p, errorcode);
	return;
}
#endif
/*
 * readLine(tWgetInternal *wg, char *buffer, int *readLength)
 * return ==0  CRLF sequence has been found. Buf is null terminated string with CRLF stripped.
 * 		 >0  Length of data in buffer, Waiting on more data.
 * 		 -1  EAGAIN or EWOULDBLOCK
 * 		 -2  read error.
 * 		 -3  Not found. Buffer size exceeded.
 */
static int readLine(tWgetInternal *wg, char *buf, int maxlen) {
	int rc;
	char c;
	int len;
	int errnovalue;
	char *ptr = buf;

	len = 0;
	while (len < maxlen) {
		rc = proto_Readn(wg->pc, &c, 1, &errnovalue);
		if (rc == 1) {
			wg->totBytesRX++;
			if (c == '\n') {
				if ( wg->crLastChar ){
					*ptr = '\0'; /* null terminated */
					if (ptr!=buf)
						*(ptr-1) = '\0';
					wg->crLastChar = 0;
					return 0;
				}
			}
			wg->crLastChar = (c=='\r');
			*ptr++ = c;
			len++;
		} else if (rc == -1) {
			if ( len >0 )
				return len;
			else
				//fprintf(stderr, "EOF or EAGIN on readLine %d %d\n", rc, errnovalue);
				return -1;
		} else {
			//fprintf(stderr, "readLine: rc: %d errno: %d\n", rc, errnovalue);
			return -2;
		}
	}
	return -3;
}
/*----------------------------------------------------------------------*/
static void do_send_request(void *p, int errorcode) {
	tWgetInternal *wg = (tWgetInternal *) p;
	int res;
#ifdef DEBUG
	fprintf(stderr, "do_send_request keepConn=%d status=%d\n", wg->keepConnection, wg->status);
#endif
	if (errorcode < 0) {
		report_status(wg, iWgetStatus_ConnectionError,
				"Failed to establish SSL connection");
		return;
	}

	/* send request */
	if (wg->request == eGetData) {
		res = send_get_request(p, wg->host, wg->port, wg->uri);
	} else { /* ePostData or ePutData */
		res = send_post_request(p, wg->request, wg->host, wg->port, wg->uri,
				wg->postdata, wg->datalen, wg->content_type);
	}

	if (res < 0) {
		report_status(wg, iWgetStatus_ConnectionError,
				"Failed to send request on connection");
		return;
	}
	/* wait for response */
	wg->bindex =0;
	setListenerType(wg->pc->fd, putWriteComplete, p, iListener_Write );
	if ( wg->request != ePutData )
		setTimer(timer_response, wg, serverTimeout); /*  */
	return;
}
static void reportNormalStatus(tWgetInternal *wg) {
	if (wg->hdrs->status_code >= 100 && wg->hdrs->status_code < 600) {
		clock_gettime(CLOCK_REALTIME, &wg->EOMTime);
		report_status(wg, iWgetStatus_Ok, NULL);
	} else {
		char buf[512];
		snprintf(buf, sizeof(buf), "Host %s returned error \"%s\"(%d)",
				wg->host, wg->hdrs->message ? wg->hdrs->message : "",
				wg->hdrs->status_code);
		report_status(wg, iWgetStatus_HttpError, buf);
	}
}
/*----------------------------------------------------------------------*/
/*
 * do_response
 */

static void do_response(void *p) {
	CookieHdr *cp;
	tWgetInternal *wg = (tWgetInternal *) p;
	int sts;

	DBGPRINT((stderr, "do_response state=%d %s\n", wg->httpState, wg->buf ));
	stopTimer(timer_response, wg);
	if (wg->pc == NULL) {
		cpeLog(LOG_ERROR, "wget %s", "Internal Error");
		report_status(wg, iWgetStatus_InternalError, "internal error: no protocol descriptor");
		return;
	}
	if (wg->pc->fd <= 0) {
		report_status(wg, iWgetStatus_InternalError, "internal error: no file descriptor");
		return;
	}
	do {
		DBGPRINT((stderr, "do_response read more, state=%d %s\n", wg->httpState, wg->buf ));
		switch (wg->httpState) {
		case eREAD_STATUS:
			sts = readLine(wg, wg->buf + wg->bindex, HTTP_HDR_SIZE-wg->bindex);
			if (sts  == 0) {
				/* found end of line - process status */
				wg->hdrs = proto_NewHttpHdrs();
				if (wg->hdrs == NULL) {
					/* memory exhausted?!? */
					stopListener(wg->pc->fd);
					cpeLog(LOG_ERROR, "wget %s", "Memory exhausted");
					report_status(wg, iWgetStatus_InternalError, "internal error: memory exhausted");
					return;
				}
				if (proto_ParseResponse(wg->hdrs, wg->buf) < 0) {
					stopListener(wg->pc->fd);
					report_status(wg, iWgetStatus_Error, "error: illegal http status response");
					return;
				}
				wg->httpState = eREAD_HEADERS;
				wg->bindex = 0;
				if ( wg->request == eGetData )
					clock_gettime(CLOCK_REALTIME, &wg->BOMTime);
			} else if (sts > 0) { // some data read but hasn't found eol.
				wg->bindex += sts;
			} else if (sts == -2) {
				stopListener(wg->pc->fd);
				report_status(wg, iWgetStatus_Error, "error: status read failure");
				return;
			}
			break;
		case eREAD_HEADERS:
			if ((sts = readLine(wg, wg->buf + wg->bindex, HTTP_HDR_SIZE-wg->bindex)) == 0) {
				/* found end of line - process header */
				if (proto_ParseHdr(wg->hdrs, wg->buf) == 0) {
					/* last line of header */
					cp = wg->hdrs->setCookies;
					while (cp) { /* save new cookies if present*/
						addCookieHdr(&wg->cookieHdrs, cp->name, cp->value,
								REPLACE);
						cp = cp->next;
					}
					if (wg->hdrs->TransferEncoding
							&& !strcasecmp(wg->hdrs->TransferEncoding,	"chunked")) {
						wg->httpState = eREAD_CHUNKSZ;
						wg->bufCnt = 0;
						wg->bufLth = wg->datalen = 0;
						if (wg->cpeGetStatus) {/* call CB function to indicate headers read */
							if (wg->cpeGetStatus(wg->handle, wg) == -1) {
								stopListener(wg->pc->fd);
								report_status(wg, iWgetStatus_CPEGetStatusError, "cpe get http status callback error");
								return; /**/
							}
						}
					} else if (wg->hdrs->content_length > 0) {
						wg->httpState = eREAD_CONTENTDATA;
						if (wg->hdrs->content_length > 0
							&& wg->hdrs->content_length < wg->maxBufferSize){
							if( wg->cpeDLBuf == NULL ){
								/* allocate the response buffer */
								wg->bufCnt = wg->datalen = 0;
								wg->bufLth = wg->hdrs->content_length;
								wg->rspBuf = (char *) GS_MALLOC(wg->bufLth + 1); /* add one for null */
								if (wg->rspBuf == NULL) {
									stopListener(wg->pc->fd);
									report_status(wg, iWgetStatus_InternalError,
											"memory allocation failed");
									return;
								}
							}
							if (wg->cpeGetStatus) { /* call CB function to indicate headers read */
								if (wg->cpeGetStatus(wg->handle, wg) == -1){
									stopListener(wg->pc->fd);
									report_status(wg, iWgetStatus_CPEGetStatusError, "cpe get http status callback error");
									return; /**/
								}
							}
						} else {
							stopListener(wg->pc->fd);
							report_status(wg, iWgetStatus_InternalError,
									"Maximum file size exceeded.");
							return;
						}
					} else {
						reportNormalStatus(wg);
						return;
					}
				}
				wg->bindex = 0;
			} else if (sts > 0) {
				wg->bindex += sts;
			} else if (sts == -2 ) {
				stopListener(wg->pc->fd);
				report_status(wg, iWgetStatus_Error, "error: read failure");
				return;
			}
			break;
		case eREAD_CHUNKSZ:
			if ((sts = readLine(wg, wg->buf + wg->bindex, HTTP_HDR_SIZE-wg->bindex)) == 0) {
				/* found end of line - process chunk size */
				if ((wg->chunksz = readChunkSz(wg, wg->buf)) < 0 ) {
					stopListener(wg->pc->fd);
					// error
					report_status(wg, iWgetStatus_Error, "error: chunk size format error");
					return;
				}
				wg->bindex = 0;
				if (wg->chunksz == 0) {
					// completed reading chunks.
					wg->httpState = eREAD_LASTCRLF; /* read last CRLF */
				} else {
					wg->httpState = eREAD_CHUNKDATA;
					wg->bindex = 0;
					wg->bufLth = wg->chunksz;
					if (wg->datalen + wg->chunksz < wg->maxBufferSize) {
						if ( wg->cpeDLBuf == NULL ){
							/* realloc allocate the response buffer */
							wg->rspBuf = (char *) GS_REALLOC(wg->rspBuf, wg->datalen + wg->chunksz + 1); /* extra for null */
							if (wg->rspBuf == NULL) {
								stopListener(wg->pc->fd);
								report_status(wg, iWgetStatus_InternalError,
										"memory allocation failed");
								return;
							}
						}
					} else {
						stopListener(wg->pc->fd);
						report_status(wg, iWgetStatus_InternalError,
								"Maximum file size exceeded.");
						return;
					}
				}
			} else if (sts > 0) {
				wg->bindex += sts;
			} else if (sts == -2 ) {
				stopListener(wg->pc->fd);
				report_status(wg, iWgetStatus_Error, "error: read failure");
				return;
			}
			break;
		case eREAD_CHUNKDATA:
			if (wg->cpeBufCB) {
				int lth = (wg->cpeDLBufLth < wg->bufLth ?	wg->cpeDLBufLth : wg->bufLth);
				if ((sts = proto_Readn(wg->pc, wg->cpeDLBuf, lth, NULL)) > 0) {
					wg->datalen += sts;
					wg->bufLth -= sts; /* bufLth is remaining chunksz */
					wg->totBytesRX += sts;
					if (wg->cpeBufCB(wg->handle, wg->cpeDLBuf, sts) == -1) {
						stopListener(wg->pc->fd);
						report_status(wg, iWgetStatus_CPEBufError, "cpe buffer callback error");
						return; /**/
					}
					if (wg->bufLth == 0) {
						// chunk data read.
						wg->httpState = eREAD_CHUNKCRLF;
						wg->bindex = 0;
					}
				}
			} else if ((sts = proto_Readn(wg->pc, wg->rspBuf + wg->datalen, wg->bufLth, NULL)) > 0) {
				wg->bufLth -= sts;
				wg->datalen += sts;
				wg->totBytesRX += sts;
				if (wg->bufLth == 0) {
					// chunk data read.
					*(wg->rspBuf + wg->datalen) = '\0';
					wg->httpState = eREAD_CHUNKCRLF;
					wg->bindex = 0;
				}
			}
			if (sts == -2 || sts == 0) {
				/* read error */
				stopListener(wg->pc->fd);
				report_status(wg, iWgetStatus_Error, "error: chunk data read failure");
				return;
			}
			break;
		case eREAD_CHUNKCRLF:
			//if ((sts = readLine(wg, wg->buf+wg->bindex, HTTP_HDR_SIZE-wg->bindex)) == 0) {
			sts = proto_Readn(wg->pc, wg->buf+wg->bindex, 2-wg->bindex, NULL);

			if ( sts >0 ) {
				wg->bindex += sts;
				if (wg->bindex == 2){
					if ( wg->buf[0] == '\r' && wg->buf[1]=='\n'){
						wg->httpState = eREAD_CHUNKSZ;
						wg->bindex = 0;
					} else {
						stopListener(wg->pc->fd);
						report_status(wg, iWgetStatus_Error, "error: chunk ending CRLF incorrect");
						return;
					}
				} else if (wg->bindex>2){
					stopListener(wg->pc->fd);
					report_status(wg, iWgetStatus_Error, "error: chunk ending CRLF incorrect, buf index error");
					return;
				}
			} else if (sts == -2 ) {
				stopListener(wg->pc->fd);
				report_status(wg, iWgetStatus_Error, "error: read failure");
				return;
			}
			break;
		case eREAD_LASTCRLF:
			if ((sts = readLine(wg, wg->buf+wg->bindex, HTTP_HDR_SIZE-wg->bindex)) == 0) {
				stopListener(wg->pc->fd);
				reportNormalStatus(wg);
				return;
			}
			break;
		case eREAD_CONTENTDATA:
			if (wg->cpeBufCB) {
				// use cpe buffer
				if ((sts = proto_Readn(wg->pc, wg->cpeDLBuf+wg->bufCnt, wg->cpeDLBufLth-wg->bufCnt, NULL)) > 0) {
					wg->bufCnt += sts;
					wg->datalen += sts;
					wg->totBytesRX += sts;
					if (wg->cpeBufCB(wg->handle, wg->cpeDLBuf, wg->bufCnt)	== -1) {
						stopListener(wg->pc->fd);
						report_status(wg, iWgetStatus_CPEBufError,
								"cpe buffer callback error");
						return; /**/
					}
					wg->bufCnt = 0;
					if (wg->datalen >= wg->hdrs->content_length) {
						reportNormalStatus(wg);
						return;
					}
				}
			} else {
				if ((sts = proto_Readn(wg->pc, wg->rspBuf+wg->datalen, wg->bufLth, NULL)) > 0) {
					wg->datalen += sts;
					wg->bufLth -= sts;
					wg->totBytesRX += sts;
					if (wg->datalen >= wg->hdrs->content_length) {
						wg->rspBuf[wg->datalen] = '\0'; // add NULL after last byte.
						stopListener(wg->pc->fd);
						reportNormalStatus(wg);
						return;
					}
				}
			}
			if (sts == -2 || sts == 0) {
				/* read error */
				stopListener(wg->pc->fd);
				report_status(wg, iWgetStatus_Error, "error: content read failure");
				return;
			}
			break;
		default:
			stopListener(wg->pc->fd);
			report_status(wg, iWgetStatus_InternalError,
					"http read state error.");
			return;
		}
	} while (sts != -1);  /* EAGAIN */
	setTimer(timer_response, wg, serverTimeout); /*  */
	return;
}
/*----------------------------------------------------------------------*
 * returns
 *  0   if ok  (fd contains descriptor for connection)
 *  -1  if socket couldn't be created
 *  -2  if connection function could not be started.
 *
 * sock_fd will hold the socket.
 * The caller of wget_Establishconnection must wait until write is possible
 * i.e. setListenerType(sockfd, ..., iListener_Write)
 * this to avoid blocking.
 */
int wget_EstablishConnection(tWgetInternal *w, int *sock_fd) {
	int fd;
	SockAddrStorage sa;
	struct sockaddr_in *sp = (struct sockaddr_in *) &sa;
	long flags;
	int res;

	memset(sp, 0, sizeof(sa));

	SET_SockADDR(sp, htons(w->port), &w->host_addr);

	if ((fd = socket(sp->sin_family, SOCK_STREAM, 0)) < 0) {
		return -1;
	}
	if ( w->local_addr.inFamily!=0 ){
		/* bind to local address */
		SockAddrStorage addr;
		struct sockaddr_in *la = (struct sockaddr_in *)&addr;
		memset(la, 0, sizeof(addr));
		SET_SockADDR(la, 0, &w->local_addr);
		res = bind(fd, (struct sockaddr*)la, SockADDRSZ(la));
		if ( res < 0){
			return -1;
		}
	}
	/* set non-blocking */
	flags = (long) fcntl(fd, F_GETFL);
	flags |= O_NONBLOCK;
	res = fcntl(fd, F_SETFL, flags);

	errno = 0;
	if (connect(fd, (struct sockaddr*) sp, SockADDRSZ(sp)) < 0) {
		if (errno != EINPROGRESS) {
			/* connect failed */
			close(fd);
			return -2;
		}
	}

	*sock_fd = fd;
	return 0;
}
/*----------------------------------------------------------------------*/
static void do_resolve(void *handle) {
	tWgetInternal *wg = handle;
	int res, fd;
	char buf[512];

	stopTimer(timer_connect, wg);
	/* if callback does not exist, this is a non-op */
	stopCallback(&(wg->host_addr), do_resolve, wg);

	if (wg->host_addr.inFamily == 0) {
		snprintf(buf, sizeof(buf), noHostResolve, wg->host);
		report_status(wg, iWgetStatus_ConnectionError, buf);
	} else if ((res = wget_EstablishConnection(wg, &fd)) < 0) {
		if (res == -1) {
			report_status(wg, iWgetStatus_InternalError,
					"Socket creation error");
		} else {
			snprintf(buf, sizeof(buf), noHostConnectMsg, wg->host,
					writeInIPAddr(&wg->host_addr), wg->port);
			report_status(wg, iWgetStatus_ConnectionError, buf);
		}
	} else {
		clock_gettime(CLOCK_REALTIME, &wg->OReqTime);
		wg->pc = proto_NewCtx(fd);
		setTimer(timer_connect, wg, serverTimeout); /* response timeout is 60 sec */
		setListenerType(fd, do_connect, wg, iListener_Write);
	}
}

/*
 * Connect to the specified url
 * Returns: NULL  failed allocate memory or immediate connection error.
 * 			     Call wget_LastErrorMsg() to retrieve last error msg.
 *         pointer to Connection descriptor tWgetInternal.
 */
tWgetInternal *wget_Connect(const char *url, InAddr *local_addr, EventHandler callback,
		void *handle, unsigned long maxBufferSize) {
	tWgetInternal *wg;
	int port;

#ifdef DEBUG
	cpeLog(LOG_DEBUG, "wget_Connect(\"%s\", ...)", url);
#endif
	if ((wg = (tWgetInternal*) GS_MALLOC(sizeof(tWgetInternal))) == NULL)
		return NULL;
	memset(wg, 0, sizeof(tWgetInternal));
	lastErrorMsg[0] = '\0';
	wg->request = eConnect;
	wg->keepConnection = eKeepConnectionOpen;
	wg->maxBufferSize = maxBufferSize;
	if (www_ParseUrl(url, wg->proto, wg->host, &port, wg->uri) < 0) {
		wg->status = -5;
		return wg;
	}

	if (port == 0) {
		if (strcmp(wg->proto, "http") == 0) {
			port = 80;
#ifdef USE_SSL
		} else if (strcmp(wg->proto, "https") == 0) {
			port = 443;
#endif
		} else {
			cpeLog(LOG_ERROR, "unsupported protocol in url \"%s\"", wg->proto);
			port = 80; /* guess http and port 80 */
		}
	}

	wg->pc = NULL;
	wg->cb = callback;
	wg->handle = handle;
	if ( local_addr )
		wg->local_addr = *local_addr;
	wg->port = port;
	if (strlen(wg->uri) == 0)
		strcpy(wg->uri, "/");

	if (dns_lookup(wg->host, SOCK_STREAM, &wg->host_addr)) {
		/* immediate return requires special handling. */
		int res;
		int fd;
		if (wg->host_addr.inFamily == 0) {
			snprintf(lastErrorMsg, sizeof(lastErrorMsg), noHostResolve, 	wg->host);
			freeData(wg);
			wg = NULL;
		} else if ((res = wget_EstablishConnection( wg, &fd)) < 0) {
			if (res == -1)
				strncpy(lastErrorMsg, "Socket creation error",
						sizeof(lastErrorMsg));
			else
				snprintf(lastErrorMsg, sizeof(lastErrorMsg), noHostConnectMsg,
						wg->host, writeInIPAddr(&wg->host_addr), wg->port);
			freeData(wg);
			wg = NULL;
		} else { /* connect started */
			clock_gettime(CLOCK_REALTIME, &wg->OReqTime);
			wg->pc = proto_NewCtx(fd);
			setTimer(timer_connect, wg, serverTimeout); /* response timeout is 60 sec */
			setListenerType(fd, do_connect, wg, iListener_Write);
		}
	} else {
		setTimer(timer_connect, wg, serverTimeout); /* response timeout is 60 sec */
		setCallback(&(wg->host_addr), do_resolve, wg);
	}

	return wg;
}

int wget_GetData(tWgetInternal *wg, EventHandler callback, void *handle) {
	wg->request = eGetData;
	wg->handle = handle;
	wg->cb = callback;
	if (wg->hdrs) {
		wg->hdrs->status_code = 0; /* reset status_code */
		wg->hdrs->content_length = 0;
	}

#ifdef USE_SSL
	/* init ssl if proto is https */
	if ((strcmp(wg->proto, "https") == 0) && wg->pc->ssl == NULL) {
		proto_SetSslCtx(wg->pc, do_chk_cert_send_request, wg);
	} else {
		do_send_request(wg, PROTO_OK);
	}
#else
	do_send_request(wg, PROTO_OK);
#endif
	return 0;
}

int wget_PostData(tWgetInternal *wg, char *postdata, int datalen,
		const char *content_type, EventHandler callback, void *handle) {
	wg->request = ePostData;
	wg->content_type = content_type;
	wg->postdata = postdata;
	wg->datalen = datalen;
	wg->handle = handle;
	wg->cb = callback;
	if (wg->hdrs) {
		wg->hdrs->status_code = 0; /* reset status_code */
		wg->hdrs->content_length = 0;
	}

#ifdef USE_SSL
	/* init ssl if proto is https */
	if ((strcmp(wg->proto, "https") == 0) && wg->pc->ssl == NULL) {
		proto_SetSslCtx(wg->pc, do_chk_cert_send_request, wg);
	} else {
		do_send_request(wg, PROTO_OK);
	}
#else
	do_send_request(wg, PROTO_OK);
#endif
	return 0;
}

int wget_PostDataClose(tWgetInternal *wg, char *postdata, int datalen,
		const char *content_type, EventHandler callback, void *handle) {
	wg->request = ePostData;
	wg->content_type = content_type;
	wg->postdata = postdata;
	wg->datalen = datalen;
	wg->handle = handle;
	wg->cb = callback;
	if (wg->hdrs) {
		wg->hdrs->status_code = 0; /* reset status_code */
		wg->hdrs->content_length = 0;
	}
	wg->keepConnection = eCloseConnection;
#ifdef USE_SSL
	/* init ssl if proto is https */
	if ((strcmp(wg->proto, "https") == 0) && wg->pc->ssl == NULL) {
		proto_SetSslCtx(wg->pc, do_chk_cert_send_request, wg);
	} else {
		do_send_request(wg, PROTO_OK);
	}
#else
	do_send_request(wg, PROTO_OK);
#endif
	return 0;
}

int wget_PutData(tWgetInternal *wg, char *postdata, int datalen,
		const char *content_type, EventHandler callback, void *handle) {
	wg->request = ePutData;
	wg->content_type = content_type;
	wg->postdata = postdata;
	wg->datalen = datalen;
	wg->handle = handle;
	wg->cb = callback;
	if (wg->hdrs) {
		wg->hdrs->status_code = 0; /* reset status_code */
		wg->hdrs->content_length = 0;
	}
#ifdef USE_SSL
	/* init ssl if proto is https */
	if ((strcmp(wg->proto, "https") == 0) && wg->pc->ssl == NULL) {
		proto_SetSslCtx(wg->pc, do_chk_cert_send_request, wg);
	} else {
		do_send_request(wg, PROTO_OK);
	}
#else
	do_send_request(wg, PROTO_OK);
#endif
	return 0;
}
/*
 * Disconnect maybe called from within a callback called
 * by report_status. Don't freeData() if cbActive is set.
 * Setting cCloseConnection will cause report_status
 * to free up the data on return by the callback.
 *
 */

int wget_Disconnect(tWgetInternal *wg) {
	if (wg != NULL) {
		stopTimer(timer_response, wg); /* may be running */
		stopTimer(timer_connect, wg);  /*    "     "     */
		if (wg->pc)
			stopListener(wg->pc->fd);  /* may be listening */
		wg->request = eDisconnect;
		wg->keepConnection = eCloseConnection;
		if (!wg->cbActive) {
			freeData(wg);
		}
	}
	return 0;
}

int wget_AddPostHdr(tWgetInternal *wg, char *xhdrname, char *value) {
	XtraPostHdr **p = &wg->xtraPostHdrs;
	return addPostHdr(p, xhdrname, value, REPLACE);
}

void wget_ClearPostHdrs(tWgetInternal *wg) {
	XtraPostHdr *xh = wg->xtraPostHdrs;

	while (xh) {
		XtraPostHdr *nxt;
		GS_FREE(xh->hdr);
		GS_FREE(xh->value);
		nxt = xh->next;
		GS_FREE(xh);
		xh = nxt;
	}
	wg->xtraPostHdrs = NULL;
}

const char *wget_LastErrorMsg(void) {
	return lastErrorMsg;
}
/*
 * Return a pointer to the response buffer and set the active data length
 * in the mlth variable if mlth pointer is not NULL. Also remove rspBuf
 * pointer from the WgetInternal state structure.
 */
char *wget_GetResponseBuf(tWgetInternal *wg, int *mlth) {
	char *respBuf = wg->rspBuf;
	wg->rspBuf = NULL;
	if (mlth != NULL)
		*mlth = wg->datalen;
	return respBuf;
}


void wget_SetUserAgent(const char *uaName) {
	strncpy(userAgent, uaName, sizeof(userAgent));
	return;
}
void wget_SetServerTimeout(int timeout) {
	serverTimeout = timeout;
}

