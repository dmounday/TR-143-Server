/*----------------------------------------------------------------------*
 * Gatespace
 * Copyright 2005-2013 Gatespace. All Rights Reserved.
 * Gatespace Networks, Inc. confidential material.
 *----------------------------------------------------------------------*
 * File Name  : protocol.h
 *
 * Description:
 * $Revision: 1.8 $
 * $Id: protocol.h,v 1.8 2015/06/22 16:59:26 dmounday Exp $
 *----------------------------------------------------------------------*/
#ifndef _PROTOCOL_H_
#define _PROTOCOL_H_

#ifdef USE_SSL
	#include <openssl/ssl.h>
#endif
#define HTTP_HDR_SIZE 4096   /* maximum HTTP header size */
/*----------------------------------------------------------------------*
 * typedefs
 */


typedef enum {  /* use to determine http source */
  iZone_Unknown,
  iZone_Lan,
  iZone_Ihz,
  iZone_Plan
} tZone;


typedef struct CookieHdr {
	struct CookieHdr *next;
	char    *name;
	char    *value;
} CookieHdr;

/*--------------------*/
typedef struct {

	/* request */
	char method[8];
	char path[256];
	char *host;
	int  port;
	int  content_length;
	char *expect;			/* indicates request body is coming */

	/* result */
	int  status_code;
	CookieHdr *setCookies;
	char *message;
	char *locationHdr;		  /* from 3xx status response */

	/* common */
	char protocol[10];
	char *content_type;
	char *wwwAuthenticate;
	char *Authorization;
	char *TransferEncoding;
	char *Connection;
	char *Referer;

	/* request derived */
	char *arg;
} tHttpHdrs;

typedef void (*tProtoHandler)(void *, int lth);

typedef enum {
	sslRead,
	sslWrite
} tSSLIO;
/*--------------------*/
typedef enum {
	iUnknown,
	iNormal,
#ifdef USE_SSL
	iSsl,
#endif
	i__Last
} tPostCtxType;

/*--------------------*/
typedef struct {
	tPostCtxType type;
	int fd;		 /* filedescriptor */
	/* internal use */
#ifdef USE_SSL
	SSL           *ssl;
#endif
	tProtoHandler cb;
	void *data;
} tProtoCtx;


/* convenient naming */
#define fdgets   proto_Readline
#define fdprintf proto_Printline

#define PROTO_OK                0
#define PROTO_ERROR            -1
#define PROTO_ERROR_SSL        -2

/*----------------------------------------------------------------------*/
void proto_Init(char *cipherList, char *serverCerts, char *clientCerts);

tHttpHdrs *proto_NewHttpHdrs(void);
void proto_FreeHttpHdrs(tHttpHdrs *p);

tProtoCtx *proto_NewCtx(int fd);
#ifdef USE_SSL
void proto_SetSslCtx(tProtoCtx *pc, tProtoHandler cb, void *data);
#endif
void proto_FreeCtx(tProtoCtx *pc);

//int  proto_ReadWait(tProtoCtx *pc, char *ptr, int nbytes, int timeout);
int  proto_Readn(tProtoCtx *pc, char *ptr, int nbytes, int *errnovalue);
int  proto_Writen(tProtoCtx *pc, const char *ptr, int nbytes);
void proto_Printline(tProtoCtx *pc, const char *fmt, ...);
int  proto_Skip(tProtoCtx *pc);
int  proto_SSL_IO(tSSLIO iofunc, tProtoCtx *pc, char *ptr, int nbytes, tProtoHandler cb, void *data);
int  proto_SendRequest(tProtoCtx *pc, const char *method, const char *url);
int  proto_SendCookie(tProtoCtx *pc, CookieHdr *c);
int  proto_SendHeader(tProtoCtx *pc,  const char *header, const char *value);
int  proto_SendEndHeaders(tProtoCtx *pc);
int  proto_SendRaw(tProtoCtx *pc, const char *arg, int len);

int  proto_ParseResponse(tHttpHdrs *hdrs, char *buf);
int  proto_ParseRequest(tHttpHdrs *hdrs, char *buf);
int  proto_ParseHdr(tHttpHdrs *hdrs, char *buf);

#ifdef USE_CERTIFICATES
int proto_CheckCertificate(tProtoCtx *pc, const char *host);
#endif

#endif
