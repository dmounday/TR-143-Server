/*
 * httpserver.c
 *
 *  Created on: Apr 20, 2015
 *      Author: dmounday
 *
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <time.h>
#include <syslog.h>
#include <string.h>
#include "limits.h"
#include "ctype.h"
#include <signal.h>

#include "targetsys.h"
//#include "../includes/sys.h"
#include "gslib/src/utils.h"
#include "gslib/src/event.h"
#include "gslib/src/protocol.h"
#include "gslib/auxsrc/cpelog.h"


#define DEBUG
#ifdef DEBUG
#define DBGPRINT(X) fprintf X
#else
#define DBGPRINT(X)
#endif
#define	MAX_CONNS	100				/* maximum number of transfer connections */
#define	HTTPBUFSZ	4096
#define CLIENT_DISCONNECT_TIME	1500 /* time after transfer to wait on client disconnect */

typedef enum {
	sIdle, sInitializing, sData, sDataTimed, sShutdown
} eServerState;

typedef enum {
	eMethod,
	eREAD_HEADERS,
	eREAD_CHUNKSZ,
	eREAD_CHUNKDATA,
	eREAD_CHUNKCRLF,
	eREAD_LASTCRLF,
	eREAD_CONTENTDATA,
	eDataReceive,
	eDataReply
} eHTTPSEQ;

#define	MAXCR_SZ	1025
#define CHUNKBUFSZ	HTTPBUFSZ+10
typedef struct ClientConnection{
	eServerState cState; /* authentication state */
	eHTTPSEQ	 httpState; /* state of HTTP message parsing */
	tProtoCtx *cpc; /* so we can use wget proto functions */
	int lfd; /* listener socket */
	tHttpHdrs *hdrs;
	InAddr ipAddr; /* IP address to bind listener to */
	char 	buf[CHUNKBUFSZ];
	int 	bufIdx;
	long	bytesXfrd;
	long	pathSize;	/* size requested in path ZZnnnnnn*/
	int		timed;		/* if set this transfer is timed by client */
	int		b2write;		/* bytes in buffer to write */
	long	bufCnt;    /* used by PUT method reading */
	long	bufLth;
	long	datalen;
	long	chunksz;
	long	totDataBytes;
} ClientConnection;

static	ClientConnection clientConnection[MAX_CONNS];
static	int	maxConn = MAX_CONNS;
static	int	stopOnError = 0;	/* stop server on any error */

static	int	listenSocket;
static	int	listenQsize;
static	int	port =8080;
static	struct InAddr	localHost;
static	char *sizePrefix="/ZZ";
static	char *timedPrefix="/TT";

ClientConnection *getCD(void){
	int	i;
	for(i=0; i<maxConn; ++i){
		if (clientConnection[i].cState == sIdle){
			memset(&clientConnection[i], 0, sizeof(ClientConnection));
			clientConnection[i].hdrs = proto_NewHttpHdrs();
			clientConnection[i].cState = sInitializing;
			clientConnection[i].httpState = eMethod;
			return &clientConnection[i];
		}
	}

	return NULL;
}
/*
 * readLine(ACSConnection *cd, char *buffer, int *readLength)
 * return ==0  CRLF sequence has been found. Buf is null terminated string with CRLF stripped.
 * 		 >0  Length of data in buffer, Waiting on more data.
 * 		 -1  EAGAIN or EWOULDBLOCK
 * 		 -2  read error.
 * 		 -3  Not found. Buffer size exceeded.
 */
static int readLine(ClientConnection *cd, char *buf, int maxlen) {
	int rc;
	char c;
	int len;
	int errnovalue;
	char *ptr = buf;

	len = 0;
	while (len < maxlen) {
		rc = proto_Readn(cd->cpc, &c, 1, &errnovalue);
		if (rc == 1) {
			if (c == '\n') {
				*ptr = '\0'; /* null terminated */
				if (ptr!=buf && *(ptr-1)=='\r')
					*(ptr - 1) = '\0';
				return 0;
			}
			*ptr++ = c;
			len++;
		} else
			return rc;
	}
	return -3;
}
/*
 * return -1: for error
 *       != -1 is socket
 */
static int initSocket(InAddr *ip, int port) {
	SockAddrStorage sa;
	struct sockaddr_in *sp = (struct sockaddr_in *) &sa;

	int port_sock = 0;
	int res, i = 1;
	long flags;

	memset(sp, 0, sizeof(SockAddrStorage));
	SET_SockADDR(sp, htons(port), ip);

	port_sock = socket(sp->sin_family, SOCK_STREAM, IPPROTO_TCP);
	if (port_sock < 0) {
		fprintf(stderr, "ConnReq: init_socket(port=%d), socket failed: %s",
				port, strerror(errno));
		return -1;
	}
	/* set non-blocking */
	flags = (long) fcntl(port_sock, F_GETFL);
	flags |= O_NONBLOCK;
	res = fcntl(port_sock, F_SETFL, flags);
	res = setsockopt(port_sock, SOL_SOCKET, SO_REUSEADDR, (char*) &i,
			sizeof(i));
	if (res < 0) {
		fprintf(stderr, "ConnReq: Socket error initializing");
		close(port_sock);
		return -1;
	}

	res = bind(port_sock, (struct sockaddr *) sp, SockADDRSZ(sp));
	if (res < 0) {
		fprintf(stderr, "ConnReq: bind failed errno=%d.%s", errno,
				strerror(errno));
		close(port_sock);
		return -1;
	}

	res = listen(port_sock, listenQsize);
	if (res < 0) {
		fprintf(stderr, "ConnReq: listen failed errno=%d.%s", errno,
				strerror(errno));
		close(port_sock);
		return -1;
	}
	return port_sock;
}
static void connectionCleanUp(ClientConnection *cd){
	stopListener(cd->cpc->fd);
	if (cd->hdrs) {
		proto_FreeHttpHdrs(cd->hdrs);
		cd->hdrs = NULL;
	}
	proto_FreeCtx(cd->cpc);
	cd->cState = sIdle;

}
static void errorWriteComplete(void *handle) {
	ClientConnection *cd = (ClientConnection*) handle;
	cpeDbgLog(DBG_ACSCONNECT, "statusWriteComplete fd=%d", cd->cpc->fd);
	connectionCleanUp(cd);
	if ( stopOnError )
		closeAllFds();
}
static void doClientDisconnect(void *handle){
	ClientConnection *cd = (ClientConnection*) handle;
	cpeDbgLog(DBG_ACSCONNECT, "Client Disconnected fd=%d", cd->cpc->fd);
	stopTimer(doClientDisconnect, cd);
	connectionCleanUp(cd);
}
static void transferComplete(void *handle){
	ClientConnection *cd = (ClientConnection*) handle;
	cpeDbgLog(DBG_ACSCONNECT, "transferComplete fd=%d Total Bytes=%ld", cd->cpc->fd, cd->totDataBytes);
	setListener(cd->cpc->fd, doClientDisconnect, cd);
	setTimer(doClientDisconnect, cd, CLIENT_DISCONNECT_TIME);
}
static int sendStatusReply(ClientConnection *cd, const char *status, int sendContentLength) {
	char response[300];
	int i;

	i = snprintf(response, sizeof(response), "HTTP/1.1 ");
	i += snprintf(response+i, sizeof(response)-i, "%s\r\n", status);
	if ( sendContentLength)
		i += snprintf(response + i, sizeof(response) - i, "Content-Length: 0\r\n\r\n");
	else
		i += snprintf(response + i, sizeof(response)-1, "\r\n");
	if (proto_Writen(cd->cpc, response, i) < i)
		return 0;
	return 1;
}
static void sendResponseHeaders(ClientConnection *cd){
	char *b = cd->buf;
	int	i;
	i = snprintf(b, HTTPBUFSZ, "HTTP/1.1 200 OK\r\n");
	i += snprintf(b + i, HTTPBUFSZ - i, "Transfer-Encoding: chunked\r\n");
	i += snprintf(b + i, HTTPBUFSZ - i, "\r\n");
	//cd->bufIdx = i;
	write(cd->cpc->fd, b, i);
	//fprintf(stderr, "sendResponse %d\n", n);
}

static void fillChunk(ClientConnection *cd){
	int left;
	int sz;
	int i;
	int nsz;
	if ( cd->timed ){
		sz = HTTPBUFSZ;
	} else {
		left = cd->pathSize - cd->bytesXfrd;
		sz  = HTTPBUFSZ>left? left: HTTPBUFSZ;
	}
	nsz = snprintf(cd->buf, CHUNKBUFSZ, "%04x\r\n", sz);
	if ( sz > 0){
		for (i=nsz; i<sz+nsz; ++i){
			cd->buf[i]='a';
		}
		nsz+=snprintf(cd->buf+nsz+sz, CHUNKBUFSZ-nsz, "\r\n");
		cd->bytesXfrd+=sz;
	}
	cd->b2write = sz+nsz;
}
const char *endChunk="0000\r\n\r\n";   /* last chunk plus final CRLF */
static void writeData(void *handle){
	ClientConnection *cd = (ClientConnection *)handle;
	int n;
	cpeDbgLog(DBG_TRANSFER, "writeData");
	if (cd->b2write==0){
		if ( cd->timed || cd->bytesXfrd < cd->pathSize){
			fillChunk(cd);
		} else if ( cd->bytesXfrd == cd->pathSize){
			/* write end chunk */
			strcpy(cd->buf, endChunk);
			cd->b2write = strlen(cd->buf);
			cd->bytesXfrd+=cd->b2write; /* increment past end */
		} else {
			transferComplete(cd);
			return;
		}
	}
	n = write(cd->cpc->fd, cd->buf, cd->b2write);
	if ( n==-1 ){
		if ( errno==EAGAIN || errno==EWOULDBLOCK)
			return;
		else {
			fprintf(stderr, "write failed on writing chunk lth=%d:(%d) %s\n",
					cd->b2write, errno, strerror(errno));
			connectionCleanUp(cd);
		}
	}else {
		cd->b2write = 0;
		cd->totDataBytes+=n;
	}
}

static int readChunkSz(ClientConnection *cd, char *buf) {
	int chksz = 0;
	if (sscanf(buf, "%x", &chksz) == 1)
		return chksz;
	return -1;
}
/*
 * Parse path for lead sizePrefix (ZZ) followed by the
 * digits that specify the number of bytes to send to client.
 * TTddd indicates a time based test and the server will continue
 * sending chunked data until the client disconnects.
 */
static int parsePath(ClientConnection *cd){
	char *p;
	if ( (p = strstr(cd->hdrs->path, sizePrefix)) ){
		p+=3;
		if ( isdigit(*p)){
			cd->pathSize = atol(p);
			return 1;
		}
	} else if ( (p=strstr(cd->hdrs->path, timedPrefix))){
		cd->timed = 1;
		return 1;
	}
	return 0;
}
/**
 * A connected client is sending us data,
 * Our action is to send a 200 OK .
 *
 */
static void clientReadData(void *handle) {
	ClientConnection *cd = (ClientConnection *) handle;
	int sts;

#ifdef DEBUG
	cpeDbgLog(DBG_ACSCONNECT, "clientReadData: %d state=%d", cd->cpc->fd, cd->httpState);
#endif
	switch (cd->httpState ){
	case eMethod:
		if ((sts = readLine(cd, cd->buf+cd->bufIdx, MAXCR_SZ - cd->bufIdx)== 0)){
			/* found end of line for METHOD line */
			if (proto_ParseRequest( cd->hdrs, cd->buf) < 0 ){
				/**** error *****/
				cd->cState = sShutdown;
				sendStatusReply(cd, "400 Bad Request", 1);
				setListenerType(cd->cpc->fd, errorWriteComplete, cd, iListener_Write );
			}else {
				cd->httpState = eREAD_HEADERS;
				cd->bufIdx = 0;
			}
		} else if (sts > 0){ // some data read but not to eol
			cd->bufIdx += sts;
		} else if (sts == -2){
			/**** error *****/
			cd->cState = sShutdown;
			stopListener(cd->cpc->fd);
		}
		break;
	case eREAD_HEADERS:
		if ((sts = readLine(cd, cd->buf + cd->bufIdx, HTTP_HDR_SIZE-cd->bufIdx)) == 0) {
			/* found end of line - process header */
			cd->bufIdx = 0;
			if (proto_ParseHdr(cd->hdrs, cd->buf) == 0) {
				/* last line of header */
				cd->cState = sData;
				if ( strcmp(cd->hdrs->method,"PUT")==0) {
					if (cd->hdrs->TransferEncoding
						&& !strcasecmp(cd->hdrs->TransferEncoding,	"chunked")) {
						cd->httpState = eREAD_CHUNKSZ;
						cd->bufCnt = 0;
						cd->bufLth = cd->datalen = 0;
					} else if (cd->hdrs->content_length > 0) {
						cd->httpState = eREAD_CONTENTDATA;
						if (cd->hdrs->content_length > 0 ){
							cd->bufCnt = cd->datalen = 0;
							cd->bufLth = HTTPBUFSZ;
						}
					} else {
						sendStatusReply(cd, "200 OK", 1);
						setListenerType(cd->cpc->fd, transferComplete, cd, iListener_Write);
					}
					if ( cd->hdrs->expect && strcasecmp(cd->hdrs->expect, "100-continue")==0){
						sendStatusReply(cd, "100 Continue", 0);
					}
				} else if ( strcmp(cd->hdrs->method, "GET")==0) {
					if ( parsePath(cd) ){
						cd->httpState = eDataReply;
						cd->bufIdx = 0;
						sendResponseHeaders(cd);
						setListenerType(cd->cpc->fd, writeData, cd, iListener_Write);
					} else {
						// path error
						cd->cState = sShutdown;
						sendStatusReply(cd, "404 Not Found", 1);
						setListenerType(cd->cpc->fd, errorWriteComplete, cd, iListener_Write );
					}
				} else {
					sendStatusReply(cd, "501 Not Implemented", 1);
					cd->cState = sShutdown;
					setListenerType(cd->cpc->fd, errorWriteComplete, cd, iListener_Write);
				}
			}
			cd->bufIdx = 0;
		} else if (sts > 0){ // some data read but not to eol
			cd->bufIdx += sts;
		} else if (sts == -2){
			/**** error *****/
			cd->cState = sShutdown;
			sendStatusReply(cd, "500 Internal Server Error", 1);
			setListenerType(cd->cpc->fd, errorWriteComplete, cd, iListener_Write );
		}
		break;
	case eREAD_CHUNKSZ:
		if ((sts = readLine(cd, cd->buf + cd->bufIdx, HTTP_HDR_SIZE-cd->bufIdx)) == 0) {
			/* found end of line - process chunk size */
			if ((cd->chunksz = readChunkSz(cd, cd->buf)) < 0) {
				stopListener(cd->cpc->fd);
				// error
				cd->cState = sShutdown;
				sendStatusReply(cd, "500 Internal Server Error", 1);
				setListenerType(cd->cpc->fd, errorWriteComplete, cd, iListener_Write );
				return;
			}

			if (cd->chunksz == 0) {
				// completed reading chunks.
				cd->httpState = eREAD_LASTCRLF;
				return;
			}
			cd->httpState = eREAD_CHUNKDATA;
			cd->datalen = cd->bufIdx = 0;
			cd->bufLth = ( cd->chunksz > HTTPBUFSZ)? HTTPBUFSZ: cd->chunksz;

		} else if (sts > 0) {
			cd->bufIdx += sts;
		} else if (sts == -2 ) {
			/**** error *****/
			cd->cState = sShutdown;
			sendStatusReply(cd, "500 Internal Server Error", 1);
			setListenerType(cd->cpc->fd, errorWriteComplete, cd, iListener_Write );
		}
		break;
	case eREAD_CHUNKDATA:
		if ((sts = proto_Readn(cd->cpc, cd->buf, cd->bufLth, NULL)) > 0) {
			cd->totDataBytes+= sts;
			cd->datalen += sts;
			if (cd->datalen>=cd->chunksz){
				// chunk data read.
				cd->httpState = eREAD_CHUNKCRLF;
				cd->bufIdx = 0;
			} else {
				int left = cd->chunksz - cd->datalen;
				cd->bufLth = (left>HTTPBUFSZ)? HTTPBUFSZ: left;
			}

		}
		if (sts == -2 || sts == 0) {
			/* read error */
			stopListener(cd->cpc->fd);
			// error
			cd->cState = sShutdown;
			sendStatusReply(cd, "500 Internal Server Error", 1);
			setListenerType(cd->cpc->fd, errorWriteComplete, cd, iListener_Write );
			return;
		}
		break;
	case eREAD_CHUNKCRLF:
		if ((sts = readLine(cd, cd->buf + cd->bufIdx, HTTP_HDR_SIZE-cd->bufIdx)) == 0) {
			/* found end of line  */
			cd->httpState = eREAD_CHUNKSZ;
			cd->bufIdx = 0;
		} else if (sts > 0) {
			cd->bufIdx += sts;
		} else if (sts == -2 ) {
			stopListener(cd->cpc->fd);
			// error
			cd->cState = sShutdown;
			sendStatusReply(cd, "500 Internal Server Error", 1);
			setListenerType(cd->cpc->fd, errorWriteComplete, cd, iListener_Write );
			return;
		}
		break;
	case eREAD_LASTCRLF:
		stopListener(cd->cpc->fd);
		sendStatusReply(cd, "200 OK", 1);
		setListenerType(cd->cpc->fd, transferComplete, cd, iListener_Write);
		return;
		break;
	case eREAD_CONTENTDATA:
		if ((sts = proto_Readn(cd->cpc, cd->buf, HTTPBUFSZ, NULL)) > 0) {
			cd->totDataBytes += sts;
			cd->datalen += sts;
			if (cd->datalen >= cd->hdrs->content_length) {
				stopListener(cd->cpc->fd);
				cd->cState = sShutdown;
				sendStatusReply(cd, "200 OK", 1);
				setListenerType(cd->cpc->fd, transferComplete, cd, iListener_Write );
				return;
			}
		}
		if (sts == -2 || sts == 0) {
			/* read error */
			stopListener(cd->cpc->fd);
			// error
			cd->cState = sShutdown;
			sendStatusReply(cd, "500 Internal Server Error", 1);
			setListenerType(cd->cpc->fd, errorWriteComplete, cd, iListener_Write );
			return;
		}
		break;
	case eDataReply:
	default:
		/**** error *****/
		cd->cState = sShutdown;
		sendStatusReply(cd, "500 Internal Server Error", 1);
		setListenerType(cd->cpc->fd, errorWriteComplete, cd, iListener_Write );
		break;
	}
}
/**
 * Something is trying to connect.
 */
static void connectClient(void *handle) {
	int res;
	struct sockaddr_in addr;
	ClientConnection *cd;
	socklen_t sz = sizeof(struct sockaddr_in);
	long flags;
	int fd;

	memset(&addr, 0, sz);
	if ((fd = accept(listenSocket, (struct sockaddr *) &addr, &sz)) < 0) {
		if ( errno==EAGAIN || errno==EWOULDBLOCK )
			return;
		fprintf(stderr, "connectACS accept failed errno=%d.%s\n", errno,
				strerror(errno));

		close(listenSocket);
		return; /* return errno */
	}
	cpeDbgLog(DBG_ACSCONNECT, "Connect Client %d", fd);
	/* set non-blocking */
	flags = (long) fcntl(fd, F_GETFL);
	flags |= O_NONBLOCK;
	res = fcntl(fd, F_SETFL, flags);
	if ( (cd=getCD()) ){
		cd->cpc = proto_NewCtx(fd);
		if ((res = setsockopt(cd->cpc->fd, SOL_SOCKET, SO_REUSEADDR, &flags,
				sizeof(flags))) < 0)
			fprintf(stderr, "conn req setsockopt error %d %d %s\n", cd->cpc->fd,
					errno, strerror(errno));
		setListener(cd->cpc->fd, clientReadData, cd);
	} else {
		close(fd);
		fprintf(stderr, "Connection pool exhausted\n");
	}
}
static int startReqListener(struct InAddr *ip, int port){
	if ((listenSocket = initSocket(ip, port)) == -1)
		return -1;
	else {
		setListener(listenSocket, connectClient, NULL);
	}
	return 0;
}


static void usage(char** p){
	fprintf(stderr, "Usage: %s [-v] [-n max-connection] -h host-ip [-D] [-p port] [-S]\n", *p);
	fprintf(stderr, " Options:\n");
	fprintf(stderr, "	-v                   verbose output\n");
	fprintf(stderr, "	-n max-connections   maximum number of concurrent connections\n");
	fprintf(stderr, "	-D                   Debug logging\n");
	fprintf(stderr, "	-h bind-to-IP        IP address to listen on\n");
	fprintf(stderr, "	-p port              Port to listen on\n");
	fprintf(stderr, "	-S                   Stop program on any error\n");
	fprintf(stderr, "	-H                   This help message\n");
}
/*
 * Program arguments:
 * dldiag -v -D 0xff <dl-server-url>
 */
int main(int argc, char** argv)
{
	int verbose = 0;
	int	opt;
	int status = 0;
	int mask = 0;

	memset(&localHost, 0, sizeof(InAddr));

	while ((opt=getopt(argc, argv, "vDn:h:p:S"))!=-1) {
		switch (opt) {
		case 'v':
			verbose = 1;
			break;
		case 'D':
			mask = -1;
			break;
		case 'n':
			maxConn = atoi(optarg);
			if ( maxConn>MAX_CONNS){
				fprintf(stderr, "Maximum number of connections is %d\n", MAX_CONNS);
				exit(EXIT_FAILURE);
			}
			listenQsize = maxConn+2;
			break;
		case 'h':
			readInIPAddr( &localHost, optarg);
			break;
		case 'p':
			port = atoi(optarg);
			break;
		case 'S':
			stopOnError = 1;
			break;
		case 'H':
		default:
			usage(argv);
			exit (EXIT_FAILURE);
		}

	}

	initGSLib();		/* initialize the gslib timer and event handlers */
	cpeInitLog(verbose, mask);
	signal(SIGPIPE, SIG_IGN);
	/* start diag */
	if ( startReqListener(&localHost, port) < 0){
		fprintf(stderr, "Unable to initialize host/port listener\n");
		status = -1;
	} else {
		eventLoop();		/* this returns when there are no timers or listeners */
		fprintf(stderr,"eventLoop() exited\n");
		//printResults();
	}
	return status==0? EXIT_SUCCESS: EXIT_FAILURE;
}


