#ifndef _WGET_H_
#define _WGET_H_
#include "www.h"
/*----------------------------------------------------------------------*/
typedef enum {
  iWgetStatus_Ok = 0,
  iWgetStatus_InternalError,
  iWgetStatus_ConnectionError,
  iWgetStatus_Error,
  iWgetStatus_HttpError,
  iWgetStatus_CPEBufError,
  iWgetStatus_CPEGetStatusError,
  iWgetStatus_HttpStateError
} tWgetStatus;

typedef enum {
    eCloseConnection=0,
    eKeepConnectionOpen  /* used by wConnect and wClose */
} tConnState;
typedef enum {
    eUndefined,
    eConnect,
    ePostData,
    eGetData,
    ePutData,
    eDisconnect
} tRequest;

typedef struct XtraPostHdr{
    struct XtraPostHdr *next;
    char    *hdr;   /* header string */
    char    *value; /* value string*/
} XtraPostHdr;
/*
 * HTTP_STATE used by doResponse to track input of HTTP response
 * message.
 */
typedef enum {
	eREAD_STATUS,
	eREAD_HEADERS,
	eREAD_CHUNKSZ,
	eREAD_CHUNKDATA,
	eREAD_CHUNKCRLF,
	eREAD_LASTCRLF,
	eREAD_CONTENTDATA,
	eWRITE_HEADERS,
	eWRITE_CHUNKSZ,
	eWRITE_CHUNKDATA,
	eWRITE_CONTENTDATA
} HTTP_STATE;
#define CHUNKLTHSZ	6
#define	CHUNKCRLF	2
#define HTTPBUFSZ HTTP_HDR_SIZE+CHUNKLTHSZ+CHUNKCRLF+10
#define	HTTPCHUNKSZ	HTTPBUFSZ
typedef struct timespec timespec;
struct  tWgetInternal;
typedef int (*CBGetBuf)(void *, char *, int);
typedef int (*CBGetStatus)(void *, void *);

typedef struct tWgetInternal {
    tConnState  keepConnection;
    tWgetStatus status;
    const char 	*msg;           /* status message */
    tRequest    request;
    char         cbActive; /* set to 1 if callback from report status */
    char		crLastChar;
    tProtoCtx 	*pc;
    EventHandler cb;
    void 		*handle;
    char 		proto[PROTOCOL_SZ];
    char 		host[HOSTNAME_SZ];
    InAddr		host_addr;	/* remote host addr */
    InAddr		local_addr;	/* local host addr  */
    int 		port;
    char		uri[URI_SZ];
    tHttpHdrs 	*hdrs;
	CookieHdr	*cookieHdrs;
    XtraPostHdr	*xtraPostHdrs;
    const char 	*content_type;
    char 		*postdata;
    int  		datalen;	/* data read counter. current data size. */
    HTTP_STATE	httpState;
    char		buf[HTTPBUFSZ];		/* working buffer to read headers and chunk sizes */
    int			bindex;		/* index into header buf */
    int			chunksz;	/* size of current chunk */
    void		*cpeDLBuf;	/* optional download buffer supplied by calling functions */
    int			cpeDLBufLth;/* length of optional down load buffer */
    CBGetBuf	cpeBufCB;	/* callback to handle buffer */
    char		*rspBuf;	/* buffer used to download content data */
    int			bufCnt;
    int			bufLth;
    unsigned long maxBufferSize; /* limit to maximum file size allowed to down load */
    /* statistics */
    unsigned long totBytesRX;
    unsigned long totBytesTX;
    CBGetStatus cpeGetStatus;/* callback after HTTP status is read */
    timespec	ROMTime;	/* time GET sent */
    timespec	BOMTime;	/* time received first data packet*/
    timespec	EOMTime;	/* time received last data packet */
    timespec	OReqTime;	/* time SYN sent to server */
    timespec	ORspTime;	/* time ACK to SYN received */
} tWgetInternal;
/*----------------------------------------------------------------------*
 * returns
 *   0 if sending request succeded
 *  -1 on URL syntax error
 *
 * The argument to the callback is of type (tWget *)
 */
void wget_freeCookies( CookieHdr **);
int wget_GetData(tWgetInternal *wg,EventHandler callback, void *handle);
int wget_Get(const char *url, EventHandler callback, void *handle);
int wget_Post(const char *url, char *arg_keys[], char *arg_values[], EventHandler callback, void *handle);
int wget_PostRaw(const char *url, char *content_type, char *data, int len, EventHandler callback, void *handle);
tWgetInternal *wget_Connect(const char *url, InAddr *localHost, EventHandler callback, void *handle, unsigned long maxBufferSize);
int wget_PostData(tWgetInternal *,char *data, int datalen, const char *contenttype, EventHandler callback, void *handle);
int wget_PostDataClose(tWgetInternal *,char *data, int datalen, const char *contenttype, EventHandler callback, void *handle);
int wget_PutData(tWgetInternal *,char *data, int datalen, const char *contenttype, EventHandler callback, void *handle);
int wget_Disconnect(tWgetInternal *);
const char *wget_LastErrorMsg(void);

int wget_AddPostHdr( tWgetInternal *wio, char *xhdrname, char *value);
void wget_ClearPostHdrs( tWgetInternal *wio);
char *wget_GetResponseBuf(tWgetInternal *wg, int *mlth );
//char *wget_ReadResponse( tWgetInternal *wg, int *mlth, int maxBufferSize);
//int  wget_ReadBufResponse( tWgetInternal *wg, CBGetBuf, void *, char* , int);
void wget_SetUserAgent( const char *);
void wget_SetServerTimeout(int timeout);
#endif

