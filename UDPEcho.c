/*----------------------------------------------------------------------*
 * Gatespace Networks, Inc.
 * Copyright 2004,2015 Gatespace. All Rights Reserved.
 * Gatespace Networks, Inc. confidential material.
 *----------------------------------------------------------------------*
 * File Name  :UDPEchoServer.c
 *
 * Description: UDP echo client.
 *
 *
 * $Revision: 1.2 $
 * $Id: UDPEchoServer.c,v 1.2 2015/09/03 20:31:00 dmounday Exp $
 *----------------------------------------------------------------------*/
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/time.h>
#include <time.h>
#include <syslog.h>
#include <string.h>
#include "limits.h"

#include "targetsys.h"
#include "includes/sys.h"
#include "gslib/src/utils.h"
#include "gslib/src/event.h"
#include "gslib/auxsrc/dns_lookup.h"
#include "gslib/auxsrc/cpelog.h"

#define DEBUG
#ifdef DEBUG
#define DBGPRINT(X) fprintf X
#else
#define DBGPRINT(X)
#endif

#define	UDPHDRSZ		8
#define	ECHOPLUSSZ		24

#define TESTGENSN		0
#define	TESTRESPSN		1
#define	TESTRESPRECVTIME	2
#define	TESTRESPREPLYTIME	3
#define	TESTRESPFAILCNT		4
#define	TESTITERATIONCNT	5

static char	*interface;			/* Interface to use. May be NULL */
static InAddr   clientIP;			/* Client IP address. Only listen for this IP */
static SockAddrStorage sa;
static struct sockaddr_in *clientAddr = (struct sockaddr_in *) &sa;
static InAddr   localIP;		/* Local host IP address */
static uint16_t	port;
static int	echoPlus;
static int	verbose;
static int	dateTimeFormat;
static int	idProcess;

static InAddr	srvrIP;

SockAddrStorage udpServer;

static int	blockSize;
static int	repetitions;
static int	timeout;
static int	DSCP;
static int	interTime;
static char host[256];
static int	fd;
static char detail;


static int listenSocket;
static struct timeval startupTime;
static struct timeval sendTime;
static struct timeval recTime;
static long totalRespTime;
static unsigned minRespTime;
static unsigned maxRespTime;
static unsigned successCnt;
static unsigned failureCnt;

/*
 * statistics
 */
unsigned	packetsRevd;
unsigned	packetsResponded;
unsigned	bytesRevd;
unsigned	bytesResponded;
struct timeval	timeFirstPacket;
struct timeval	timeLastPacket;
unsigned	reqCnt;
unsigned	failCnt;

static uint32_t	rbuf[65536/sizeof(uint32_t)];

static void printServerResult(void){
	char	buf[128];
	struct tm   *tmp;
	fprintf(stdout, "%d %d %d %d ", packetsRevd, packetsResponded, bytesRevd, bytesResponded);
	if (dateTimeFormat ){
		tmp = localtime(&timeFirstPacket.tv_sec);
		strftime(buf,sizeof(buf),"%Y-%m-%dT%H:%M:%S",tmp );
		fprintf(stdout, "%s.%06d ", buf, timeFirstPacket.tv_usec);
		tmp = localtime(&timeLastPacket.tv_sec);
		strftime(buf,sizeof(buf),"%Y-%m-%dT%H:%M:%S",tmp );
		fprintf(stdout, "%s.%06d\n", buf, timeLastPacket.tv_usec);
	} else {
		fprintf(stdout, "%ld.%06d %ld.%06d\n",
			timeFirstPacket.tv_sec, timeFirstPacket.tv_usec,
			timeLastPacket.tv_sec, timeLastPacket.tv_usec);
	}
	fflush(stdout);
}

static void printDetailResults(int success){
	char	buf[128];
	struct tm *tmp;
	if ( detail && echoPlus ){
		if (dateTimeFormat) {
			tmp = localtime(&sendTime.tv_sec);
			strftime(buf,sizeof(buf),"%Y-%m-%dT%H:%M:%S",tmp );
			fprintf(stdout, "D%d: %d %s.%06d ",
				reqCnt,
				success,
				buf, sendTime.tv_usec);
			tmp = localtime(&recTime.tv_sec);
			strftime(buf,sizeof(buf),"%Y-%m-%dT%H:%M:%S",tmp );
			fprintf(stdout, "%s.%06d", buf, recTime.tv_usec);
		} else {
			fprintf(stdout, "D%d: %d %d.%06d %d.%06d %d %d %d %d %d\n",
				reqCnt,
				success,
				sendTime.tv_sec, sendTime.tv_usec,
				recTime.tv_sec, recTime.tv_usec);
		}
		fprintf(stdout, " %u %u %u %u %u\n",
			ntohl(rbuf[TESTGENSN]),
			ntohl(rbuf[TESTRESPSN]),
			ntohl(rbuf[TESTRESPRECVTIME]),
			ntohl(rbuf[TESTRESPREPLYTIME]),
			ntohl(rbuf[TESTRESPFAILCNT]));
	}

}
static void printClientResults(void){
	unsigned avg;
	if ( successCnt>0)
		avg = totalRespTime/successCnt;
	else
		avg = 0;
	fprintf(stdout, "S:%u %u %u %u %u\n",
			successCnt, failureCnt, avg, minRespTime, maxRespTime);
}

static void sendUDPEchoPacket(void *);

/* echo from server timed out */
static void echoTimeout(void *handle){
	DBGPRINT((stderr, "sendUDPEchoPacket\n"));
	failureCnt++;
	if ( reqCnt < repetitions)
		setTimer(sendUDPEchoPacket, NULL, interTime*1000);
	else
		stopListener(fd);
	printDetailResults(0);
}
static void recvdResponse(void *handle){
	struct timeval tempTime;
	long	mics;
	struct sockaddr_in *sp=(struct sockaddr_in*)&udpServer;
	socklen_t		addrlen;
	ssize_t		len;
	ssize_t		rlen;
	addrlen = sizeof(udpServer);

	DBGPRINT((stderr,"recvResponse\n"));
	stopTimer(echoTimeout, NULL);
	gettimeofday(&recTime, NULL);
	if ((len = recvfrom(fd, rbuf, sizeof(rbuf), 0, sp, &addrlen)) > 0) {
		timersub(&recTime, &sendTime, &tempTime);
		mics = tempTime.tv_sec*1000000 + tempTime.tv_usec;
		totalRespTime += mics;
		if ( mics>maxRespTime)
			maxRespTime = mics;
		else if ( mics<minRespTime)
			minRespTime = mics;
		if ( ntohl(rbuf[TESTITERATIONCNT]) == reqCnt)
			successCnt++;
		/* failure counted in echoTimeout */
		if ( reqCnt < repetitions)
			setTimer(sendUDPEchoPacket, NULL, interTime*1000);
		else
			stopListener(fd);
		printDetailResults(1);
	}
}

static void sendUDPEchoPacket(void *handle){
	int rstat;
	DBGPRINT((stderr, "sendUDPEchoPacket\n"));
	rbuf[TESTGENSN]= htonl(reqCnt);
	rbuf[TESTRESPSN] = 0;
	rbuf[TESTITERATIONCNT]= htonl(++reqCnt);
	rstat = send(fd, rbuf, blockSize, 0);
	if (rstat == blockSize ){
		gettimeofday(&sendTime, NULL);
		setListenerType(fd, recvdResponse, NULL, iListener_Read);
		setTimer(echoTimeout, NULL, timeout*1000);
	}
}


static int startClient(void){
	long	flags;
	SockAddrStorage sa;
	struct sockaddr_in *sp=(struct sockaddr_in*)&udpServer;

	DBGPRINT((stderr, "startClient"));
	minRespTime = timeout*1000000;
	dns_lookup( host, SOCK_DGRAM, &srvrIP);
	if ( srvrIP.inFamily!=0 ) {
		if ((fd = udp_listen(&localIP, port, interface, 0)) < 0) {
			cpeLog(LOG_ERR, "Could not create socket for (port=%d)", port);
			return -1;
		}
		SET_SockADDR( sp, htons(port), &srvrIP);
		if ( connect(fd, sp, sizeof(sa)) == 0 ){
			/* set non-blocking */
			flags = (long) fcntl(fd, F_GETFL);
			flags |= O_NONBLOCK;
			fcntl(fd, F_SETFL, flags);
			reqCnt = 0;
			sendUDPEchoPacket(NULL);
		}
	}
	return 0;
}


static int isFromClient( struct sockaddr *from ){
	struct sockaddr_in *cip = (struct sockaddr_in *)from;
#ifdef USE_IPV6
	int lth = fam1==AF_INET6? sizeof(struct in6_addr): sizeof(struct in_addr);
#else
	int lth = sizeof( struct in_addr );
#endif
	return ( (cip->sin_family == clientAddr->sin_family)
	        && (memcmp(&cip->sin_addr, &clientAddr->sin_addr, lth)==0 ));
}

static void doEcho(void *handle){
	struct sockaddr from;
	socklen_t		addrlen;
	ssize_t		len;
	ssize_t		rlen;
	unsigned long mics, rmics;
	struct timeval rtime, tempTime;
	addrlen = sizeof(from);
	gettimeofday(&rtime, NULL);  /* time of receive complete event */
	if ((len = recvfrom(listenSocket, rbuf, sizeof(rbuf), 0, &from, &addrlen)) > 0) {
		if ( isFromClient(&from) ){
			if ( packetsRevd==0 )
				timeFirstPacket = rtime;
			timeLastPacket = rtime;
			++packetsRevd;
			bytesRevd+= len + 8;
			if ( echoPlus && len>= ECHOPLUSSZ ){
				if (verbose)
					fprintf(stderr, "UDP Packet received: TestGenSN=%d\n", rbuf[0]);
				rbuf[TESTRESPSN] = htonl(reqCnt++);
				timersub(&rtime, &startupTime, &tempTime);
				mics = tempTime.tv_sec*1000000 + tempTime.tv_usec;
				rbuf[TESTRESPRECVTIME] = htonl( mics );
				rbuf[TESTRESPFAILCNT] = htonl(failCnt);
				gettimeofday(&rtime, NULL);   /* probably the same time as before*/
				timersub(&rtime, &startupTime, &tempTime);
				rmics = tempTime.tv_sec*1000000 + tempTime.tv_usec;
				if ( verbose )
					fprintf(stderr, "packet Rec time:  %ld   Resp time: %ld\n", mics, rmics);
				rbuf[TESTRESPREPLYTIME] = htonl(rmics);
			} else {
				if (verbose)
					fprintf(stderr, "UDP Packet received\n");
			}
			if ( (rlen = sendto(listenSocket, rbuf, len, 0, &from, addrlen))!= len){
				++failCnt;
			}else{
				++packetsResponded;
				bytesResponded+= rlen +8;
			}
		} else { /* else ignore the packet */
			if (verbose)
				fprintf(stderr, "packet discarded from unknown host\n");
		}
	} else {
		++failCnt;
	}
	printServerResult();
}
/*
 * Start UDP Echo Server
 */
static int	startServer(void){
	SET_SockADDR(clientAddr, 0, &clientIP);
	listenSocket = udp_listen( &localIP, port, interface, 0);
	if ( listenSocket != -1){
		setListener(listenSocket, doEcho, 0);
		return 0;
	}
	return listenSocket;
}
/*
 * Example usage
 * udpechoserver -I eth0 -i 10.0.0.11 -p 7 -E
 */
static void usage(char** p){
	fprintf(stderr, "Usage Server:\n  %s options\n", *p);
	fprintf(stderr, "\t<common options\n");
	fprintf(stderr, "\t-I           Interface\n");
	fprintf(stderr, "\t-S           DSCP\n");
	fprintf(stderr, "\t-h           Local host IP\n");
	fprintf(stderr, "\t-E           Enable Echo Plus\n");
	fprintf(stderr, "\t-v           Verbose output\n");
	fprintf(stderr, "\t-D           Display times in DateTime format\n");
	fprintf(stderr, "\t-P           Write process ID to stdout\n");
	fprintf(stderr, "\t<UDP Server Options:\n");
	fprintf(stderr, "\t-i           IP address of client\n");
	fprintf(stderr, "\t-p           UDP Port to listen on\n");
	fprintf(stderr, "\t<UDP Client Options:\n");
	fprintf(stderr, "\t-r           Remote Echo Server Host\n");
	fprintf(stderr, "\t-n           Number of repetitions (client)\n");
	fprintf(stderr, "\t-T           Timeout (client)\n");
	fprintf(stderr, "\t-t           InterTransmissionTime(client)\n");
	fprintf(stderr, "\t-b           Block size(client)\n");
	fprintf(stderr, "\t-p           Port to send to\n");
	fprintf(stderr, "\t-d           Enable client detail results\n");
}
/*
 */
int main(int argc, char** argv)
{
	int	opt;
	int	rstat = 0;

	readInIPAddr(&localIP, "0.0.0.0" /*INADDR_ANY*/);

	while ((opt=getopt(argc, argv, "PDS:I:i:p:h:Evr:n:T:t:b:d"))!=-1) {
		switch (opt) {
		case 'I':
			interface = optarg;
			break;
		case 'S':
			DSCP = atoi(optarg);
		case 'p':
			port = atoi(optarg);
			break;
		case 'i':
			readInIPAddr( &clientIP, optarg);
			break;
		case 'h':
			readInIPAddr( &localIP, optarg);
			break;
		case 'E':
			echoPlus = 1;
			break;
		case 'v':
			verbose = 1;
			break;
		case 'D':
			dateTimeFormat = 1;
			break;
		case 'P':
			idProcess = 1;
			break;
		case 'r':
			strncpy(host, optarg, sizeof(host));
			break;
		case 'b':
			blockSize = atoi(optarg);
			break;
		case 'n':
			repetitions = atoi(optarg);
			break;
		case 'T':
			timeout = atoi(optarg);
			break;
		case 't':
			interTime = atoi(optarg);
			break;
		case 'd':
			detail = 1;
			break;
		default:
			usage(argv);
			exit (EXIT_FAILURE);
		}
	}

	gettimeofday(&startupTime, NULL);
	initGSLib();		/* initialize the gslib timer and event handlers */
	fprintf(stdout, "Pid=%d\n", getpid());
	fflush(stdout);
	if ( strlen(host)>0 && blockSize>0 && timeout>0 && interTime>0 ) {
		/* we are running as a UDP Echo client */
		rstat = startClient();
	} else {
		rstat = startServer();
	}
	if ( rstat == 0 ){
		eventLoop();		/* this returns when there are no timers or listeners */
		if (verbose)
			fprintf(stderr, "exited event loop\n");
		if ( strlen(host)> 0){
			printClientResults();
		} else {
			printServerResult();
		}
	}
	fprintf(stderr, "Exit status %d\n", rstat);
	return rstat==0? EXIT_SUCCESS: EXIT_FAILURE;
}



