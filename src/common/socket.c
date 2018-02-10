// Copyright (c) Athena Dev Teams - Licensed under GNU GPL
// For more information, see LICENCE in the main folder

#include "cbasetypes.h"
#include "mmo.h"
#include "timer.h"
#include "malloc.h"
#include "showmsg.h"
#include "strlib.h"
#include "socket.h"

#include <stdlib.h>

#ifdef WIN32
	#include "winapi.h"
#else
	#include <errno.h>
#include <netinet/tcp.h>
	#include <net/if.h>
	#include <unistd.h>
#include <sys/ioctl.h>
	#include <netdb.h>
	#include <arpa/inet.h>

	#ifndef SIOCGIFCONF
	#include <sys/sockio.h> // SIOCGIFCONF on Solaris, maybe others? [Shinomori]
	#endif
	#ifndef FIONBIO
	#include <sys/filio.h> // FIONBIO on Solaris [FlavioJS]
	#endif

	#ifdef HAVE_SETRLIMIT
	#include <sys/resource.h>
	#endif
#endif

/////////////////////////////////////////////////////////////////////
#if defined(WIN32)
/////////////////////////////////////////////////////////////////////
// windows portability layer

typedef int socklen_t;

#define sErrno WSAGetLastError()
#define S_ENOTSOCK WSAENOTSOCK
#define S_EWOULDBLOCK WSAEWOULDBLOCK
#define S_EINTR WSAEINTR
#define S_ECONNABORTED WSAECONNABORTED

#define SHUT_RD   SD_RECEIVE
#define SHUT_WR   SD_SEND
#define SHUT_RDWR SD_BOTH

// global array of sockets (emulating linux)
// fd is the position in the array
static SOCKET sock_arr[FD_SETSIZE];
static int sock_arr_len = 0;

/// Returns the socket associated with the target fd.
///
/// @param fd Target fd.
/// @return Socket
#define fd2sock(fd) sock_arr[fd]

/// Returns the first fd associated with the socket.
/// Returns -1 if the socket is not found.
///
/// @param s Socket
/// @return Fd or -1
int sock2fd(SOCKET s)
{
	int fd;

	// search for the socket
	for( fd = 1; fd < sock_arr_len; ++fd )
		if( sock_arr[fd] == s )
			break;// found the socket
	if( fd == sock_arr_len )
		return -1;// not found
	return fd;
}


/// Inserts the socket into the global array of sockets.
/// Returns a new fd associated with the socket.
/// If there are too many sockets it closes the socket, sets an error and
//  returns -1 instead.
/// Since fd 0 is reserved, it returns values in the range [1,FD_SETSIZE[.
///
/// @param s Socket
/// @return New fd or -1
int sock2newfd(SOCKET s)
{
	int fd;

	// find an empty position
	for( fd = 1; fd < sock_arr_len; ++fd )
		if( sock_arr[fd] == INVALID_SOCKET )
			break;// empty position
	if( fd == ARRAYLENGTH(sock_arr) )
	{// too many sockets
		closesocket(s);
		WSASetLastError(WSAEMFILE);
		return -1;
	}
	sock_arr[fd] = s;
	if( sock_arr_len <= fd )
		sock_arr_len = fd+1;
	return fd;
}

int sAccept(int fd, struct sockaddr* addr, int* addrlen)
{
	SOCKET s;

	// accept connection
	s = accept(fd2sock(fd), addr, addrlen);
	if( s == INVALID_SOCKET )
		return -1;// error
	return sock2newfd(s);
}

int sClose(int fd)
{
	int ret = closesocket(fd2sock(fd));
	fd2sock(fd) = INVALID_SOCKET;
	return ret;
}

int sSocket(int af, int type, int protocol)
{
	SOCKET s;

	// create socket
	s = socket(af,type,protocol);
	if( s == INVALID_SOCKET )
		return -1;// error
	return sock2newfd(s);
}

char* sErr(int code)
{
	static char sbuf[512];
	// strerror does not handle socket codes
	if( FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM|FORMAT_MESSAGE_IGNORE_INSERTS, NULL,
			code, MAKELANGID(LANG_ENGLISH, SUBLANG_DEFAULT), (LPTSTR)&sbuf, sizeof(sbuf), NULL) == 0 )
		snprintf(sbuf, sizeof(sbuf), "unknown error");
	return sbuf;
}

#define sBind(fd,name,namelen) bind(fd2sock(fd),name,namelen)
#define sConnect(fd,name,namelen) connect(fd2sock(fd),name,namelen)
#define sIoctl(fd,cmd,argp) ioctlsocket(fd2sock(fd),cmd,argp)
#define sListen(fd,backlog) listen(fd2sock(fd),backlog)
#define sRecv(fd,buf,len,flags) recv(fd2sock(fd),buf,len,flags)
#define sSelect select
#define sSend(fd,buf,len,flags) send(fd2sock(fd),buf,len,flags)
#define sSetsockopt(fd,level,optname,optval,optlen) setsockopt(fd2sock(fd),level,optname,optval,optlen)
#define sShutdown(fd,how) shutdown(fd2sock(fd),how)
#define sFD_SET(fd,set) FD_SET(fd2sock(fd),set)
#define sFD_CLR(fd,set) FD_CLR(fd2sock(fd),set)
#define sFD_ISSET(fd,set) FD_ISSET(fd2sock(fd),set)
#define sFD_ZERO FD_ZERO

/////////////////////////////////////////////////////////////////////
#else
/////////////////////////////////////////////////////////////////////
// nix portability layer

#define SOCKET_ERROR (-1)

#define sErrno errno
#define S_ENOTSOCK EBADF
#define S_EWOULDBLOCK EAGAIN
#define S_EINTR EINTR
#define S_ECONNABORTED ECONNABORTED

#define sAccept accept
#define sClose close
#define sSocket socket
#define sErr strerror

#define sBind bind
#define sConnect connect
#define sIoctl ioctl
#define sListen listen
#define sRecv recv
#define sSelect select
#define sSend send
#define sSetsockopt setsockopt
#define sShutdown shutdown
#define sFD_SET FD_SET
#define sFD_CLR FD_CLR
#define sFD_ISSET FD_ISSET
#define sFD_ZERO FD_ZERO

/////////////////////////////////////////////////////////////////////
#endif
/////////////////////////////////////////////////////////////////////

#ifndef MSG_NOSIGNAL
	#define MSG_NOSIGNAL 0
#endif

fd_set readfds;
int fd_max;
time_t last_tick;
time_t stall_time = 60;

uint32 addr_[16];   // ip addresses of local host (host byte order)
int naddr_ = 0;   // # of ip addresses

// Maximum packet size in bytes, which the client is able to handle.
// Larger packets cause a buffer overflow and stack corruption.
#if PACKETVER < 20131223
static size_t socket_max_client_packet = 0x6000;
#else
static size_t socket_max_client_packet = USHRT_MAX;
#endif

#ifdef SHOW_SERVER_STATS
// Data I/O statistics
static size_t socket_data_i = 0, socket_data_ci = 0, socket_data_qi = 0;
static size_t socket_data_o = 0, socket_data_co = 0, socket_data_qo = 0;
static time_t socket_data_last_tick = 0;
#endif

// initial recv buffer size (this will also be the max. size)
// biggest known packet: S 0153 <len>.w <emblem data>.?B -> 24x24 256 color .bmp (0153 + len.w + 1618/1654/1756 bytes)
#define RFIFO_SIZE (2*1024)
// initial send buffer size (will be resized as needed)
#define WFIFO_SIZE (16*1024)

// Maximum size of pending data in the write fifo. (for non-server connections)
// The connection is closed if it goes over the limit.
#define WFIFO_MAX (1*1024*1024)

struct socket_data* session[FD_SETSIZE];

#ifdef SEND_SHORTLIST
int send_shortlist_array[FD_SETSIZE];// we only support FD_SETSIZE sockets, limit the array to that
int send_shortlist_count = 0;// how many fd's are in the shortlist
uint32 send_shortlist_set[(FD_SETSIZE+31)/32];// to know if specific fd's are already in the shortlist
#endif

static int create_session(int fd, RecvFunc func_recv, SendFunc func_send, ParseFunc func_parse);

#ifndef MINICORE
	int ip_rules = 1;
	static int connect_check(uint32 ip);
#endif

const char* error_msg(void)
{
	static char buf[512];
	int code = sErrno;
	snprintf(buf, sizeof(buf), "error %d: %s", code, sErr(code));
	return buf;
}

/*======================================
 *	CORE : Default processing functions
 *--------------------------------------*/
int null_recv(int fd) { return 0; }
int null_send(int fd) { return 0; }
int null_parse(int fd) { return 0; }

ParseFunc default_func_parse = null_parse;

void set_defaultparse(ParseFunc defaultparse)
{
	default_func_parse = defaultparse;
}


/*======================================
 *	CORE : Socket options
 *--------------------------------------*/
void set_nonblocking(int fd, unsigned long yes)
{
	// FIONBIO Use with a nonzero argp parameter to enable the nonblocking mode of socket s.
	// The argp parameter is zero if nonblocking is to be disabled.
	if( sIoctl(fd, FIONBIO, &yes) != 0 )
		ShowError("set_nonblocking: Failed to set socket #%d to non-blocking mode (%s) - Please report this!!!\n", fd, error_msg());
}

void setsocketopts(int fd,int delay_timeout){
	int yes = 1; // reuse fix

#if !defined(WIN32)
	// set SO_REAUSEADDR to true, unix only. on windows this option causes
	// the previous owner of the socket to give up, which is not desirable
	// in most cases, neither compatible with unix.
	sSetsockopt(fd,SOL_SOCKET,SO_REUSEADDR,(char *)&yes,sizeof(yes));
#ifdef SO_REUSEPORT
	sSetsockopt(fd,SOL_SOCKET,SO_REUSEPORT,(char *)&yes,sizeof(yes));
#endif
#endif

	// Set the socket into no-delay mode; otherwise packets get delayed for up to 200ms, likely creating server-side lag.
	// The RO protocol is mainly single-packet request/response, plus the FIFO model already does packet grouping anyway.
	sSetsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char *)&yes, sizeof(yes));

	// force the socket into no-wait, graceful-close mode (should be the default, but better make sure)
	//(https://msdn.microsoft.com/en-us/library/windows/desktop/ms737582%28v=vs.85%29.aspx)
	{
		struct linger opt;
		opt.l_onoff = 0; // SO_DONTLINGER
		opt.l_linger = 0; // Do not care
		if( sSetsockopt(fd, SOL_SOCKET, SO_LINGER, (char*)&opt, sizeof(opt)) )
			ShowWarning("setsocketopts: Unable to set SO_LINGER mode for connection #%d!\n", fd);
	}
	if(delay_timeout){
#if defined(WIN32)
		int timeout = delay_timeout * 1000;
#else
		struct timeval timeout;
		timeout.tv_sec = delay_timeout;
		timeout.tv_usec = 0;
#endif

		if (sSetsockopt (fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout,sizeof(timeout)) < 0)
			ShowError("setsocketopts: Unable to set SO_RCVTIMEO timeout for connection #%d!\n");
		if (sSetsockopt (fd, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout,sizeof(timeout)) < 0)
			ShowError("setsocketopts: Unable to set SO_SNDTIMEO timeout for connection #%d!\n");
	}
}

/*======================================
 *	CORE : Socket Sub Function
 *--------------------------------------*/
void set_eof(int fd)
{
	if( session_isActive(fd) )
	{
#ifdef SEND_SHORTLIST
		// Add this socket to the shortlist for eof handling.
		send_shortlist_add_fd(fd);
#endif
		session[fd]->flag.eof = 1;
	}
}

int recv_to_fifo(int fd)
{
	int len;

	if( !session_isActive(fd) )
		return -1;

	len = sRecv(fd, (char *) session[fd]->rdata + session[fd]->rdata_size, (int)RFIFOSPACE(fd), 0);

	if( len == SOCKET_ERROR )
	{//An exception has occured
		if( sErrno != S_EWOULDBLOCK ) {
			//ShowDebug("recv_to_fifo: %s, closing connection #%d\n", error_msg(), fd);
			set_eof(fd);
		}
		return 0;
	}

	if( len == 0 )
	{//Normal connection end.
		set_eof(fd);
		return 0;
	}

	session[fd]->rdata_size += len;
	session[fd]->rdata_tick = last_tick;
#ifdef SHOW_SERVER_STATS
	socket_data_i += len;
	socket_data_qi += len;
	if (!session[fd]->flag.server)
	{
		socket_data_ci += len;
	}
#endif
	return 0;
}

int send_from_fifo(int fd)
{
	int len;

	if( !session_isValid(fd) )
		return -1;

	if( session[fd]->wdata_size == 0 )
		return 0; // nothing to send

	len = sSend(fd, (const char *) session[fd]->wdata, (int)session[fd]->wdata_size, MSG_NOSIGNAL);

	if( len == SOCKET_ERROR )
	{//An exception has occured
		if( sErrno != S_EWOULDBLOCK ) {
			//ShowDebug("send_from_fifo: %s, ending connection #%d\n", error_msg(), fd);
#ifdef SHOW_SERVER_STATS
			socket_data_qo -= session[fd]->wdata_size;
#endif
			session[fd]->wdata_size = 0; //Clear the send queue as we can't send anymore. [Skotlex]
			set_eof(fd);
		}
		return 0;
	}

	if( len > 0 )
	{
		// some data could not be transferred?
		// shift unsent data to the beginning of the queue
		if( (size_t)len < session[fd]->wdata_size )
			memmove(session[fd]->wdata, session[fd]->wdata + len, session[fd]->wdata_size - len);

		session[fd]->wdata_size -= len;
#ifdef SHOW_SERVER_STATS
		socket_data_o += len;
		socket_data_qo -= len;
		if (!session[fd]->flag.server)
		{
			socket_data_co += len;
		}
#endif
	}

	return 0;
}

/// Best effort - there's no warranty that the data will be sent.
void flush_fifo(int fd)
{
	if(session[fd] != NULL)
		session[fd]->func_send(fd);
}

void flush_fifos(void)
{
	int i;
	for(i = 1; i < fd_max; i++)
		flush_fifo(i);
}

/*======================================
 *	CORE : Connection functions
 *--------------------------------------*/
int connect_client(int listen_fd)
{
	int fd;
	struct sockaddr_in client_address;
	socklen_t len;

	len = sizeof(client_address);

	fd = sAccept(listen_fd, (struct sockaddr*)&client_address, &len);
	if ( fd == -1 ) {
		ShowError("connect_client: accept failed (%s)!\n", error_msg());
		return -1;
	}
	if( fd == 0 )
	{// reserved
		ShowError("connect_client: Socket #0 is reserved - Please report this!!!\n");
		sClose(fd);
		return -1;
	}
	if( fd >= FD_SETSIZE )
	{// socket number too big
		ShowError("connect_client: New socket #%d is greater than can we handle! Increase the value of FD_SETSIZE (currently %d) for your OS to fix this!\n", fd, FD_SETSIZE);
		sClose(fd);
		return -1;
	}

	setsocketopts(fd,0);
	set_nonblocking(fd, 1);

#ifndef MINICORE
	if( ip_rules && !connect_check(ntohl(client_address.sin_addr.s_addr)) ) {
		do_close(fd);
		return -1;
	}
#endif

	if( fd_max <= fd ) fd_max = fd + 1;
	sFD_SET(fd,&readfds);

	create_session(fd, recv_to_fifo, send_from_fifo, default_func_parse);
	session[fd]->client_addr = ntohl(client_address.sin_addr.s_addr);

	return fd;
}

int make_listen_bind(uint32 ip, uint16 port)
{
	struct sockaddr_in server_address;
	int fd;
	int result;

	fd = sSocket(AF_INET, SOCK_STREAM, 0);

	if( fd == -1 )
	{
		ShowError("make_listen_bind: socket creation failed (%s)!\n", error_msg());
		exit(EXIT_FAILURE);
	}
	if( fd == 0 )
	{// reserved
		ShowError("make_listen_bind: Socket #0 is reserved - Please report this!!!\n");
		sClose(fd);
		return -1;
	}
	if( fd >= FD_SETSIZE )
	{// socket number too big
		ShowError("make_listen_bind: New socket #%d is greater than can we handle! Increase the value of FD_SETSIZE (currently %d) for your OS to fix this!\n", fd, FD_SETSIZE);
		sClose(fd);
		return -1;
	}

	setsocketopts(fd,0);
	set_nonblocking(fd, 1);

	server_address.sin_family      = AF_INET;
	server_address.sin_addr.s_addr = htonl(ip);
	server_address.sin_port        = htons(port);

	result = sBind(fd, (struct sockaddr*)&server_address, sizeof(server_address));
	if( result == SOCKET_ERROR ) {
		ShowError("make_listen_bind: bind failed (socket #%d, %s)!\n", fd, error_msg());
		exit(EXIT_FAILURE);
	}
	result = sListen(fd,5);
	if( result == SOCKET_ERROR ) {
		ShowError("make_listen_bind: listen failed (socket #%d, %s)!\n", fd, error_msg());
		exit(EXIT_FAILURE);
	}

	if(fd_max <= fd) fd_max = fd + 1;
	sFD_SET(fd, &readfds);

	create_session(fd, connect_client, null_send, null_parse);
	session[fd]->client_addr = 0; // just listens
	session[fd]->rdata_tick = 0; // disable timeouts on this socket

	return fd;
}

int make_connection(uint32 ip, uint16 port, bool silent,int timeout) {
	struct sockaddr_in remote_address;
	int fd;
	int result;

	fd = sSocket(AF_INET, SOCK_STREAM, 0);

	if (fd == -1) {
		ShowError("make_connection: socket creation failed (%s)!\n", error_msg());
		return -1;
	}
	if( fd == 0 )
	{// reserved
		ShowError("make_connection: Socket #0 is reserved - Please report this!!!\n");
		sClose(fd);
		return -1;
	}
	if( fd >= FD_SETSIZE )
	{// socket number too big
		ShowError("make_connection: New socket #%d is greater than can we handle! Increase the value of FD_SETSIZE (currently %d) for your OS to fix this!\n", fd, FD_SETSIZE);
		sClose(fd);
		return -1;
	}

	setsocketopts(fd,timeout);

	remote_address.sin_family      = AF_INET;
	remote_address.sin_addr.s_addr = htonl(ip);
	remote_address.sin_port        = htons(port);

	if( !silent )
		ShowStatus("Connecting to %d.%d.%d.%d:%i\n", CONVIP(ip), port);
#ifdef WIN32
	// On Windows we have to set the socket non-blocking before the connection to make timeout work. [Lemongrass]
	set_nonblocking(fd, 1);

	result = sConnect(fd, (struct sockaddr *)(&remote_address), sizeof(struct sockaddr_in));

	// Only enter if a socket error occurred
	// Create a pseudo scope to be able to break out in case of successful connection
	while( result == SOCKET_ERROR ) {
		// Specially handle the error number for connection attempts that would block, because we want to use a timeout
		if( sErrno == S_EWOULDBLOCK ){
			fd_set writeSet;
			struct timeval tv;

			sFD_ZERO(&writeSet);
			sFD_SET(fd,&writeSet);

			tv.tv_sec = timeout;
			tv.tv_usec = 0;

			result = sSelect(0, NULL, &writeSet, NULL, &tv);

			// Connection attempt timed out
			if( result == 0 ){
				if( !silent ){
					// Needs special handling, because it does not set an error code and therefore does not provide an error message from the API
					ShowError("make_connection: connection failed (socket #%d, timeout after %ds)!\n", fd, timeout);
				}

				do_close(fd);
				return -1;
			// If the select operation did not return an error
			}else if( result != SOCKET_ERROR ){
				// Check if it is really writeable
				if( sFD_ISSET(fd, &writeSet) != 0 ){
					// Our socket is writeable now => we have connected successfully
					break; // leave the pseudo scope
				}

				if( !silent ){
					// Needs special handling, because it does not set an error code and therefore does not provide an error message from the API
					ShowError("make_connection: connection failed (socket #%d, not writeable)!\n", fd);
				}

				do_close(fd);
				return -1;
			}
			// The select operation failed
		}

		if( !silent )
			ShowError("make_connection: connect failed (socket #%d, %s)!\n", fd, error_msg());

		do_close(fd);
		return -1;
	}
	// Keep the socket in non-blocking mode, since we would set it to non-blocking here on unix. [Lemongrass]
#else
	result = sConnect(fd, (struct sockaddr *)(&remote_address), sizeof(struct sockaddr_in));
	if( result == SOCKET_ERROR ) {
		if( !silent )
			ShowError("make_connection: connect failed (socket #%d, %s)!\n", fd, error_msg());
		do_close(fd);
		return -1;
	}

	//Now the socket can be made non-blocking. [Skotlex]
	set_nonblocking(fd, 1);
#endif

	if (fd_max <= fd) fd_max = fd + 1;
	sFD_SET(fd,&readfds);

	create_session(fd, recv_to_fifo, send_from_fifo, default_func_parse);
	session[fd]->client_addr = ntohl(remote_address.sin_addr.s_addr);

	return fd;
}

static int create_session(int fd, RecvFunc func_recv, SendFunc func_send, ParseFunc func_parse)
{
	CREATE(session[fd], struct socket_data, 1);
	CREATE(session[fd]->rdata, unsigned char, RFIFO_SIZE);
	CREATE(session[fd]->wdata, unsigned char, WFIFO_SIZE);
	session[fd]->max_rdata  = RFIFO_SIZE;
	session[fd]->max_wdata  = WFIFO_SIZE;
	session[fd]->func_recv  = func_recv;
	session[fd]->func_send  = func_send;
	session[fd]->func_parse = func_parse;
	session[fd]->rdata_tick = last_tick;
	return 0;
}

static void delete_session(int fd)
{
	if( session_isValid(fd) )
	{
#ifdef SHOW_SERVER_STATS
		socket_data_qi -= session[fd]->rdata_size - session[fd]->rdata_pos;
		socket_data_qo -= session[fd]->wdata_size;
#endif
		aFree(session[fd]->rdata);
		aFree(session[fd]->wdata);
		aFree(session[fd]->session_data);
		aFree(session[fd]);
		session[fd] = NULL;
	}
}

int realloc_fifo(int fd, unsigned int rfifo_size, unsigned int wfifo_size)
{
	if( !session_isValid(fd) )
		return 0;

	if( session[fd]->max_rdata != rfifo_size && session[fd]->rdata_size < rfifo_size) {
		RECREATE(session[fd]->rdata, unsigned char, rfifo_size);
		session[fd]->max_rdata  = rfifo_size;
	}

	if( session[fd]->max_wdata != wfifo_size && session[fd]->wdata_size < wfifo_size) {
		RECREATE(session[fd]->wdata, unsigned char, wfifo_size);
		session[fd]->max_wdata  = wfifo_size;
	}
	return 0;
}

int realloc_writefifo(int fd, size_t addition)
{
	size_t newsize;

	if( !session_isValid(fd) ) // might not happen
		return 0;

	if( session[fd]->wdata_size + addition  > session[fd]->max_wdata )
	{	// grow rule; grow in multiples of WFIFO_SIZE
		newsize = WFIFO_SIZE;
		while( session[fd]->wdata_size + addition > newsize ) newsize += WFIFO_SIZE;
	}
	else
	if( session[fd]->max_wdata >= (size_t)2*(session[fd]->flag.server?FIFOSIZE_SERVERLINK:WFIFO_SIZE)
		&& (session[fd]->wdata_size+addition)*4 < session[fd]->max_wdata )
	{	// shrink rule, shrink by 2 when only a quarter of the fifo is used, don't shrink below nominal size.
		newsize = session[fd]->max_wdata / 2;
	}
	else // no change
		return 0;

	RECREATE(session[fd]->wdata, unsigned char, newsize);
	session[fd]->max_wdata  = newsize;

	return 0;
}

/// advance the RFIFO cursor (marking 'len' bytes as processed)
int RFIFOSKIP(int fd, size_t len)
{
    struct socket_data *s;

	if ( !session_isActive(fd) )
		return 0;

	s = session[fd];

	if ( s->rdata_size < s->rdata_pos + len ) {
		ShowError("RFIFOSKIP: skipped past end of read buffer! Adjusting from %d to %d (session #%d)\n", len, RFIFOREST(fd), fd);
		len = RFIFOREST(fd);
	}

	s->rdata_pos = s->rdata_pos + len;
#ifdef SHOW_SERVER_STATS
	socket_data_qi -= len;
#endif
	return 0;
}

/// advance the WFIFO cursor (marking 'len' bytes for sending)
int WFIFOSET(int fd, size_t len)
{
	size_t newreserve;
	struct socket_data* s = session[fd];

	if( !session_isValid(fd) || s->wdata == NULL )
		return 0;

	// we have written len bytes to the buffer already before calling WFIFOSET
	if(s->wdata_size+len > s->max_wdata)
	{	// actually there was a buffer overflow already
		uint32 ip = s->client_addr;
		ShowFatalError("WFIFOSET: Write Buffer Overflow. Connection %d (%d.%d.%d.%d) has written %u bytes on a %u/%u bytes buffer.\n", fd, CONVIP(ip), (unsigned int)len, (unsigned int)s->wdata_size, (unsigned int)s->max_wdata);
		ShowDebug("Likely command that caused it: 0x%x\n", (*(uint16*)(s->wdata + s->wdata_size)));
		// no other chance, make a better fifo model
		exit(EXIT_FAILURE);
	}

	if( len > 0xFFFF )
	{
		// dynamic packets allow up to UINT16_MAX bytes (<packet_id>.W <packet_len>.W ...)
		// all known fixed-size packets are within this limit, so use the same limit
		ShowFatalError("WFIFOSET: Packet 0x%x is too big. (len=%u, max=%u)\n", (*(uint16*)(s->wdata + s->wdata_size)), (unsigned int)len, 0xFFFF);
		exit(EXIT_FAILURE);
	}
	else if( len == 0 )
	{
		// abuses the fact, that the code that did WFIFOHEAD(fd,0), already wrote
		// the packet type into memory, even if it could have overwritten vital data
		// this can happen when a new packet was added on map-server, but packet len table was not updated
		ShowWarning("WFIFOSET: Attempted to send zero-length packet, most likely 0x%04x (please report this).\n", WFIFOW(fd,0));
		return 0;
	}

	if( !s->flag.server ) {

		if( len > socket_max_client_packet ) {// see declaration of socket_max_client_packet for details
			ShowError("WFIFOSET: Dropped too large client packet 0x%04x (length=%u, max=%u).\n", WFIFOW(fd,0), len, socket_max_client_packet);
			return 0;
		}

		if( s->wdata_size+len > WFIFO_MAX ) {// reached maximum write fifo size
			ShowError("WFIFOSET: Maximum write buffer size for client connection %d exceeded, most likely caused by packet 0x%04x (len=%u, ip=%lu.%lu.%lu.%lu).\n", fd, WFIFOW(fd,0), len, CONVIP(s->client_addr));
			set_eof(fd);
			return 0;
		}

	}
		// Gepard Shield
	if (is_gepard_active == true)
	{
		gepard_process_packet(fd, s->wdata + s->wdata_size, len, &s->send_crypt);
	}
	// Gepard Shield

	s->wdata_size += len;
#ifdef SHOW_SERVER_STATS
	socket_data_qo += len;
#endif
	//If the interserver has 200% of its normal size full, flush the data.
	if( s->flag.server && s->wdata_size >= 2*FIFOSIZE_SERVERLINK )
		flush_fifo(fd);

	// always keep a WFIFO_SIZE reserve in the buffer
	// For inter-server connections, let the reserve be 1/4th of the link size.
	newreserve = s->flag.server ? FIFOSIZE_SERVERLINK / 4 : WFIFO_SIZE;

	// readjust the buffer to include the chosen reserve
	realloc_writefifo(fd, newreserve);

#ifdef SEND_SHORTLIST
	send_shortlist_add_fd(fd);
#endif

	return 0;
}

int do_sockets(int next)
{
	fd_set rfd;
	struct timeval timeout;
	int ret,i;

	// PRESEND Timers are executed before do_sendrecv and can send packets and/or set sessions to eof.
	// Send remaining data and process client-side disconnects here.
#ifdef SEND_SHORTLIST
	send_shortlist_do_sends();
#else
	for (i = 1; i < fd_max; i++)
	{
		if(!session[i])
			continue;

		if(session[i]->wdata_size)
			session[i]->func_send(i);
	}
#endif

	// can timeout until the next tick
	timeout.tv_sec  = next/1000;
	timeout.tv_usec = next%1000*1000;

	memcpy(&rfd, &readfds, sizeof(rfd));
	ret = sSelect(fd_max, &rfd, NULL, NULL, &timeout);

	if( ret == SOCKET_ERROR )
	{
		if( sErrno != S_EINTR )
		{
			ShowFatalError("do_sockets: select() failed, %s!\n", error_msg());
			exit(EXIT_FAILURE);
		}
		return 0; // interrupted by a signal, just loop and try again
	}

	last_tick = time(NULL);

#if defined(WIN32)
	// on windows, enumerating all members of the fd_set is way faster if we access the internals
	for( i = 0; i < (int)rfd.fd_count; ++i )
	{
		int fd = sock2fd(rfd.fd_array[i]);
		if( session[fd] )
			session[fd]->func_recv(fd);
	}
#else
	// otherwise assume that the fd_set is a bit-array and enumerate it in a standard way
	for( i = 1; ret && i < fd_max; ++i )
	{
		if(sFD_ISSET(i,&rfd) && session[i])
		{
			session[i]->func_recv(i);
			--ret;
		}
	}
#endif

	// POSTSEND Send remaining data and handle eof sessions.
#ifdef SEND_SHORTLIST
	send_shortlist_do_sends();
#else
	for (i = 1; i < fd_max; i++)
	{
		if(!session[i])
			continue;

		if(session[i]->wdata_size)
			session[i]->func_send(i);

		if(session[i]->flag.eof) //func_send can't free a session, this is safe.
		{	//Finally, even if there is no data to parse, connections signalled eof should be closed, so we call parse_func [Skotlex]
			session[i]->func_parse(i); //This should close the session immediately.
		}
	}
#endif

	// parse input data on each socket
	for(i = 1; i < fd_max; i++)
	{
		if(!session[i])
			continue;

		if (session[i]->rdata_tick && DIFF_TICK(last_tick, session[i]->rdata_tick) > stall_time) {
			if( session[i]->flag.server ) {/* server is special */
				if( session[i]->flag.ping != 2 )/* only update if necessary otherwise it'd resend the ping unnecessarily */
					session[i]->flag.ping = 1;
			} else {
				ShowInfo("Session #%d timed out\n", i);
				set_eof(i);
			}
		}

		session[i]->func_parse(i);

		if(!session[i])
			continue;

		// after parse, check client's RFIFO size to know if there is an invalid packet (too big and not parsed)
		if (session[i]->rdata_size == RFIFO_SIZE && session[i]->max_rdata == RFIFO_SIZE) {
			set_eof(i);
			continue;
		}
		RFIFOFLUSH(i);
	}

#ifdef SHOW_SERVER_STATS
	if (last_tick != socket_data_last_tick)
	{
		char buf[1024];
		
		sprintf(buf, "In: %.03f kB/s (%.03f kB/s, Q: %.03f kB) | Out: %.03f kB/s (%.03f kB/s, Q: %.03f kB) | RAM: %.03f MB", socket_data_i/1024., socket_data_ci/1024., socket_data_qi/1024., socket_data_o/1024., socket_data_co/1024., socket_data_qo/1024., malloc_usage()/1024.);
#ifdef _WIN32
		SetConsoleTitle(buf);
#else
		ShowMessage("\033[s\033[1;1H\033[2K%s\033[u", buf);
#endif
		socket_data_last_tick = last_tick;
		socket_data_i = socket_data_ci = 0;
		socket_data_o = socket_data_co = 0;
	}
#endif

	return 0;
}

//////////////////////////////
#ifndef MINICORE
//////////////////////////////
// IP rules and DDoS protection

typedef struct _connect_history {
	struct _connect_history* next;
	uint32 ip;
	uint32 tick;
	int count;
	unsigned ddos : 1;
} ConnectHistory;

typedef struct _access_control {
	uint32 ip;
	uint32 mask;
} AccessControl;

enum _aco {
	ACO_DENY_ALLOW,
	ACO_ALLOW_DENY,
	ACO_MUTUAL_FAILURE
};

static AccessControl* access_allow = NULL;
static AccessControl* access_deny = NULL;
static int access_order    = ACO_DENY_ALLOW;
static int access_allownum = 0;
static int access_denynum  = 0;
static int access_debug    = 0;
static int ddos_count      = 10;
static int ddos_interval   = 3*1000;
static int ddos_autoreset  = 10*60*1000;
/// Connection history, an array of linked lists.
/// The array's index for any ip is ip&0xFFFF
static ConnectHistory* connect_history[0x10000];

static int connect_check_(uint32 ip);

/// Verifies if the IP can connect. (with debug info)
/// @see connect_check_()
static int connect_check(uint32 ip)
{
	int result = connect_check_(ip);
	if( access_debug ) {
		ShowInfo("connect_check: Connection from %d.%d.%d.%d %s\n", CONVIP(ip),result ? "allowed." : "denied!");
	}
	return result;
}

/// Verifies if the IP can connect.
///  0      : Connection Rejected
///  1 or 2 : Connection Accepted
static int connect_check_(uint32 ip)
{
	ConnectHistory* hist = connect_history[ip&0xFFFF];
	int i;
	int is_allowip = 0;
	int is_denyip = 0;
	int connect_ok = 0;

	// Search the allow list
	for( i=0; i < access_allownum; ++i ){
		if( (ip & access_allow[i].mask) == (access_allow[i].ip & access_allow[i].mask) ){
			if( access_debug ){
				ShowInfo("connect_check: Found match from allow list:%d.%d.%d.%d IP:%d.%d.%d.%d Mask:%d.%d.%d.%d\n",
					CONVIP(ip),
					CONVIP(access_allow[i].ip),
					CONVIP(access_allow[i].mask));
			}
			is_allowip = 1;
			break;
		}
	}
	// Search the deny list
	for( i=0; i < access_denynum; ++i ){
		if( (ip & access_deny[i].mask) == (access_deny[i].ip & access_deny[i].mask) ){
			if( access_debug ){
				ShowInfo("connect_check: Found match from deny list:%d.%d.%d.%d IP:%d.%d.%d.%d Mask:%d.%d.%d.%d\n",
					CONVIP(ip),
					CONVIP(access_deny[i].ip),
					CONVIP(access_deny[i].mask));
			}
			is_denyip = 1;
			break;
		}
	}
	// Decide connection status
	//  0 : Reject
	//  1 : Accept
	//  2 : Unconditional Accept (accepts even if flagged as DDoS)
	switch(access_order) {
	case ACO_DENY_ALLOW:
	default:
		if( is_denyip )
			connect_ok = 0; // Reject
		else if( is_allowip )
			connect_ok = 2; // Unconditional Accept
		else
			connect_ok = 1; // Accept
		break;
	case ACO_ALLOW_DENY:
		if( is_allowip )
			connect_ok = 2; // Unconditional Accept
		else if( is_denyip )
			connect_ok = 0; // Reject
		else
			connect_ok = 1; // Accept
		break;
	case ACO_MUTUAL_FAILURE:
		if( is_allowip && !is_denyip )
			connect_ok = 2; // Unconditional Accept
		else
			connect_ok = 0; // Reject
		break;
	}

	// Inspect connection history
	while( hist ) {
		if( ip == hist->ip )
		{// IP found
			if( hist->ddos )
			{// flagged as DDoS
				return (connect_ok == 2 ? 1 : 0);
			} else if( DIFF_TICK(gettick(),hist->tick) < ddos_interval )
			{// connection within ddos_interval
				hist->tick = gettick();
				if( hist->count++ >= ddos_count )
				{// DDoS attack detected
					hist->ddos = 1;
					ShowWarning("connect_check: DDoS Attack detected from %d.%d.%d.%d!\n", CONVIP(ip));
					return (connect_ok == 2 ? 1 : 0);
				}
				return connect_ok;
			} else
			{// not within ddos_interval, clear data
				hist->tick  = gettick();
				hist->count = 0;
				return connect_ok;
			}
		}
		hist = hist->next;
	}
	// IP not found, add to history
	CREATE(hist, ConnectHistory, 1);
	memset(hist, 0, sizeof(ConnectHistory));
	hist->ip   = ip;
	hist->tick = gettick();
	hist->next = connect_history[ip&0xFFFF];
	connect_history[ip&0xFFFF] = hist;
	return connect_ok;
}

/// Timer function.
/// Deletes old connection history records.
static int connect_check_clear(int tid, unsigned int tick, int id, intptr_t data)
{
	int i;
	int clear = 0;
	int list  = 0;
	ConnectHistory root;
	ConnectHistory* prev_hist;
	ConnectHistory* hist;

	for( i=0; i < 0x10000 ; ++i ){
		prev_hist = &root;
		root.next = hist = connect_history[i];
		while( hist ){
			if( (!hist->ddos && DIFF_TICK(tick,hist->tick) > ddos_interval*3) ||
					(hist->ddos && DIFF_TICK(tick,hist->tick) > ddos_autoreset) )
			{// Remove connection history
				prev_hist->next = hist->next;
				aFree(hist);
				hist = prev_hist->next;
				clear++;
			} else {
				prev_hist = hist;
				hist = hist->next;
			}
			list++;
		}
		connect_history[i] = root.next;
	}
	if( access_debug ){
		ShowInfo("connect_check_clear: Cleared %d of %d from IP list.\n", clear, list);
	}
	return list;
}

/// Parses the ip address and mask and puts it into acc.
/// Returns 1 is successful, 0 otherwise.
int access_ipmask(const char* str, AccessControl* acc)
{
	uint32 ip;
	uint32 mask;

	if( strcmp(str,"all") == 0 ) {
		ip   = 0;
		mask = 0;
	} else {
		unsigned int a[4];
		unsigned int m[4];
		int n;
		if( ((n=sscanf(str,"%3u.%3u.%3u.%3u/%3u.%3u.%3u.%3u",a,a+1,a+2,a+3,m,m+1,m+2,m+3)) != 8 && // not an ip + standard mask
				(n=sscanf(str,"%3u.%3u.%3u.%3u/%3u",a,a+1,a+2,a+3,m)) != 5 && // not an ip + bit mask
				(n=sscanf(str,"%3u.%3u.%3u.%3u",a,a+1,a+2,a+3)) != 4 ) || // not an ip
				a[0] > 255 || a[1] > 255 || a[2] > 255 || a[3] > 255 || // invalid ip
				(n == 8 && (m[0] > 255 || m[1] > 255 || m[2] > 255 || m[3] > 255)) || // invalid standard mask
				(n == 5 && m[0] > 32) ){ // invalid bit mask
			return 0;
		}
		ip = MAKEIP(a[0],a[1],a[2],a[3]);
		if( n == 8 )
		{// standard mask
			mask = MAKEIP(m[0],m[1],m[2],m[3]);
		} else if( n == 5 )
		{// bit mask
			mask = 0;
			while( m[0] ){
				mask = (mask >> 1) | 0x80000000;
				--m[0];
			}
		} else
		{// just this ip
			mask = 0xFFFFFFFF;
		}
	}
	if( access_debug ){
		ShowInfo("access_ipmask: Loaded IP:%d.%d.%d.%d mask:%d.%d.%d.%d\n", CONVIP(ip), CONVIP(mask));
	}
	acc->ip   = ip;
	acc->mask = mask;
	return 1;
}
//////////////////////////////
#endif
//////////////////////////////

int socket_config_read(const char* cfgName)
{
	char line[1024],w1[1024],w2[1024];
	FILE *fp;

	fp = fopen(cfgName, "r");
	if(fp == NULL) {
		ShowError("File not found: %s\n", cfgName);
		return 1;
	}

	while(fgets(line, sizeof(line), fp))
	{
		if(line[0] == '/' && line[1] == '/')
			continue;
		if(sscanf(line, "%1023[^:]: %1023[^\r\n]", w1, w2) != 2)
			continue;

		if (!strcmpi(w1, "stall_time")) {
			stall_time = atoi(w2);
			if( stall_time < 3 )
				stall_time = 3;/* a minimum is required to refrain it from killing itself */
		}
#ifndef MINICORE
		else if (!strcmpi(w1, "enable_ip_rules")) {
			ip_rules = config_switch(w2);
		} else if (!strcmpi(w1, "order")) {
			if (!strcmpi(w2, "deny,allow"))
				access_order = ACO_DENY_ALLOW;
			else if (!strcmpi(w2, "allow,deny"))
				access_order = ACO_ALLOW_DENY;
			else if (!strcmpi(w2, "mutual-failure"))
				access_order = ACO_MUTUAL_FAILURE;
		} else if (!strcmpi(w1, "allow")) {
			RECREATE(access_allow, AccessControl, access_allownum+1);
			if (access_ipmask(w2, &access_allow[access_allownum]))
				++access_allownum;
			else
				ShowError("socket_config_read: Invalid ip or ip range '%s'!\n", line);
		} else if (!strcmpi(w1, "deny")) {
			RECREATE(access_deny, AccessControl, access_denynum+1);
			if (access_ipmask(w2, &access_deny[access_denynum]))
				++access_denynum;
			else
				ShowError("socket_config_read: Invalid ip or ip range '%s'!\n", line);
		}
		else if (!strcmpi(w1,"ddos_interval"))
			ddos_interval = atoi(w2);
		else if (!strcmpi(w1,"ddos_count"))
			ddos_count = atoi(w2);
		else if (!strcmpi(w1,"ddos_autoreset"))
			ddos_autoreset = atoi(w2);
		else if (!strcmpi(w1,"debug"))
			access_debug = config_switch(w2);
#endif
		else if (!strcmpi(w1, "import"))
			socket_config_read(w2);
		else
			ShowWarning("Unknown setting '%s' in file %s\n", w1, cfgName);
	}

	fclose(fp);
	return 0;
}


void socket_final(void)
{
	int i;
#ifndef MINICORE
	ConnectHistory* hist;
	ConnectHistory* next_hist;

	for( i=0; i < 0x10000; ++i ){
		hist = connect_history[i];
		while( hist ){
			next_hist = hist->next;
			aFree(hist);
			hist = next_hist;
		}
	}
	if( access_allow )
		aFree(access_allow);
	if( access_deny )
		aFree(access_deny);
#endif

	for( i = 1; i < fd_max; i++ )
		if(session[i])
			do_close(i);

	// session[0]
	aFree(session[0]->rdata);
	aFree(session[0]->wdata);
	aFree(session[0]->session_data);
	aFree(session[0]);
	session[0] = NULL;

#ifdef WIN32
	// Shut down windows networking
	if( WSACleanup() != 0 ){
		ShowError("socket_final: WinSock could not be cleaned up! %s\n", error_msg() );
	}
#endif
}

/// Closes a socket.
void do_close(int fd)
{
	if( fd <= 0 ||fd >= FD_SETSIZE )
		return;// invalid

	flush_fifo(fd); // Try to send what's left (although it might not succeed since it's a nonblocking socket)
	sFD_CLR(fd, &readfds);// this needs to be done before closing the socket
	sShutdown(fd, SHUT_RDWR); // Disallow further reads/writes
	sClose(fd); // We don't really care if these closing functions return an error, we are just shutting down and not reusing this socket.
	if (session[fd]) delete_session(fd);
}

/// Retrieve local ips in host byte order.
/// Uses loopback is no address is found.
int socket_getips(uint32* ips, int max)
{
	int num = 0;

	if( ips == NULL || max <= 0 )
		return 0;

#ifdef WIN32
	{
		char fullhost[255];	

		// XXX This should look up the local IP addresses in the registry
		// instead of calling gethostbyname. However, the way IP addresses
		// are stored in the registry is annoyingly complex, so I'll leave
		// this as T.B.D. [Meruru]
		if( gethostname(fullhost, sizeof(fullhost)) == SOCKET_ERROR )
		{
			ShowError("socket_getips: No hostname defined!\n");
			return 0;
		}
		else
		{
			u_long** a;
			struct hostent* hent;
			hent = gethostbyname(fullhost);
			if( hent == NULL ){
				ShowError("socket_getips: Cannot resolve our own hostname to an IP address\n");
				return 0;
			}
			a = (u_long**)hent->h_addr_list;
			for( ;num < max && a[num] != NULL; ++num)
				ips[num] = (uint32)ntohl(*a[num]);
		}
	}
#else // not WIN32
	{
		int fd;
		char buf[2*16*sizeof(struct ifreq)];
		struct ifconf ic;
		u_long ad;

		fd = sSocket(AF_INET, SOCK_STREAM, 0);

		memset(buf, 0x00, sizeof(buf));

		// The ioctl call will fail with Invalid Argument if there are more
		// interfaces than will fit in the buffer
		ic.ifc_len = sizeof(buf);
		ic.ifc_buf = buf;
		if( sIoctl(fd, SIOCGIFCONF, &ic) == -1 )
		{
			ShowError("socket_getips: SIOCGIFCONF failed!\n");
			return 0;
		}
		else
		{
			int pos;
			for( pos=0; pos < ic.ifc_len && num < max; )
			{
				struct ifreq* ir = (struct ifreq*)(buf+pos);
				struct sockaddr_in*a = (struct sockaddr_in*) &(ir->ifr_addr);
				if( a->sin_family == AF_INET ){
					ad = ntohl(a->sin_addr.s_addr);
					if( ad != INADDR_LOOPBACK && ad != INADDR_ANY )
						ips[num++] = (uint32)ad;
				}
	#if (defined(BSD) && BSD >= 199103) || defined(_AIX) || defined(__APPLE__)
				pos += ir->ifr_addr.sa_len + sizeof(ir->ifr_name);
	#else// not AIX or APPLE
				pos += sizeof(struct ifreq);
	#endif//not AIX or APPLE
			}
		}
		sClose(fd);
	}
#endif // not W32

	// Use loopback if no ips are found
	if( num == 0 )
		ips[num++] = (uint32)INADDR_LOOPBACK;

	return num;
}

void socket_init(void)
{
	char *SOCKET_CONF_FILENAME = "conf/packet_athena.conf";
	unsigned int rlim_cur = FD_SETSIZE;

#ifdef WIN32
	{// Start up windows networking
		WSADATA wsaData;
		WORD wVersionRequested = MAKEWORD(2, 0);
		if( WSAStartup(wVersionRequested, &wsaData) != 0 )
		{
			ShowError("socket_init: WinSock not available!\n");
			return;
		}
		if( LOBYTE(wsaData.wVersion) != 2 || HIBYTE(wsaData.wVersion) != 0 )
		{
			ShowError("socket_init: WinSock version mismatch (2.0 or compatible required)!\n");
			return;
		}
	}
#elif defined(HAVE_SETRLIMIT) && !defined(CYGWIN)
	// NOTE: getrlimit and setrlimit have bogus behaviour in cygwin.
	//       "Number of fds is virtually unlimited in cygwin" (sys/param.h)
	{// set socket limit to FD_SETSIZE
		struct rlimit rlp;
		if( 0 == getrlimit(RLIMIT_NOFILE, &rlp) )
		{
			rlp.rlim_cur = FD_SETSIZE;
			if( 0 != setrlimit(RLIMIT_NOFILE, &rlp) )
			{// failed, try setting the maximum too (permission to change system limits is required)
				rlp.rlim_max = FD_SETSIZE;
				if( 0 != setrlimit(RLIMIT_NOFILE, &rlp) )
				{// failed
					const char *errmsg = error_msg();
					int rlim_ori;
					// set to maximum allowed
					getrlimit(RLIMIT_NOFILE, &rlp);
					rlim_ori = (int)rlp.rlim_cur;
					rlp.rlim_cur = rlp.rlim_max;
					setrlimit(RLIMIT_NOFILE, &rlp);
					// report limit
					getrlimit(RLIMIT_NOFILE, &rlp);
					rlim_cur = rlp.rlim_cur;
					ShowWarning("socket_init: failed to set socket limit to %d, setting to maximum allowed (original limit=%d, current limit=%d, maximum allowed=%d, %s).\n", FD_SETSIZE, rlim_ori, (int)rlp.rlim_cur, (int)rlp.rlim_max, errmsg);
				}
			}
		}
	}
#endif

	// Get initial local ips
	naddr_ = socket_getips(addr_,16);

	sFD_ZERO(&readfds);
#if defined(SEND_SHORTLIST)
	memset(send_shortlist_set, 0, sizeof(send_shortlist_set));
#endif

	socket_config_read(SOCKET_CONF_FILENAME);
		// Gepard Shield
	gepard_config_read();
	// Gepard Shield

	// initialise last send-receive tick
	last_tick = time(NULL);

	// session[0] is now currently used for disconnected sessions of the map server, and as such,
	// should hold enough buffer (it is a vacuum so to speak) as it is never flushed. [Skotlex]
	create_session(0, null_recv, null_send, null_parse); //FIXME this is causing leak

#ifndef MINICORE
	// Delete old connection history every 5 minutes
	memset(connect_history, 0, sizeof(connect_history));
	add_timer_func_list(connect_check_clear, "connect_check_clear");
	add_timer_interval(gettick()+1000, connect_check_clear, 0, 0, 5*60*1000);
#endif

	ShowInfo("Server supports up to '"CL_WHITE"%u"CL_RESET"' concurrent connections.\n", rlim_cur);
}


bool session_isValid(int fd)
{
	return ( fd > 0 && fd < FD_SETSIZE && session[fd] != NULL );
}

bool session_isActive(int fd)
{
	return ( session_isValid(fd) && !session[fd]->flag.eof );
}

// Resolves hostname into a numeric ip.
uint32 host2ip(const char* hostname)
{
	struct hostent* h = gethostbyname(hostname);
	return (h != NULL) ? ntohl(*(uint32*)h->h_addr) : 0;
}

// Converts a numeric ip into a dot-formatted string.
// Result is placed either into a user-provided buffer or a static system buffer.
const char* ip2str(uint32 ip, char ip_str[16])
{
	struct in_addr addr;
	addr.s_addr = htonl(ip);
	return (ip_str == NULL) ? inet_ntoa(addr) : strncpy(ip_str, inet_ntoa(addr), 16);
}

// Converts a dot-formatted ip string into a numeric ip.
uint32 str2ip(const char* ip_str)
{
	return ntohl(inet_addr(ip_str));
}

// Reorders bytes from network to little endian (Windows).
// Neccessary for sending port numbers to the RO client until Gravity notices that they forgot ntohs() calls.
uint16 ntows(uint16 netshort)
{
	return ((netshort & 0xFF) << 8) | ((netshort & 0xFF00) >> 8);
}

#ifdef SEND_SHORTLIST
// Add a fd to the shortlist so that it'll be recognized as a fd that needs
// sending or eof handling.
void send_shortlist_add_fd(int fd)
{
	int i;
	int bit;

	if( !session_isValid(fd) )
		return;// out of range

	i = fd/32;
	bit = fd%32;

	if( (send_shortlist_set[i]>>bit)&1 )
		return;// already in the list

	if( send_shortlist_count >= ARRAYLENGTH(send_shortlist_array) )
	{
		ShowDebug("send_shortlist_add_fd: shortlist is full, ignoring... (fd=%d shortlist.count=%d shortlist.length=%d)\n", fd, send_shortlist_count, ARRAYLENGTH(send_shortlist_array));
		return;
	}

	// set the bit
	send_shortlist_set[i] |= 1<<bit;
	// Add to the end of the shortlist array.
	send_shortlist_array[send_shortlist_count++] = fd;
}

// Do pending network sends and eof handling from the shortlist.
void send_shortlist_do_sends()
{
	int i;

	for( i = send_shortlist_count-1; i >= 0; --i )
	{
		int fd = send_shortlist_array[i];
		int idx = fd/32;
		int bit = fd%32;

		// Remove fd from shortlist, move the last fd to the current position
		--send_shortlist_count;
		send_shortlist_array[i] = send_shortlist_array[send_shortlist_count];
		send_shortlist_array[send_shortlist_count] = 0;

		if( fd <= 0 || fd >= FD_SETSIZE )
		{
			ShowDebug("send_shortlist_do_sends: fd is out of range, corrupted memory? (fd=%d)\n", fd);
			continue;
		}
		if( ((send_shortlist_set[idx]>>bit)&1) == 0 )
		{
			ShowDebug("send_shortlist_do_sends: fd is not set, why is it in the shortlist? (fd=%d)\n", fd);
			continue;
		}
		send_shortlist_set[idx]&=~(1<<bit);// unset fd
		// If this session still exists, perform send operations on it and
		// check for the eof state.
		if( session[fd] )
		{
			// Send data
			if( session[fd]->wdata_size )
				session[fd]->func_send(fd);

			// If it's been marked as eof, call the parse func on it so that
			// the socket will be immediately closed.
			if( session[fd]->flag.eof )
				session[fd]->func_parse(fd);

			// If the session still exists, is not eof and has things left to
			// be sent from it we'll re-add it to the shortlist.
			if( session[fd] && !session[fd]->flag.eof && session[fd]->wdata_size )
				send_shortlist_add_fd(fd);
		}
	}
}
#endif

bool is_gepard_active;
uint32 gepard_rand_seed;
uint32 min_allowed_gepard_version;

const unsigned char* shield_matrix = (const unsigned char*)

	"\x4e\x09\x49\xbc\x71\x76\xd6\x8e\x9b\x61\xee\xe5\xa8\x9a\x41\x97"
	"\x36\xc1\x41\x89\x04\x78\xa6\x0d\x7d\x17\xd0\x7a\x7d\x36\x4e\xea"
	"\x1f\xf9\xf3\xc3\x3d\xfe\x40\x69\xdc\xd1\xeb\xc9\xae\xcb\x75\x10"
	"\xe9\xc3\x0b\x40\x9f\xf4\x08\x87\x54\x74\x7c\xec\x75\xa5\x7b\xcf"
	"\x01\x15\x8c\xbf\xed\x09\x14\xb6\x32\x49\x87\xb2\x71\xdc\x3c\xa9"
	"\xa8\x52\xab\x22\xf6\xc0\xfa\xca\x46\x14\xa3\xa7\x76\x66\xfb\xe5"
	"\xcf\x63\x17\xc5\xe8\x05\x24\xa4\x33\x24\x4a\xb1\x5f\x25\xb7\x21"
	"\xe0\x40\xc9\xf4\x21\xb4\x14\x41\xbb\xdf\x2b\x94\xde\xf6\x73\x61"
	"\x8e\x81\x5b\x1c\xf7\xb5\x43\x52\x97\x56\xfa\x8a\xca\x4b\x8c\x25"
	"\x26\xf3\xcf\x03\x98\x7f\xe8\x46\x3f\xd2\x40\xd0\xf2\x2b\x09\xec"
	"\x60\xa1\xe5\xbd\xc8\x33\x4c\x58\x3f\xe5\xa7\x37\x6b\xce\x65\x57"
	"\xae\x69\xea\x3d\xbc\xa2\x15\x28\x03\x7d\x51\x30\xdc\x29\xe8\xa5"
	"\x8e\x88\x06\xdb\xea\xe8\x1a\xc0\x2a\xec\x21\xe2\xd9\xfd\x70\xd0"
	"\x55\x30\x0d\xee\xd2\x73\xb5\xac\xd8\x83\x10\xb8\x28\x6b\xc1\x9a"
	"\x05\x90\x51\x58\x55\x17\x8e\x87\x80\x1a\x7b\x6e\x95\x7e\x5d\x1b"
	"\x99\xeb\xed\x94\x01\x9c\xee\x0c\x38\x1f\xf5\xa5\xc4\xc1\xc8\xd1"
	"\x56\xa5\x1e\xcc\xe1\x51\x0e\x21\x8a\x2e\x13\x6f\x22\xc9\x62\x36"
	"\x1e\x53\x87\x61\x52\x1a\x66\xf0\x3f\x9a\x3d\x64\x07\x4d\xb3\xc4"
	"\x37\x4a\x8a\x81\x4c\x22\x01\xf2\x35\x01\x02\xad\x61\x2c\xbb\x94"
	"\x29\x31\x96\xb8\xb6\x3f\x47\xfb\xac\x57\x64\x18\x28\x85\xbf\x60"
	"\x22\x12\xf5\xf8\xb7\x5d\xd2\xd4\x15\x7c\x2a\xa4\x61\x46\xa3\x1d"
	"\xa6\x65\x9e\xb4\x82\xb1\xbf\xc1\x64\x49\x2e\x17\x45\xb5\xac\x84"
	"\xad\x27\x04\x65\x28\x7b\x77\x97\x5e\x1f\x31\x07\x11\x8c\x5d\xaa"
	"\xa4\xe2\x64\x23\xea\x6b\x83\x4a\xec\xf8\xa4\xec\xdb\xfc\x3d\x88"
	"\xe1\x47\x9c\x2f\x08\xbb\xdf\xfb\xeb\xfa\x7f\x37\x61\xc7\x2e\x8d"
	"\x56\x32\x73\x06\x8c\xb9\xc8\x90\xf4\x81\x8f\x56\xd2\x4c\x39\xb2"
	"\xdf\xc3\xed\xf0\xa3\x57\x87\xb8\x3a\xb5\xc4\xce\x29\x95\xdf\x87"
	"\x13\x6d\x1a\x92\x66\xbd\x49\x05\xcb\x95\x01\x47\x71\x6c\x6c\x42"
	"\x91\x80\xe4\xf9\x2d\x5a\xe9\xf5\x6c\x0a\xed\x1a\xa2\xe6\x40\xcf"
	"\xd5\xc2\xe8\x31\xdd\x6f\x44\x0c\xe3\xf6\xc9\xe5\x65\xf6\xa6\xe6"
	"\x84\x79\x39\x4f\x3a\xa3\x07\x55\x48\x47\x33\x1a\x6b\x7f\x21\x12"
	"\xbc\x78\xb6\x81\x37\x16\x7d\xfd\x55\xfe\x81\x8c\x3d\x5b\xba\x46"
	"\x68\xb8\xe0\x26\x44\xe6\x64\xe4\xb6\x4d\x0d\x03\x87\xf7\x57\xec"
	"\x8b\x63\x1f\xd3\x20\x50\xba\xa5\xdc\x9a\x04\x49\x6f\x5c\x81\x79"
	"\x13\xe1\x97\xec\xa7\x2d\x0b\x2d\xc7\x15\x39\xbd\xdd\xbd\xbd\xf2"
	"\xa7\xef\x7d\x2d\xa6\x8f\x45\x45\xd9\x48\xf0\x60\x52\x90\xd6\x0d"
	"\xfb\x29\x5f\x40\xa6\xd0\x07\xa7\xaa\xa7\xb6\xe5\x36\x12\xb0\xac"
	"\x9d\x9b\xf6\xc8\xbf\x9b\xed\x8d\x51\x9e\x2a\x46\x24\x61\x19\x02"
	"\x42\x57\x7b\xf5\x67\x82\xe8\x41\xb6\xa2\x4d\xcc\xc0\x09\x13\x93"
	"\x1b\x7c\xee\x92\xc1\x8b\x85\x29\x69\xc3\xd7\xa6\x84\x8f\xab\x4e"
	"\xa4\xcb\x73\x14\x71\xc4\x45\xdd\xe6\x39\x84\xf5\x0f\x8b\x49\x96"
	"\x74\xb7\x12\x2c\xe7\xce\x64\xb4\xef\x75\xe3\xdf\x77\x2e\xf8\x5a"
	"\x0a\x75\x13\xd6\xb2\x71\x35\x52\x56\xb1\xaa\x9b\x19\x56\x3e\x9a"
	"\x20\x89\xcc\x6c\xd0\x27\xe4\xbc\x52\x83\x7e\x84\xe5\xa1\xe8\x82"
	"\xf9\x5b\x6d\x2e\x7e\x32\xd4\xe8\xc9\x66\x4f\xa8\x37\xfa\x5f\x74"
	"\x38\x41\x51\xda\x02\xa9\xe4\xc8\x27\xd1\x9a\xda\x1b\x27\x6e\x98"
	"\xa1\x95\xd3\xbc\x87\x88\x45\xdf\xa5\xc5\xc7\x3e\x28\xdc\x1d\x70"
	"\xfb\xc1\x17\xb7\x62\x41\x47\xcf\xa3\xd8\x6f\xdc\x49\x4c\x7b\xe1"
	"\x52\x52\xde\x5a\xe7\x47\xab\xe8\x73\x50\xaf\xb1\x90\x35\xee\xcc"
	"\x4d\x03\x57\x71\x3c\xa9\x72\x3c\xa6\x26\x78\xba\x05\x73\x07\x96"
	"\x80\xd1\x6b\x13\x1f\x96\xaf\x2a\x62\x1e\xe0\x8a\xf3\x91\xcc\x3d"
	"\x35\x8e\x10\x30\x3f\xf5\x52\x70\x2e\xd7\xf3\x55\x44\x54\x0e\x65"
	"\xc4\xea\x19\xa5\x8c\x72\x7d\x3e\xc3\xd8\x7f\x05\xbe\xd1\x35\xe8"
	"\x5e\x85\x84\xcb\x80\x0c\xd3\xbe\x5e\xa3\xe5\x45\x65\x79\x90\x6d"
	"\xdc\x05\x4d\x85\x75\x29\x48\x31\x0d\xbf\x6e\x13\xbe\xab\xa9\xea"
	"\x16\x9b\xb9\xd1\xf4\xa5\xea\xf0\x7f\x50\x94\xd1\x28\xc1\x11\x44"
	"\x29\x9e\xad\xdb\x84\x61\x41\x88\xd8\xa3\x57\x58\x26\xa6\xaf\xd1"
	"\x50\x15\x79\x85\xf8\xd0\x0e\xc1\x7d\xbc\x0c\xfc\xb0\xdf\x17\x72"
	"\xae\xc7\xa8\x02\x46\x10\xa4\xb6\x64\x6b\xa8\xac\x0a\xa0\x51\x20"
	"\x23\x50\x53\xda\x4c\xed\x37\xe0\x67\xd6\x9a\xf6\x09\xd9\x30\xf6"
	"\x17\x28\x6d\x88\x2c\x01\x2c\xa7\x12\x11\x92\x1d\x67\x4a\x9b\x4d"
	"\x4b\xbb\x98\x7c\x92\x34\xe5\x72\xf1\x25\x54\x27\x1b\x0b\xe8\xc0"
	"\xad\x76\x70\xb2\x0c\xd6\x99\x39\xe7\xa4\x89\xea\x9b\x27\xa1\x45"
	"\xa5\x59\xdf\xc5\xd1\xad\x1c\x10\xf4\xbd\x90\x28\x39\xa2\x58\xb5"
	"\xe3\x82\xe9\x78\x1f\x03\xb1\xbd\x0f\x45\x48\x0a\x68\x12\x77\xe5"
	"\xb5\xc1\x82\x4a\x77\x36\xe0\x44\x6c\xcc\xe8\x47\x96\x23\x93\x2f"
	"\x50\x2b\xd5\x05\x02\x4d\xbd\x79\xd5\xab\x4a\xa3\xf4\xb5\xb7\x82"
	"\xa3\x20\x9e\xcf\xd0\x81\x3e\x10\x77\x94\x3d\x89\xcc\xe3\x37\x79"
	"\x29\xe6\x74\x39\x37\x52\x09\x28\xaf\x22\x52\x93\x4b\x94\xfe\xe2"
	"\xb8\xb3\x18\xcd\x13\x15\x43\x65\xdb\xe7\xb1\x22\xd6\x8d\xe2\xd5"
	"\xcd\x3e\xc8\xa6\xa3\x02\x64\x78\xaf\x05\xe4\x6a\xda\x82\xef\x41"
	"\xe3\xce\x93\x73\x55\x49\x04\x2f\xfe\x30\xab\x7f\x96\x22\xba\xf9"
	"\x3e\xcf\x9d\x15\x11\x9f\xa6\x0a\x11\x48\xca\xeb\xf3\x29\xaf\xcc"
	"\x39\xda\xfa\xa1\x12\x4d\x94\x48\xee\x68\xd8\xbc\xcf\x71\x65\x0e"
	"\x9e\x4b\x7c\x80\x2d\x42\xa5\xf4\xb2\x71\x90\x12\x4e\x83\x68\xa8"
	"\x6f\x50\x7d\xee\x28\xa2\x90\xfe\xd9\xa1\xa4\xae\x2b\x24\x8f\xae"
	"\xb7\x77\x36\x19\x08\xd7\xbe\x43\x95\x9b\x0a\x09\x85\xe3\xc7\xea"
	"\x60\xc0\x0d\x24\xdc\x1f\x18\x1a\x15\x7f\x46\x5a\x34\x33\xe7\xee"
	"\xf7\xac\x60\x41\x97\x9d\xd3\x70\x5e\xf4\xc8\x30\x15\x6e\x7e\x21"
	"\x0b\x4d\x5f\xbd\x56\x6b\x4b\xd0\x98\x3b\xb2\x7b\xdb\xef\xa2\xd0"
	"\x6f\xd8\x52\x11\x36\xa8\xc7\x71\x59\x3e\x29\x1e\xe1\x9c\xc3\x47"
	"\x93\x30\xed\xed\x21\x87\xd3\x4d\xfd\x20\xa4\x22\x76\xfa\xf7\x51"
	"\xd2\xfb\x27\x54\x21\x61\x06\xaa\x73\xce\x45\x1a\xb0\x3b\x4f\xd2"
	"\x40\x33\x79\x9b\x2b\xc2\xd8\x32\x87\x8f\x1d\x0a\xbc\x4c\x22\x59"
	"\xfa\x2c\x3f\x8a\xf7\x81\x77\xf7\x3d\x11\x81\x9f\x2d\x6a\x60\x29"
	"\x7b\xb4\x80\xde\xc9\xc4\x0c\x91\x19\xfc\xdc\xef\xca\x2e\x61\xcc"
	"\x65\x94\x40\x66\x42\x1b\x8f\x25\xee\x83\x80\xe1\x65\x9e\x37\xa6"
	"\xd5\xa8\xcc\x06\x32\x86\x9e\x75\x39\xf0\xed\x3e\x21\xbf\xf9\xfe"
	"\xb2\x6e\x91\x50\x68\x90\x42\xf4\xe0\xb8\x2c\x43\xca\xa1\x1b\x18"
	"\x22\x96\x66\x12\x80\x56\xc6\xd7\x94\x07\x18\x31\xa4\x73\x33\xb9"
	"\x28\x8e\xde\xe3\xb6\x1a\x87\x9e\x91\xd4\x32\x5c\x35\x8f\xd3\x43"
	"\xd1\x19\x1b\xb8\xb4\xd4\xc1\xa9\xfa\x71\xed\xbb\x9c\x8f\x58\xba"
	"\xad\x59\x98\x6f\x61\xc3\x5d\xc9\xa2\x94\x83\x7b\x5e\x59\x31\x5e"
	"\x46\x61\x7e\x62\xb2\x78\x4a\xce\x60\x72\xc0\x06\xb5\xaf\xb9\xb1"
	"\xd0\x46\xf2\xf6\xfb\x6d\xc3\x17\x5b\xc5\xd4\x1e\x64\x44\x04\x92"
	"\xfc\x30\x66\xae\xbf\x8b\xa5\x9f\xdc\xe2\x27\xe8\x81\xc2\x2a\x45"
	"\x43\xe4\x66\xb3\x22\x49\xbe\x96\x23\xc8\x9f\xfc\x4a\xe7\x21\x81"
	"\xb6\xdd\x6c\xed\x0a\xab\x9a\xe7\xab\xaf\xfc\xf2\xf2\x0b\x82\x0c"
	"\xd7\x55\xae\x0f\xca\x60\xd6\xcf\x09\x96\x21\x7c\x76\xb2\xe2\x3d"
	"\x5d\x56\xee\xa5\x1f\x4a\x73\x68\x2e\xd7\x62\xe7\xe3\x9f\x9d\x15"
	"\x89\x4d\x4c\x2a\x1e\x0f\x1b\xbb\x3f\x38\x5a\xbb\x32\xe3\xa6\xcb"
	"\xf8\x98\x10\x10\xf1\x2d\x7d\xd2\xe5\xf1\x39\xbd\x10\x6a\x5b\x60"
	"\x74\x96\x02\x56\x20\x84\x98\x48\x1c\x4b\x11\x0a\x2d\x10\xce\xa9"
	"\xba\xb6\x36\x19\xdb\xed\x8c\xd1\x7c\xa3\xa9\x1e\x16\x2c\x1f\x64"
	"\x58\x8c\xd9\x1e\x58\x44\x67\x58\x18\x03\x4d\xeb\x7a\x22\xc0\xc5"
	"\x74\x5a\x8a\xe4\x17\x7a\xf6\x01\x3e\xaa\x1d\xe8\x7d\x75\x50\x88"
	"\x9c\x23\x9f\x3a\xb5\xa6\x9c\xc1\xd2\x25\x5c\x9b\x0e\x55\x65\x81"
	"\x9c\x3c\x7c\xc5\x43\x15\x98\x6e\x99\xd6\xc4\xaf\x2d\x2e\xdb\x2a"
	"\x48\x5d\xe2\x1c\x89\xd6\xd8\x4d\x0c\x0d\x51\x83\xc3\x3a\x2a\xb5"
	"\x4e\x2d\xbe\x48\x62\xd2\x4e\xa0\xa3\x0d\x12\x39\x71\x90\x2f\x9b"
	"\x09\x55\xf7\x66\x87\x54\xb9\x3b\x2c\xa7\xfd\xc4\x5a\x36\x81\x2c"
	"\x49\x10\x45\x28\xdd\x9d\xfb\x0f\x14\xc4\x3d\x7f\x7a\xac\x40\xa0"
	"\x2f\x38\xf6\xef\xcb\x74\xe4\x3c\xbb\x77\xfe\x35\x73\x02\xe1\x25"
	"\xef\x5b\x4c\x58\x01\x34\x07\xa3\x45\x0b\x42\xb2\x5d\x63\x85\xf1"
	"\x30\x48\x3c\x46\x51\x5d\x03\xf5\xe7\x13\x2e\x5b\x16\xaa\x43\xd2"
	"\x49\x9c\x50\x7c\xfa\x27\xdb\xc0\x39\x7f\x5e\xb3\x12\x6d\xfa\xbc"
	"\xa4\xd8\x68\xa7\xfa\x0c\x41\x82\x04\x25\xaf\xf4\xac\x8f\xa4\x5c"
	"\x7f\x70\x94\x6f\x5e\x5c\xe6\xb9\x13\xd6\x95\x9a\x75\x53\xa0\x23"
	"\x49\xd4\xde\x07\x0d\xce\x4f\x71\x85\xeb\xe6\xf2\x84\x67\x86\x5c"
	"\xe3\x8b\x9e\xbd\xa2\x8e\x1d\xd6\x1b\x58\x2f\xb0\xc7\xf5\xf8\x39"
	"\xfe\x39\xc7\x8c\xb2\xca\xe2\x44\x06\x39\xfc\x78\x51\xb9\x6f\xe2"
	"\xe5\x35\x39\x2a\x23\x4a\x74\x53\x3c\xe1\x36\x74\xac\x08\x0d\x89"
	"\x4b\x17\x8f\x94\xf7\x77\xb3\xee\xc3\x72\xdf\xde\x29\xe3\x69\x72"
	"\x1e\xc8\xf1\xa9\x21\x72\x66\xdf\x07\x62\xf8\x18\x2d\x8e\x67\x0e"
	"\x56\x14\x66\xae\x4e\x20\xfe\xdd\xa0\x93\x41\x33\x06\x96\x01\x81"
	"\xc7\xb4\x1b\xe4\xbd\x3c\xf2\x20\xae\x60\x8c\x04\x36\x66\x18\x3a"
	"\xee\x68\xbf\x1c\x8b\x65\x85\xed\x22\xaa\x94\xb3\xc6\x55\xc7\x7c"
	"\x42\x7c\xcb\xbb\x01\x31\x1c\xac\x8c\xf0\x47\xd0\x17\x3c\xb2\x73";

void gepard_config_read()
{
	char* conf_name = "conf/gepard_shield.conf";
	char line[1024], w1[1024], w2[1024];

	FILE* fp = fopen(conf_name, "r");

	is_gepard_active = false;

	if (fp == NULL) 
	{
		ShowError("Gepard configuration file (%s) not found. Shield disabled.\n", conf_name);
		return;
	}

	while(fgets(line, sizeof(line), fp))
	{
		if (line[0] == '/' && line[1] == '/')
			continue;

		if (sscanf(line, "%[^:]: %[^\r\n]", w1, w2) < 2)
			continue;

		if (!strcmpi(w1, "gepard_shield_enabled"))
		{
			is_gepard_active = (bool)config_switch(w2);
		}
	}

	fclose(fp);

	conf_name = "conf/gepard_version.txt";

	if ((fp = fopen(conf_name, "r")) == NULL)
	{
		min_allowed_gepard_version = 0;
		ShowError("Gepard version file (%s) not found.\n", conf_name);
		return;
	}

	fscanf(fp, "%u", &min_allowed_gepard_version);

	fclose(fp);
}

bool gepard_process_packet(int fd, uint8* packet_data, uint32 packet_size, struct gepard_crypt_link* link)
{
	uint16 packet_id = RBUFW(packet_data, 0);

	switch (packet_id)
	{
		case CS_GEPARD_SYNC:
		{
			uint32 control_value;

			if (RFIFOREST(fd) < 6)
			{
				return true;
			}

			gepard_enc_dec(packet_data + 2, packet_data + 2, 4, &session[fd]->sync_crypt);

			control_value = RFIFOL(fd, 2);

			if (control_value == 0xDDCCBBAA)
			{
				session[fd]->gepard_info.sync_tick = gettick();
			}

			RFIFOSKIP(fd, 6);

			return true;
		}
		break;

		case CS_LOGIN_PACKET_1:
		case CS_LOGIN_PACKET_2:
		case CS_LOGIN_PACKET_3:
		case CS_LOGIN_PACKET_4:
		case CS_LOGIN_PACKET_5:
		{
			set_eof(fd);
			return true;
		}
		break;

		case CS_LOGIN_PACKET:
		{
			if (RFIFOREST(fd) < 55)
			{
				return false;
			}

			if (session[fd]->gepard_info.is_init_ack_received == false)
			{
				RFIFOSKIP(fd, RFIFOREST(fd));
				gepard_init(fd, GEPARD_LOGIN);	
				return true;
			}

			gepard_enc_dec(packet_data + 2, packet_data + 2, RFIFOREST(fd) - 2, link);
		}
		break;

		case CS_LOGIN_PACKET_6:
		{
			if (RFIFOREST(fd) < 4 || RFIFOREST(fd) < (packet_size = RBUFW(packet_data, 2)) || packet_size < 4)
			{
				return true;
			}

			if (session[fd]->gepard_info.is_init_ack_received == false)
			{
				RFIFOSKIP(fd, RFIFOREST(fd));
				gepard_init(fd, GEPARD_LOGIN);	
				return true;
			}

			gepard_enc_dec(packet_data + 4, packet_data + 4, RFIFOREST(fd) - 4, link);
		}
		break;

		case CS_WHISPER_TO:
		{
			if (RFIFOREST(fd) < 4 || RFIFOREST(fd) < (packet_size = RBUFW(packet_data, 2)) || packet_size < 4)
			{
				return true;
			}

			gepard_enc_dec(packet_data + 4, packet_data + 4, packet_size - 4, link);
		}
		break;

		case CS_WALK_TO_XY:
		case CS_USE_SKILL_TO_ID:
		case CS_USE_SKILL_TO_POS:
		{
			if (packet_size < 2 || RFIFOREST(fd) < packet_size)
			{
				return true;
			}

			gepard_enc_dec(packet_data + 2, packet_data + 2, packet_size - 2, link);
		}
		break;

		case SC_WHISPER_FROM:
		case SC_SET_UNIT_IDLE:
		case SC_SET_UNIT_WALKING:
		{
			if (&session[fd]->send_crypt != link)
			{
				return true;
			}

			gepard_enc_dec(packet_data + 4, packet_data + 4, packet_size - 4, link);
		}
		break;

		case CS_GEPARD_INIT_ACK:
		{
			uint32 unique_id, unique_id_, shield_ver;

			if (RFIFOREST(fd) < 4 || RFIFOREST(fd) < (packet_size = RFIFOW(fd, 2)))
			{
				return true;
			}

			if (packet_size < 16)
			{
				ShowWarning("gepard_process_packet: invalid size of CS_GEPARD_INIT_ACK packet: %u\n", packet_size);
				set_eof(fd);
				return true;
			}

			gepard_enc_dec(packet_data + 4, packet_data + 4, packet_size - 4, link);

			unique_id  = RFIFOL(fd, 4);
			shield_ver = RFIFOL(fd, 8);
			unique_id_ = RFIFOL(fd, 12) ^ UNIQUE_ID_XOR;

			RFIFOSKIP(fd, packet_size);

			if (!unique_id || !unique_id_ || unique_id != unique_id_)
			{
				WFIFOHEAD(fd, 6);
				WFIFOW(fd, 0) = SC_GEPARD_INFO;
				WFIFOL(fd, 2) = 3;
				WFIFOSET(fd, 6);
				set_eof(fd);
			}

			session[fd]->gepard_info.is_init_ack_received = true;
			session[fd]->gepard_info.unique_id = unique_id;
			session[fd]->gepard_info.gepard_shield_version = shield_ver;

			return true;
		}
		break;
	}

	return false;
}

inline void gepard_srand(unsigned int seed)
{
	gepard_rand_seed = seed;
}

inline unsigned int gepard_rand()
{
	return (((gepard_rand_seed = gepard_rand_seed * 214013L + 2531011L) >> 16) & 0x7fff);
}

void gepard_session_init(int fd, unsigned int recv_key, unsigned int send_key, unsigned int sync_key)
{
	uint32 i;
	uint8 random_1 = RAND_1_START;
	uint8 random_2 = RAND_2_START;

	session[fd]->recv_crypt.pos_1 = session[fd]->send_crypt.pos_1 = session[fd]->sync_crypt.pos_1 = POS_1_START;
	session[fd]->recv_crypt.pos_2 = session[fd]->send_crypt.pos_2 = session[fd]->sync_crypt.pos_2 = POS_2_START;
	session[fd]->recv_crypt.pos_3 = session[fd]->send_crypt.pos_3 = session[fd]->sync_crypt.pos_3 = 0;

	gepard_srand(recv_key ^ SRAND_CONST);

	for (i = 0; i < (KEY_SIZE-1); ++i)
	{
		random_1 ^= shield_matrix[gepard_rand() % (MATRIX_SIZE-1)];
		random_1 += (9 * random_2) + 2;
		random_2 ^= shield_matrix[gepard_rand() % (MATRIX_SIZE-1)];
		random_2 += (3 * random_1) + 7;
		random_1 += random_2 ^ shield_matrix[gepard_rand() % (MATRIX_SIZE-1)];
		session[fd]->recv_crypt.key[i] = random_1;
	}

	random_1 = RAND_1_START;
	random_2 = RAND_2_START;	
	gepard_srand(send_key | SRAND_CONST);

	for (i = 0; i < (KEY_SIZE-1); ++i)
	{
		random_1 ^= shield_matrix[gepard_rand() % (MATRIX_SIZE-1)];
		random_1 += (4 * random_2) - 5;
		random_2 ^= shield_matrix[gepard_rand() % (MATRIX_SIZE-1)];
		random_2 -= (5 * random_1) - 8;
		random_1 += random_2 ^ shield_matrix[gepard_rand() % (MATRIX_SIZE-1)];
		session[fd]->send_crypt.key[i] = random_1;
	}

	random_1 = RAND_1_START;
	random_2 = RAND_2_START;	
	gepard_srand(sync_key | SRAND_CONST);

	for (i = 0; i < (KEY_SIZE-1); ++i)
	{
		random_1 ^= shield_matrix[gepard_rand() % (MATRIX_SIZE-1)];
		random_1 += (7 * random_2) - 6;
		random_2 ^= shield_matrix[gepard_rand() % (MATRIX_SIZE-1)];
		random_2 -= (7 * random_1) - 8;
		random_1 += random_2 ^ shield_matrix[gepard_rand() % (MATRIX_SIZE-1)];
		session[fd]->sync_crypt.key[i] = random_1;
	}
}

void gepard_init(int fd, uint16 server_type)
{
	const uint16 init_packet_size = 20;
	uint16 recv_key = (gepard_rand() % 0xFFFF);
	uint16 send_key = (gepard_rand() % 0xFFFF);
	uint16 sync_key = (gepard_rand() % 0xFFFF);

	gepard_srand((unsigned)time(NULL) ^ clock());

	WFIFOHEAD(fd, init_packet_size);
	WFIFOW(fd, 0) = SC_GEPARD_INIT;
	WFIFOW(fd, 2) = init_packet_size;
	WFIFOW(fd, 4) = recv_key;
	WFIFOW(fd, 6) = send_key;
	WFIFOW(fd, 8) = server_type;
	WFIFOL(fd, 10) = GEPARD_ID;
	WFIFOL(fd, 14) = min_allowed_gepard_version;
	WFIFOW(fd, 18) = sync_key;
	WFIFOSET(fd, init_packet_size);

	gepard_session_init(fd, recv_key, send_key, sync_key);
}

void gepard_enc_dec(uint8* in_data, uint8* out_data, uint32 data_size, struct gepard_crypt_link* link)
{	
	uint32 i;

	for(i = 0; i < data_size; ++i)
	{
		link->pos_1 += link->key[link->pos_3 % (KEY_SIZE-1)];
		link->pos_2 += (51 + link->pos_1) / 6;
		link->key[link->pos_2 % (KEY_SIZE-1)] ^= link->pos_1;
		link->pos_1 -= (link->pos_2 + link->pos_3) * 7;
		link->key[link->pos_3 % (KEY_SIZE-1)] ^= link->pos_1;
		out_data[i] = in_data[i] ^ link->pos_1;
		link->pos_1 += 19;
		link->pos_2 -= data_size % 0xFF;
		link->pos_3++;
	}
}

void gepard_send_info(int fd, unsigned short info_type, char* message)
{
	int message_len = strlen(message) + 1;
	int packet_len = 2 + 2 + 2 + message_len;

	WFIFOHEAD(fd, packet_len);
	WFIFOW(fd, 0) = SC_GEPARD_INFO;
	WFIFOW(fd, 2) = packet_len;
	WFIFOW(fd, 4) = info_type;
	safestrncpy((char*)WFIFOP(fd, 6), message, message_len);
	WFIFOSET(fd, packet_len);
}
