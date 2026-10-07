/* LD_PRELOAD shim: unprivileged /proc/self/pagemap hides PFNs (reads 0).
 * bf_switchd's DMA pool turns that into physical address 0 and every ilist push fails.
 * In model mode the "physical" address only has to be unique, nonzero and contiguous
 * within a hugepage, so return fake PFN = vpn + FAKE_BASE with the present bit set. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#define FAKE_BASE 0x100000ULL
#define MAXFD 4096
static unsigned char tracked[MAXFD];
static int is_pm(const char *p){return p && !strcmp(p,"/proc/self/pagemap");}
static int track(int fd,const char*p){ if(fd>=0&&fd<MAXFD) tracked[fd]=is_pm(p); return fd;}
int open(const char *p,int f,...){int (*r)(const char*,int,...)=dlsym(RTLD_NEXT,"open");mode_t m=0;if(f&O_CREAT){va_list a;va_start(a,f);m=va_arg(a,mode_t);va_end(a);}return track(r(p,f,m),p);}
int open64(const char *p,int f,...){int (*r)(const char*,int,...)=dlsym(RTLD_NEXT,"open64");mode_t m=0;if(f&O_CREAT){va_list a;va_start(a,f);m=va_arg(a,mode_t);va_end(a);}return track(r(p,f,m),p);}
int openat(int d,const char *p,int f,...){int (*r)(int,const char*,int,...)=dlsym(RTLD_NEXT,"openat");mode_t m=0;if(f&O_CREAT){va_list a;va_start(a,f);m=va_arg(a,mode_t);va_end(a);}return track(r(d,p,f,m),p);}
int openat64(int d,const char *p,int f,...){int (*r)(int,const char*,int,...)=dlsym(RTLD_NEXT,"openat64");mode_t m=0;if(f&O_CREAT){va_list a;va_start(a,f);m=va_arg(a,mode_t);va_end(a);}return track(r(d,p,f,m),p);}
int close(int fd){int (*r)(int)=dlsym(RTLD_NEXT,"close");if(fd>=0&&fd<MAXFD)tracked[fd]=0;return r(fd);}
static void fix(void *buf,ssize_t n,off_t off){
  for(ssize_t i=0;i+8<=n;i+=8){uint64_t v;memcpy(&v,(char*)buf+i,8);
    if((v>>63)&1){uint64_t vpn=(uint64_t)(off+i)/8;v=(1ULL<<63)|(vpn+FAKE_BASE);memcpy((char*)buf+i,&v,8);}}}
ssize_t read(int fd,void*b,size_t c){ssize_t(*r)(int,void*,size_t)=dlsym(RTLD_NEXT,"read");
  if(fd>=0&&fd<MAXFD&&tracked[fd]){off_t o=lseek(fd,0,SEEK_CUR);ssize_t n=r(fd,b,c);if(n>0)fix(b,n,o);return n;}return r(fd,b,c);}
ssize_t pread(int fd,void*b,size_t c,off_t o){ssize_t(*r)(int,void*,size_t,off_t)=dlsym(RTLD_NEXT,"pread");
  ssize_t n=r(fd,b,c,o);if(n>0&&fd>=0&&fd<MAXFD&&tracked[fd])fix(b,n,o);return n;}
ssize_t pread64(int fd,void*b,size_t c,off_t o){ssize_t(*r)(int,void*,size_t,off_t)=dlsym(RTLD_NEXT,"pread64");
  ssize_t n=r(fd,b,c,o);if(n>0&&fd>=0&&fd<MAXFD&&tracked[fd])fix(b,n,o);return n;}
