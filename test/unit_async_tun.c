#include "tayga.h"
#include "experimental_io.h"
#include <assert.h>
#include <sys/socket.h>
struct config gcfg;
int main(void)
{
	gcfg.workers=0;assert(async_tun_init()==0);async_tun_select(0);
	int fd[2];assert(socketpair(AF_UNIX,SOCK_DGRAM|SOCK_NONBLOCK,0,fd)==0);
	unsigned char bytes[128]={0x45};struct iovec vec[2]={{bytes,64},{bytes+64,64}};
	for(unsigned i=0;i<48;i++){bytes[1]=i;assert(async_tun_submit(fd[0],vec,2)==128);memset(bytes+1,0xee,127);}
	for(unsigned i=0;i<1000 && atomic_load(&async_completed)<48;i++){assert(async_tun_service()==0);usleep(1000);}
	for(unsigned i=0;i<48;i++){unsigned char result[128];assert(recv(fd[1],result,sizeof(result),0)==128);assert(result[1]==i);}
	
	assert(atomic_load(&async_completed)==48 && !atomic_load(&async_errors));
	close(fd[0]);
	assert(async_tun_submit(-1,vec,2)==128);
	assert(async_tun_finish()==-1);
	assert(atomic_load(&async_errors)==1);
	assert(async_tun_submit(-1,vec,2)==-1 && errno==ESHUTDOWN);
	close(fd[1]);async_tun_destroy();return 0;
}
