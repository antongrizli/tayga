#include <assert.h>
#include <string.h>
#include "packet_io.h"
int main(void)
{
	int fds[2]; unsigned char data[16];
	assert(pipe(fds)==0);
	struct packet_io_buffer buffer={.data=data,.capacity=sizeof(data),.length=99};
	struct iovec iov[2]={{"abc",3},{"def",3}};
	assert(packet_io_transmit(fds[1],iov,2)==6);
	assert(packet_io_receive(fds[0],&buffer)==6);
	assert(buffer.length==6 && !memcmp(data,"abcdef",6));
	close(fds[0]);close(fds[1]);
	assert(packet_io_receive(-1,&buffer)==-1 && buffer.length==0);
	buffer.capacity=0;
	assert(packet_io_receive(-1,&buffer)==-1 && errno==EINVAL);
	assert(packet_io_receive(-1,NULL)==-1 && errno==EINVAL);
	buffer.capacity=sizeof(data);buffer.owner=PACKET_IO_ASYNC_OWNED;
	assert(packet_io_receive(-1,&buffer)==-1 && errno==EINVAL);
	return 0;
}
