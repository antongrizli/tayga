/* Synchronous reference packet I/O. Borrowed caller storage stays owned by
 * the caller; successful transmit returns after the kernel consumed it.
 * An asynchronous backend must use a distinct interface with completions. */
#ifndef TAYGA_PACKET_IO_H
#define TAYGA_PACKET_IO_H
#include <errno.h>
#include <stddef.h>
#include <unistd.h>
#include <sys/uio.h>
#include <stdint.h>
enum packet_io_owner { PACKET_IO_BORROWED = 0, PACKET_IO_ASYNC_OWNED = 1 };
struct packet_io_buffer {
	unsigned char *data;
	size_t capacity;
	size_t length;
	enum packet_io_owner owner;
	size_t headroom;
	int ingress_fd;
	uint32_t features;
};
static inline ssize_t packet_io_receive(int fd, struct packet_io_buffer *buffer)
{
	if (buffer) buffer->length=0;
	if (!buffer || !buffer->data || !buffer->capacity || buffer->owner != PACKET_IO_BORROWED) {
		errno=EINVAL; return -1;
	}
	ssize_t received=read(fd,buffer->data,buffer->capacity);
	if (received>=0) buffer->length=(size_t)received;
	return received;
}
static inline ssize_t packet_io_transmit(int fd, const struct iovec *iov, int count)
{
	/* A gather operation is one packet, not a multi-packet batching API.
	 * A short/error return retains ownership; the caller decides disposition. */
	return writev(fd,iov,count);
}
#endif
