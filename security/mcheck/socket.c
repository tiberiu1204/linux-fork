#ifndef pr_fmt
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt "\n"
#endif

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/socket.h>
#include <linux/inet.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/wait.h>

#define RET(assertion, code, msg...) \
	do {                         \
		if (assertion) {     \
			pr_err(msg); \
			return code; \
		}                    \
	} while (0)

#define GOTO(assertion, label, msg...) \
	do {                           \
		if (assertion) {       \
			pr_err(msg);   \
			goto label;    \
		}                      \
	} while (0)

/******************************************************************************
 * TCP client structures and callbacks
 ******************************************************************************/

static uint16_t server_port = 9999;
static const char *server_ip = "10.0.2.2";

static struct socket *_tcp_connect(void)
{
	int32_t ans; /* answer         */
	struct sockaddr_in addr; /* server address */
	struct socket *sock; /* TCP socket     */

	ans = sock_create(PF_INET, SOCK_STREAM, IPPROTO_TCP, &sock);
	GOTO(ans < 0, exit, "unable to create TCP socket");

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(server_port);
	ans = in4_pton(server_ip, -1, (uint8_t *)&addr.sin_addr, -1, NULL);
	GOTO(!ans, clean_socket, "unable to parse IP address");

	ans = sock->ops->connect(sock, (struct sockaddr *)&addr, sizeof(addr),
				 O_RDWR);
	if (ans && ans != -EINPROGRESS) {
		goto clean_socket;
	}

	return sock;

clean_socket:
	sock_release(sock);

exit:
	return NULL;
}

static ssize_t __attribute__((unused)) _tcp_send(struct socket *sock, char *buf,
						 size_t len)
{
	struct msghdr msg; /* message                */
	struct kvec vec; /* iov (kernel ptrs only) */
	size_t wb; /* written bytes          */

	memset(&msg, 0, sizeof(msg));
	vec.iov_base = buf;
	vec.iov_len = len;

	do {
		wb = kernel_sendmsg(sock, &msg, &vec, 1, vec.iov_len);
		if (wb == -ERESTARTSYS || wb == -EAGAIN)
			continue;
		RET(wb < 0, -1, "unable to send data (%ld)", wb);

		vec.iov_base += wb;
		vec.iov_len -= wb;
	} while (vec.iov_len);

	return len;
}

static ssize_t __attribute__((unused)) _tcp_recv(struct socket *sock, char *buf,
						 size_t len)
{
	struct msghdr msg; /* message                */
	struct kvec vec; /* iov (kernel ptrs only) */
	size_t rb; /* read bytes             */
	ssize_t total_rb = 0; /* total read bytes       */

	memset(&msg, 0, sizeof(msg));
	vec.iov_base = buf;
	vec.iov_len = len;

	do {
		rb = kernel_recvmsg(sock, &msg, &vec, 1, vec.iov_len, 0);
		if (rb == -ERESTARTSYS || rb == -EAGAIN)
			continue;
		RET(rb < 0, -1, "unable to receive data (%ld)", rb);

		vec.iov_base += rb;
		vec.iov_len -= rb;
		total_rb += rb;
	} while (!skb_queue_empty(&sock->sk->sk_receive_queue));

	return total_rb;
}

