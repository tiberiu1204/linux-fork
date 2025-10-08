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
static const char *server_ip = "127.0.0.1";

static struct socket *_tcp_connect(void)
{
	int32_t ans; /* answer         */
	struct sockaddr_in addr; /* server address */
	struct socket *sock; /* TCP socket     */

	sock = kmalloc(sizeof(*sock), GFP_KERNEL);
	RET(!sock, NULL, "unable to allocate memory for socket");

	ans = sock_create(PF_INET, SOCK_STREAM, IPPROTO_TCP, &sock);
	GOTO(ans < 0, clean_alloc, "unable to create TCP socket");

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(server_port);
	ans = in4_pton(server_ip, -1, (uint8_t *)&addr.sin_addr, -1, NULL);
	GOTO(!ans, clean_socket, "unable to parse IP address");

	ans = sock->ops->connect(sock, (struct sockaddr *)&addr, sizeof(addr),
				 O_RDWR);
	GOTO(ans && ans != -EINPROGRESS, clean_socket, "unable to connect (%d)",
	     ans);

	return sock;

clean_socket:
	sock_release(sock);

clean_alloc:
	kfree(sock);

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
		RET(rb < 0, -1, "unable to send data (%ld)", rb);

		vec.iov_base += rb;
		vec.iov_len -= rb;
		total_rb += rb;
	} while (!skb_queue_empty(&sock->sk->sk_receive_queue));

	return total_rb;
}

/******************************************************************************
 * Cdev structures and callbacks
 ******************************************************************************/

static dev_t dev;
static struct class *dev_class;
static struct cdev cdev;

typedef struct {
	uint8_t *buffer;
	struct socket *socket;
} session_t;

#define BUF_SZ 1024

static int _cdev_open(struct inode *inode, struct file *file)
{
	/* allocate a session structure */
	file->private_data = kmalloc(sizeof(session_t), GFP_KERNEL);
	RET(!file->private_data, -1, "unable to allocate session struct");

	session_t *session = file->private_data;

	/* allocate a buffer for copying user data */
	session->buffer = kmalloc(BUF_SZ, GFP_KERNEL);
	GOTO(!session->buffer, free_session, "unable to allocate buffer");

	/* establish TCP connection */
	session->socket = _tcp_connect();
	GOTO(!session->socket, free_buffer,
	     "unable to establish TCP connection");

	return 0;

	/* error cleanup */
free_buffer:
	kfree(session->buffer);

free_session:
	kfree(session);
	file->private_data = NULL;

	return -1;
}

static int _cdev_release(struct inode *inode, struct file *file)
{
	session_t *session = file->private_data;

	pr_info("skq_queue_empty = %d",
		skb_queue_empty(&session->socket->sk->sk_receive_queue));

	sock_release(session->socket);
	kfree(session->buffer);
	kfree(session);

	return 0;
}

static ssize_t _cdev_write(struct file *file, const char __user *buf,
			   size_t len, loff_t *off)
{
	session_t *session = file->private_data;
	int64_t ans; /* answer        */
	ssize_t wb; /* written bytes */

	len = len > BUF_SZ ? BUF_SZ : len;

	/* copy data from user buffer to kernel buffer */
	ans = copy_from_user(session->buffer, buf, len);
	RET(ans, -1, "unable to read user data");

	/* send data via TCP connection */
	wb = _tcp_send(session->socket, session->buffer, len);
	RET(wb == -1, -1, "unable to send data");

	return wb;
}

static ssize_t _cdev_read(struct file *file, char __user *buf, size_t len,
			  loff_t *off)
{
	session_t *session = file->private_data;
	int64_t ans; /* answer     */
	ssize_t rb; /* read bytes */

	len = len > BUF_SZ ? BUF_SZ : len;

	/* receive data via TCP connection */
	rb = _tcp_recv(session->socket, session->buffer, len);
	RET(rb == -1, -1, "unable to receive data");

	/* copy data from kernel buffer to user buffer */
	ans = copy_to_user(buf, session->buffer, len);
	RET(ans, -1, "unable to write user data");

	return rb;
}

static struct file_operations fops = {
	.owner = THIS_MODULE,
	.open = _cdev_open,
	.release = _cdev_release,
	.read = _cdev_read,
	.write = _cdev_write,
};

/******************************************************************************
 * Module (de)initialization
 ******************************************************************************/

static int __init test_init(void)
{
	int32_t ans; /* answer         */
	struct device *dev_ans; /* created device */

	/* create a device in /dev */
	ans = alloc_chrdev_region(&dev, 0, 1, KBUILD_MODNAME);
	RET(ans < 0, -1, "unable to allocate mior (%d)", ans);

	cdev_init(&cdev, &fops);

	ans = cdev_add(&cdev, dev, 1);

	dev_class = class_create(KBUILD_MODNAME);
	GOTO(IS_ERR(dev_class), clean_cdev, "unable to create class");

	dev_ans = device_create(dev_class, NULL, dev, NULL, KBUILD_MODNAME);
	GOTO(IS_ERR(dev_ans), clean_class, "unable to create device");

	return 0;

	/* error cleanup */
clean_class:
	class_destroy(dev_class);

clean_cdev:
	cdev_del(&cdev);
	unregister_chrdev_region(dev, 1);

	return -1;
}

static void __exit test_exit(void)
{
	device_destroy(dev_class, dev);
	class_destroy(dev_class);
	cdev_del(&cdev);
	unregister_chrdev_region(dev, 1);
}

module_init(test_init);
module_exit(test_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Kernel socket test module");
