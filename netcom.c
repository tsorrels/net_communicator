#include <linux/module.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/major.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/poll.h>
#include <linux/fcntl.h>
//#include <linux/init.h>
#include <linux/random.h>
#include <linux/kthread.h>

//#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/miscdevice.h>
#include <linux/rtnetlink.h>

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kthread.h>

#include <linux/errno.h>
#include <linux/types.h>

#include <linux/netdevice.h>
#include <linux/ip.h>
#include <linux/in.h>

#include <linux/delay.h>


#define PORT 2325
#define NETCOM_MINOR 177
#define MODULE_NAME "netcom"

#define bufsize 10
unsigned char buf[bufsize];


int message;

struct socket * server_socket;

struct socket * sock_send;
struct sockaddr_in sock_addr;
struct task_struct * server_thread;

int netcom_socket_receive(struct socket * sock, struct sockaddr_in * addr, unsigned char* buf, size_t len);
size_t netcom_sock_send(struct socket * sock, char * buf, size_t len);


static ssize_t netcom_chr_read(struct file * file, char * user_buf, 
			     size_t count, loff_t *pos)
{	
	int num_bytes = bufsize;

	printk(KERN_INFO "netcom: netcom_chr_read message = %d count = %d\n", message, count);

	if (message == 0)
	{
		return 0;
	}

	if (count < bufsize )
	{
		num_bytes = count;
	}
	
	copy_to_user(user_buf, buf, num_bytes);

	message = 0;

	return num_bytes;
}

static ssize_t netcom_chr_write(struct file * file, const char * buf, 
			     size_t count, loff_t *pos)
{	
	printk(KERN_INFO "netcom: netcom_chr_write %d bytes\n", count);

	//if (verify_area(VERIFY_READ, buf, count))
//		return -EFAULT;

	void * kmem = kmalloc(count, GFP_KERNEL);
	if (kmem == NULL)
	{	
		printk(KERN_ERR "netcom: netcom_chr_write kmalloc fail\n");
		return -EFAULT;
	}

	copy_from_user(kmem, buf, count); //+1 to make room for null terminator

	char * kstr = (char *) kmem;
	// kstr[count + 1] = 0; //add null terminator

	printk(KERN_INFO "netcom: message from user -  %s\n", kstr);

	int bytes_sent = netcom_sock_send(sock_send, kstr, count);

	kfree(kmem);

	return bytes_sent;
}

size_t netcom_sock_send(struct socket * sock, char * buf, size_t len)
{
	struct msghdr msg;
	struct iovec iov;
	mm_segment_t oldfs;
	size_t size = 0;

	if (sock->sk == NULL)
		return 0;

	iov.iov_base = buf;
	iov.iov_len = len;
	unsigned long nr_segments = 1;
	size_t count = len;//1;

	iov_iter_init(&msg.msg_iter, READ, &iov, nr_segments, count);

	msg.msg_flags = 0;
	msg.msg_name = &sock_addr;
	msg.msg_namelen  = sizeof(struct sockaddr_in);
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	msg.msg_control = NULL;

	oldfs = get_fs();
	set_fs(KERNEL_DS);
	size = sock_sendmsg(sock, &msg);
	set_fs(oldfs);

	return size;
}

static struct file_operations netcom_fops = {
	owner:	THIS_MODULE,	
	llseek: 0,//	tun_chr_lseek,
	read:	netcom_chr_read,
	write:	netcom_chr_write,
	poll:	0,//tun_chr_poll,
	open:	0,//tun_chr_open,
	release:0,//tun_chr_close,
	fasync:	0//tun_chr_fasync		
};

static struct miscdevice netcom_miscdev =
{
    NETCOM_MINOR,
    "net/com",
    &netcom_fops
};

static void netcom_server_start(void)
{
	int err;
	struct sockaddr_in server_socket_addr;

	int size;

	err = sock_create(AF_INET, SOCK_DGRAM, IPPROTO_UDP, &server_socket);
	if (err < 0)
	{
		printk(KERN_INFO "netcom: Could not create a datagram socket, error = %d\n", -ENXIO);
		goto out;
	}

	server_socket_addr.sin_family = AF_INET;
	server_socket_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	server_socket_addr.sin_port = htons(PORT);

	err = server_socket->ops->bind(server_socket, (struct sockaddr *)&server_socket_addr, sizeof(struct sockaddr));
	if (err < 0)
	{
		printk(KERN_INFO MODULE_NAME"netcom: Could not bind or connect to socket, error = %d\n", -err);
		goto close_and_out;
	}

    printk(KERN_INFO MODULE_NAME"netcom: listening on port %d\n", PORT);

	memset(&buf, 0, bufsize);

	for (;;)
	{
		size = netcom_socket_receive(server_socket, &server_socket_addr, buf, bufsize);

		// if (signal_pending(current))
		// 	break;

		if (size < 0)
			printk(KERN_INFO MODULE_NAME": error getting datagram, sock_recvmsg error = %d\n", size);
		else 
		{
			message = 1;
			printk(KERN_INFO MODULE_NAME": received %d bytes\n", size);
			/* data processing */
			buf[size] = 0; //add null terminator
			printk("\n data: %s\n", buf);

		}
	}

close_and_out:
        sock_release(server_socket);
		server_socket = NULL;
		printk(KERN_INFO MODULE_NAME": close and out\n");
out:
        server_thread = NULL;
		printk(KERN_INFO MODULE_NAME": close and out\n");
}

int netcom_socket_receive(struct socket * sock, struct sockaddr_in * addr, unsigned char* buf, size_t len)
{
        struct msghdr msg;
        struct iovec iov;
        mm_segment_t oldfs;
        int size = 0;

        if (sock->sk==NULL) return 0;


	iov.iov_base = buf;
	iov.iov_len = len;
	unsigned long nr_segments = 1;
	size_t count = len;//1;

	iov_iter_init(&msg.msg_iter, READ, &iov, nr_segments, count);

        msg.msg_flags = 0;
        msg.msg_name = addr;
        msg.msg_namelen  = sizeof(struct sockaddr_in);
        msg.msg_control = NULL;
        msg.msg_controllen = 0;
        msg.msg_control = NULL;

        oldfs = get_fs();
        set_fs(KERNEL_DS);
        size = sock_recvmsg(sock, &msg, msg.msg_flags);
        set_fs(oldfs);

        return size;
}


static int netcom_init(void)
{
	int err = sock_create(AF_INET, SOCK_DGRAM, IPPROTO_UDP, &sock_send);
	if (err < 0)
	{
		printk(KERN_ERR "netcom: Failed to create send socket\n", NETCOM_MINOR);
		return -EIO;
	}

	if (misc_register(&netcom_miscdev)) {
		printk(KERN_ERR "netcom: Can't register misc device %d\n", NETCOM_MINOR);
		return -EIO;
	}

        /* start kernel thread */
	server_thread = kthread_run((void *)netcom_server_start, NULL, MODULE_NAME);
	if (IS_ERR(server_thread))
	{
		printk(KERN_INFO MODULE_NAME": unable to start kernel thread\n");
		kfree(server_thread);
		server_thread = NULL;
		return -ENOMEM;
	}

	message = 0;

	sock_addr.sin_family = AF_INET;
	//sock_addr.sin_addr.s_addr = 29184680425; //127.0.0.1
	sock_addr.sin_addr.s_addr = 0x7f000001; //127.0.0.1	
	//inet_pton(AF_INET, "192.0.2.33", &(sock_addr.sin_addr.s_addr));
	sock_addr.sin_port = htons(PORT);

	printk(KERN_INFO "netcom: registered misc device %d\n", NETCOM_MINOR);

    return 0;
}

static void netcom_exit(void)
{
	/* free allocated resources before exit */
	if (sock_send != NULL) 
	{
        sock_release(sock_send);
    }

	if (server_socket != NULL) 
	{
        sock_release(server_socket);
    }

    printk(KERN_INFO "netcom: de-registered misc device %d\n", NETCOM_MINOR);
	misc_deregister(&netcom_miscdev);  
}   

module_init(netcom_init);
module_exit(netcom_exit);