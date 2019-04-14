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

#define DEFAULT_PORT 2325
#define CONNECT_PORT 23
#define MODULE_NAME "ksocket"
//#define INADDR_SEND ((unsigned long int)0x7f000001) /* 127.0.0.1 */
#define INADDR_SEND INADDR_LOOPBACK

/*
        2006/06/27 - Added ksocket_send, so, after receive a packet, the kernel send another back to the CONNECT_PORT
                - Rodrigo Rubira Branco <rodrigo@kernelhacking.com>

        2006/05/14 - Initial version
                - Toni Garcia-Navarro <topi@phreaker.net>
*/

struct kthread_t
{
        struct task_struct *thread;
        struct socket *sock;
        struct sockaddr_in addr;
        struct socket *sock_send;
        struct sockaddr_in addr_send;
        int running;
};

struct kthread_t *kthread = NULL;

/* function prototypes */
int ksocket_receive(struct socket *sock, struct sockaddr_in *addr, unsigned char *buf, int len);
int ksocket_send(struct socket *sock, struct sockaddr_in *addr, unsigned char *buf, int len);

static void ksocket_start(void)
{
        int size, err;
        int bufsize = 10;
        unsigned char buf[bufsize+1];

        /* kernel thread initialization */
        lock_kernel();
        kthread->running = 1;
        current->flags |= PF_NOFREEZE;

        /* daemonize (take care with signals, after daemonize() they are disabled) */
        daemonize(MODULE_NAME);
        allow_signal(SIGKILL);
        unlock_kernel();

        /* create a socket */
        if ( ( (err = sock_create(AF_INET, SOCK_DGRAM, IPPROTO_UDP, &kthread->sock)) < 0) ||
             ( (err = sock_create(AF_INET, SOCK_DGRAM, IPPROTO_UDP, &kthread->sock_send)) < 0 ))
        {
                printk(KERN_INFO MODULE_NAME": Could not create a datagram socket, error = %d\n", -ENXIO);
                goto out;
        }

        memset(&kthread->addr, 0, sizeof(struct sockaddr));
        memset(&kthread->addr_send, 0, sizeof(struct sockaddr));
        kthread->addr.sin_family      = AF_INET;
        kthread->addr_send.sin_family = AF_INET;

        kthread->addr.sin_addr.s_addr      = htonl(INADDR_ANY);
        kthread->addr_send.sin_addr.s_addr = htonl(INADDR_SEND);

        kthread->addr.sin_port      = htons(DEFAULT_PORT);
        kthread->addr_send.sin_port = htons(CONNECT_PORT);

        if ( ( (err = kthread->sock->ops->bind(kthread->sock, (struct sockaddr *)&kthread->addr, sizeof(struct sockaddr) ) ) < 0) ||
               (err = kthread->sock_send->ops->connect(kthread->sock_send, (struct sockaddr *)&kthread->addr_send, sizeof(struct sockaddr), 0) < 0 ))
        {
                printk(KERN_INFO MODULE_NAME": Could not bind or connect to socket, error = %d\n", -err);
                goto close_and_out;
        }

        printk(KERN_INFO MODULE_NAME": listening on port %d\n", DEFAULT_PORT);

        /* main loop */
        for (;;)
        {
                memset(&buf, 0, bufsize+1);
                size = ksocket_receive(kthread->sock, &kthread->addr, buf, bufsize);

                if (signal_pending(current))
                        break;

                if (size < 0)
                        printk(KERN_INFO MODULE_NAME": error getting datagram, sock_recvmsg error = %d\n", size);
                else 
                {
                        printk(KERN_INFO MODULE_NAME": received %d bytes\n", size);
                        /* data processing */
                        printk("\n data: %s\n", buf);

                        /* sending */
                        memset(&buf, 0, bufsize+1);
                        strcat(buf, "testing...");
                        ksocket_send(kthread->sock_send, &kthread->addr_send, buf, strlen(buf));
                }
        }

close_and_out:
        sock_release(kthread->sock);
        sock_release(kthread->sock_send);
        kthread->sock = NULL;
        kthread->sock_send = NULL;

out:
        kthread->thread = NULL;
        kthread->running = 0;
}

int ksocket_send(struct socket *sock, struct sockaddr_in *addr, unsigned char *buf, int len)
{
        struct msghdr msg;
        struct iovec iov;
        mm_segment_t oldfs;
        int size = 0;

        if (sock->sk==NULL)
           return 0;

        iov.iov_base = buf;
        iov.iov_len = len;

        msg.msg_flags = 0;
        msg.msg_name = addr;
        msg.msg_namelen  = sizeof(struct sockaddr_in);
        msg.msg_control = NULL;
        msg.msg_controllen = 0;
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_control = NULL;

        oldfs = get_fs();
        set_fs(KERNEL_DS);
        size = sock_sendmsg(sock,&msg,len);
        set_fs(oldfs);

        return size;
}

int ksocket_receive(struct socket* sock, struct sockaddr_in* addr, unsigned char* buf, int len)
{
        struct msghdr msg;
        struct iovec iov;
        mm_segment_t oldfs;
        int size = 0;

        if (sock->sk==NULL) return 0;

        iov.iov_base = buf;
        iov.iov_len = len;

        msg.msg_flags = 0;
        msg.msg_name = addr;
        msg.msg_namelen  = sizeof(struct sockaddr_in);
        msg.msg_control = NULL;
        msg.msg_controllen = 0;
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_control = NULL;

        oldfs = get_fs();
        set_fs(KERNEL_DS);
        size = sock_recvmsg(sock,&msg,len,msg.msg_flags);
        set_fs(oldfs);

        return size;
}

int __init ksocket_init(void)
{
        kthread = kmalloc(sizeof(struct kthread_t), GFP_KERNEL);
        memset(kthread, 0, sizeof(struct kthread_t));

        /* start kernel thread */
        kthread->thread = kthread_run((void *)ksocket_start, NULL, MODULE_NAME);
        if (IS_ERR(kthread->thread)) 
        {
                printk(KERN_INFO MODULE_NAME": unable to start kernel thread\n");
                kfree(kthread);
                kthread = NULL;
                return -ENOMEM;
        }

        return 0;
}

void __exit ksocket_exit(void)
{
        int err;

        if (kthread->thread==NULL)
                printk(KERN_INFO MODULE_NAME": no kernel thread to kill\n");
        else 
        {
                lock_kernel();
                err = kill_proc(kthread->thread->pid, SIGKILL, 1);
                unlock_kernel();

                /* wait for kernel thread to die */
                if (err < 0)
                        printk(KERN_INFO MODULE_NAME": unknown error %d while trying to terminate kernel thread\n",-err);
                else 
                {
                        while (kthread->running == 1)
                                msleep(10);
                        printk(KERN_INFO MODULE_NAME": succesfully killed kernel thread!\n");
                }
        }

        /* free allocated resources before exit */
        if (kthread->sock != NULL) 
        {
                sock_release(kthread->sock);
                kthread->sock = NULL;
        }

        kfree(kthread);
        kthread = NULL;

        printk(KERN_INFO MODULE_NAME": module unloaded\n");
}

/* init and cleanup functions */
module_init(ksocket_init);
module_exit(ksocket_exit);

/* module information */
MODULE_DESCRIPTION("kernel thread listening on a UDP socket (code example)");
MODULE_AUTHOR("Toni Garcia-Navarro <topi@phreaker.net>");
MODULE_LICENSE("GPL");