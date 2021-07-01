#include <linux/init.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_bridge.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/byteorder/generic.h> //ntohs
#include "packet.h"
#include <linux/kernel.h> //sprintf


//这里是short
unsigned short checksum(unsigned short* buffer, int size)
{
	unsigned long int cksum = 0;
	while (size > 1)
	{
		cksum += *buffer++;
		size -= sizeof(unsigned short);
	}
	if (size)
	{
		cksum += *(unsigned char*)buffer;
	}
	cksum = (cksum >> 16) + (cksum & 0xffff);
	cksum += (cksum >> 16);
	return (unsigned short)(~cksum);
}


int tcp_checksum(unsigned char* tcphdr, int tcplen, unsigned int* srcaddr, unsigned int* dstaddr)
{
	unsigned char pseudoheader[12] = { 0 };
	unsigned short check_sum = 0;

	if (tcphdr!= NULL && srcaddr && dstaddr)
	{
		memcpy(&pseudoheader[0], srcaddr, 4);
		memcpy(&pseudoheader[4], dstaddr, 4);
		pseudoheader[8] = 0; /* fill zeors */
		pseudoheader[9] = IPPROTO_TCP;
		memcpy(&pseudoheader[10], &tcplen, 2);

		unsigned char n = pseudoheader[10];
		pseudoheader[10] = pseudoheader[11];
		pseudoheader[11] = n;
		unsigned char* pseudo_tcp_packet = (unsigned char*)kmalloc(tcplen + 12,GFP_KERNEL);
		memcpy(pseudo_tcp_packet, pseudoheader, 12);
		memcpy(pseudo_tcp_packet + 12, tcphdr, tcplen);

		check_sum = checksum((unsigned short*)pseudo_tcp_packet, tcplen + 12);
		kfree(pseudo_tcp_packet);
	}
	return check_sum;
}
unsigned int
my_hook_out_fun(void* priv, struct sk_buff* skb, const struct nf_hook_state* state)
{
    ip_header* iph ;
    tcp_header* tcph;
    udp_header* udph;
    unsigned short sport=0;
    unsigned short dport=0;
    
    int ip_len=0;
    if( unlikely(!skb) ) {
            return NF_ACCEPT;
    }

    iph =(ip_header*) ip_hdr(skb);
    unsigned char* iph_uc=(unsigned char*)ip_hdr(skb);
    if( unlikely(!iph) ) {
            return NF_ACCEPT;
    }

    if(likely(iph->proto==IPPROTO_TCP||iph->proto==IPPROTO_UDP)){
        ip_len = (iph->ver_ihl & 0xf) * 4;
        tcph = (tcp_header*)(iph_uc + ip_len);
        int tcpheader_len = ((ntohs((tcph->offsetandflags)) & 0xf000)>>12) * 4;
        unsigned char* tcp_data=(unsigned char*)tcph+tcpheader_len;

        /*实验过程进程有ssh的22 连接*/
        if(likely(ntohs(tcph->dst_port)==22)){
                return NF_ACCEPT;
        }
        udph = (udp_header*)(iph_uc + ip_len);
        sport=ntohs(tcph->src_port);
        dport=ntohs(tcph->dst_port);

        if(sport==9999){
                        printk(KERN_INFO " out-> type: %d  %d.%d.%d.%d:%d -> %d.%d.%d.%d:%d len:%d\n",
                iph->proto,
                iph->saddr.byte1,
                iph->saddr.byte2,
                iph->saddr.byte3,
                iph->saddr.byte4,
                sport,
                iph->daddr.byte1,
                iph->daddr.byte2,
                iph->daddr.byte3,
                iph->daddr.byte4,
                dport,
                ntohs(iph->tlen)
        );
            unsigned int* saddr = (unsigned int*)(iph_uc+12);
			unsigned int* daddr = (unsigned int*)(iph_uc+16);
            tcph->src_port=htons(123);
            tcph->check_sum=0;
            tcph->check_sum = tcp_checksum((unsigned char*)tcph,ntohs(iph->tlen)-ip_len, saddr, daddr);
            printk(KERN_INFO "*******iph->tlen:%d iph_len:%d tcph_len:%d data_len %d tcp_data:%X %X *****",
            ntohs(iph->tlen),ip_len,tcpheader_len,ntohs(iph->tlen)-ip_len-tcpheader_len,tcp_data[0],tcp_data[1]);
            return NF_ACCEPT;
        }


    }
    return NF_ACCEPT;
 }

static struct nf_hook_ops nfho = {
        .hook           = my_hook_out_fun,          //hook处理函数
        .pf             = PF_INET,              //协议类型
        .hooknum        = NF_INET_LOCAL_OUT,    //hook注册点
        .priority       = NF_IP_PRI_FIRST,      //优先级
};
 
static void
hello_cleanup(void)
{
        nf_unregister_net_hook(&init_net,&nfho);
}
 
static __init int hello_init(void)
{
 
        if ( nf_register_net_hook(&init_net,&nfho) != 0 ) {
                printk(KERN_WARNING "register hook error!\n");
                goto err;
        }
        printk(KERN_ALERT "outProxy init success!\n");
        return 0;
 
err:
        hello_cleanup();
        return -1;
}
 
static __exit void hello_exit(void)
{
        hello_cleanup();
        printk(KERN_WARNING "outProxy exit!\n");
}
 
module_init(hello_init);
module_exit(hello_exit);
MODULE_LICENSE("GPL");