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

//TUNNEL_CLIENT* tc=(TUNNEL_CLIENT*)kmalloc(sizeof(TUNNEL_CLIENT),GFP_KERNEL);
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
 
void printSkb(struct sk_buff* skb){
        printk("sk_buff: len:%d  skb->data_len:%d  truesize:%d head:%0X  data:%0X tail:%d end:%d"
        ,skb->len,skb->data_len,skb->truesize,(skb->head),(skb->data),(skb->tail),(skb->end));
}

unsigned int
my_hook_fun(void* priv, struct sk_buff* skb, const struct nf_hook_state* state)
{
        if(skb->data_len!=0)
        {       
                printk("skb->data_len: %d,skb_linearize!",skb->data_len);
                if(skb_linearize(skb))
                {
                        printk("error line skb\r\n");
                        printk("skb->data_len %d\r\n",skb->data_len);
                        return NF_DROP;
                }
        }
    ip_header* iph ;
    tcp_header* tcph;
    udp_header* udph;
    unsigned short sport=0;
    unsigned short dport=0;
    
    int iph_len=0;
    if( unlikely(!skb) ) {
            return NF_ACCEPT;
    }

    iph =(ip_header*) ip_hdr(skb);
    unsigned char* iph_uc=(unsigned char*)ip_hdr(skb);
    //iph=(ip_header*)skb->network_header; //这样定位iph 会报错，系统会直接崩溃，好像是因为这个header是通过宏来定位，反正有问题

    if( unlikely(!iph) ) {
            return NF_ACCEPT;
    }
    if(likely(iph->saddr.byte1==127||
                iph->saddr.byte1==10||
                iph->saddr.byte1==100||
                iph->saddr.byte1==198
                )){
        return NF_ACCEPT;
    }
    if(likely(iph->proto==IPPROTO_TCP||iph->proto==IPPROTO_UDP)){
        iph_len = (iph->ver_ihl & 0xf) * 4;
        tcph = (tcp_header*)((unsigned char*)iph + iph_len);
        //tcph=(tcp_header*)skb->transport_header;
        int tcpheader_len = ((ntohs((tcph->offsetandflags)) & 0xf000)>>12) * 4;
        unsigned char* tcp_data=(unsigned char*)tcph+tcpheader_len;
        sport=ntohs(tcph->src_port);
        dport=ntohs(tcph->dst_port);

        /*实验过程进程有ssh的22 连接*/
        if(likely(ntohs(tcph->dst_port)==22)){
                return NF_ACCEPT;
        }
        //让所有123的包丢失 模拟防火墙规则
        if(dport==123){
               return NF_DROP; 
        }
        printk(" \n");
        printk(KERN_INFO "type: %d  %d.%d.%d.%d:%d -> %d.%d.%d.%d:%d len:%d\n",
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
        printSkb(skb);
        int payload_local =(int)ntohs(iph->tlen)-32;
        unsigned char* payload=iph_uc+payload_local;
        if(dport==9999||dport==8888){
                /*int i=0;
                for(i=0;i<8;i=i+8){
                        printk("%2X %2X %2X %2X   %2X %2X %2X %2X",
                        payload[i],payload[i+1],payload[i+2],payload[i+3],
                        payload[i+4],payload[i+5],payload[i+6],payload[i+7]);
                }
                */

        }
        printk("payload_local:%d",payload_local);
        //printk( KERN_INFO "payload[0]== %2X &&payload[1]==%2X ",payload[0],payload[1]);
        if(payload[0]==0x11&&payload[1]==0x22){
               iph->tlen=htons(ntohs(iph->tlen)-32);
               //skb_trim(skb,skb->len-32);
               skb->len=skb->len-32;
               skb->tail=skb->tail-32;
               memset(payload,0,32);
               //printk("tail[0]-tail[3]%d %d %d %d    28-31:%d %d %d %d ",
               payload[0],payload[1],payload[2],payload[3],
               payload[28],payload[29],payload[30],payload[31]);
               //skb->tail 和end 在64位操作系统下不是指针而是相对于head的int偏移量，所以不能用来操作数据
               //memset(skb->tail,0,32);

               //skb_trim(skb,skb->len-32);
                if(skb->sk){
                        printk(" skb->sk->sk_rcvbuf:%d",skb->sk->sk_rcvbuf);
                }
                //tcp数据区变短了 所以需要checksum重新计算
                unsigned int* saddr = (unsigned int*)(iph_uc+12);
                unsigned int* daddr = (unsigned int*)(iph_uc+16);
                tcph->check_sum=0;
                //这里开始忘了 吧iph->tlen转化,并且注意这里的iph->tlen是修改过后的
                tcph->check_sum = tcp_checksum((unsigned char*)tcph,ntohs(iph->tlen)-iph_len, saddr, daddr);
                iph->crc=0;
                iph->crc=checksum((unsigned short*)iph,iph_len);
                printk(" iph->tlen:%d",ntohs(iph->tlen));
                printk("pkt_data_len:%d",ntohs(iph->tlen)-iph_len-tcpheader_len);            
                
            }
            printSkb(skb);
        
    }
    return NF_ACCEPT;
 }

static struct nf_hook_ops nfho = {
        .hook           = my_hook_fun,          //hook处理函数
        .pf             = PF_INET,              //协议类型
        .hooknum        = NF_INET_PRE_ROUTING,    //hook注册点
        .priority       = NF_IP_PRI_FIRST,      //优先级
};
 
static void
inProxy_cleanup(void)
{
        nf_unregister_net_hook(&init_net,&nfho);
        printk(KERN_ALERT " un regsiter success!\n");
}
 
static __init int inProxy_init(void)
{
 
        if ( nf_register_net_hook(&init_net,&nfho) != 0 ) {
                printk(KERN_WARNING "register hook error!\n");
                goto err;
        }
        printk(KERN_ALERT " inProxy init success!\n");
        return 0;
 
err:
        inProxy_cleanup();
        return -1;
}
 
static __exit void inProxy_exit(void)
{
        inProxy_cleanup();
        printk(KERN_WARNING "inProxy exit!\n");
}
 
module_init(inProxy_init);
module_exit(inProxy_exit);
MODULE_LICENSE("GPL");