#ifndef _PACKET_H
#define _PACKET_H
#include <linux/types.h>
#include <asm/byteorder.h>
#include <linux/socket.h>
#define MAX_PACKET_LEN 4096

/* 4 bytes IP address */
typedef struct ip_address
{
	unsigned char byte1;
	unsigned char byte2;
	unsigned char byte3;
	unsigned char byte4;
}ip_address;

/* IPv4 header */
typedef struct ip_header
{
	unsigned char	ver_ihl;		// Version (4 bits) + Internet header length (4 bits)
	unsigned char	tos;			// Type of service 
	unsigned short tlen;			// Total length 
	unsigned short identification; // Identification
	unsigned short flags_fo;		// Flags (3 bits) + Fragment offset (13 bits)
	unsigned char	ttl;			// Time to live
	unsigned char	proto;			// Protocol
	unsigned short crc;			// Header checksum
	ip_address	saddr;		// Source address
	ip_address	daddr;		// Destination address
	unsigned int	op_pad;			// Option + Padding
}ip_header;

/* UDP header*/
typedef struct udp_header
{
	unsigned short sport;			// Source port
	unsigned short dport;			// Destination port
	unsigned short len;			// Datagram length
	unsigned short crc;			// Checksum
}udp_header;


typedef struct tcp_header {
	unsigned short src_port;
	unsigned short dst_port;
	unsigned int   seq_number;
	unsigned int   ack_number;
	unsigned short offsetandflags;
	unsigned short windows_size;
	unsigned short check_sum;
	unsigned short Urg;
	//option
}tcp_header;

// #include <linux/ip.h> 中定义了这些结构体
//#include <linux/udp.h>
//#include <linux/tcp.h> 

/*
typedef struct iphdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u8	ihl:4,
		version:4;
#elif defined (__BIG_ENDIAN_BITFIELD)
	__u8	version:4,
  		ihl:4;
#else
#error	"Please fix <asm/byteorder.h>"
#endif
	__u8	tos;
	__be16	tot_len;
	__be16	id;
	__be16	frag_off;
	__u8	ttl;
	__u8	protocol;
	__sum16	check;
	__be32	saddr;
	__be32	daddr;
	
}IP_HEADER;

typedef struct tcphdr {
	__be16	source;
	__be16	dest;
	__be32	seq;
	__be32	ack_seq;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u16	res1:4,
		doff:4,
		fin:1,
		syn:1,
		rst:1,
		psh:1,
		ack:1,
		urg:1,
		ece:1,
		cwr:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u16	doff:4,
		res1:4,
		cwr:1,
		ece:1,
		urg:1,
		ack:1,
		psh:1,
		rst:1,
		syn:1,
		fin:1;
#else
#error	"Adjust your <asm/byteorder.h> defines"
#endif
	__be16	window;
	__sum16	check;
	__be16	urg_ptr;
}TCP_HEADER;

typedef struct udphdr {
	__be16	source;
	__be16	dest;
	__be16	len;
	__sum16	check;
}UDP_HDEADR;
*/
#endif