/*********************************************
 * rawsockpostmann.cpp
 * Author: kamuszhou@tencent.com kamuszhou@qq.com
 * website: v.qq.com  http://blog.ykyi.net
 * Created on: 25 Mar, 2014
 * Praise Be to the Lord. BUG-FREE CODE !
 ********************************************/

#include <boost/make_shared.hpp>
#include "rawsock_postman.h"
#include "configuration.h"

rawsock_postman::rawsock_postman()
{
}

rawsock_postman::~rawsock_postman()
{
}

void rawsock_postman::get_ready4subclass()
{
	const char* err_hint;
	// on level2, sniff datalink package enclosing IP package as playload.
	// failed to capture outgoing packets elicited by incoming pakcets from other machines.
	// it actually works to capture both incoming and outgoing packets if the outgoing
	// pakcets are elicited by packets sent from the same machine.
	// _recv_fd = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_IP));

	// code from tcpcopy, failed to capture outgoing packets.
	// _recv_fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);

	// code from http://www.binarytides.com/packet-sniffer-code-in-c-using-linux-sockets-bsd-part-2/.
	// works for both directions. But ethernet header is also received.
	_recv_fd = socket(AF_PACKET , SOCK_RAW , htons(ETH_P_ALL));

	// failed to capture outgoing packets. ethernet header is received.
	// _recv_fd = socket(AF_PACKET , SOCK_RAW , htons(ETH_P_IP));
	if (-1 == _recv_fd)
	{
		// I'm supprised strerror_r doesn't work. buff is not filled with error infomation.
		// strerror_r(errno, _buff, sizeof(_buff));
		// The mentioned problem above is clear.
		// The GNU-specific strerror_r() returns a pointer to a string containing the error message.
		// This may be either a pointer to a string that the function stores in buf, or a pointer to
		// some (immutable) static string (in which case buf is unused).
		//g_logger.printf("%s\n", _buff);
		perror("socket");
		abort();
	}

	_svr_port = htons(g_configuration.get_dst_port());
	_l2hdr_len = -1;
}

void rawsock_postman::recv_impl()
{
	int ret;
	char* ptr_ippkt;
	uint16_t src_port;

	ret = ::recv(_recv_fd, _buff, sizeof(_buff), 0);

	if (ret <= 0)
	{
		return;
	}

	if (-1 == _l2hdr_len)
	{
		_l2hdr_len = detect_l2head_len(_buff);
		if (-1 == _l2hdr_len)
		{
			std::cerr << "Failed to detect data link level header's length.\n";
			return;
		}
	}

	ptr_ippkt = _buff + _l2hdr_len;
	ip_packet_parser(ptr_ippkt);

	// ignore the truncated package.
	if (ip_tot_len > ret)
	{
		return;
	}

	if (iphdr->protocol != IPPROTO_TCP)
	{
		return;
	}

	if (_svr_port != tcphdr->source)
	{
		return;
	}

	boost::shared_ptr<ip_pkt> pkt = boost::make_shared<ip_pkt>(ptr_ippkt);

	push_recved_ippkt(pkt);
}
