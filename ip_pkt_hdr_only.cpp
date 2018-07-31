/*********************************************
 * ippkthdronly.cpp
 * Author: kamuszhou@tencent.com kamuszhou@qq.com
 * website: v.qq.com  http://blog.ykyi.net
 * Created on: 28 Mar, 2014
 * Praise Be to the Lord. BUG-FREE CODE !
 ********************************************/

#include "ip_pkt_hdr_only.h"

ip_pkt_hdr_only::ip_pkt_hdr_only()
{
}

ip_pkt_hdr_only::ip_pkt_hdr_only(const char* pkt)
{
	cp(pkt);
}

ip_pkt_hdr_only::~ip_pkt_hdr_only()
{
}

void ip_pkt_hdr_only::cp(const char* pkt)
{
	int len;

	assert(NULL != pkt);
	ip_packet_parser(pkt);

	len = iphdr_len + tcphdr_len;

	_pkt.reset(new char[len]);
	memcpy((char*)_pkt.get(), pkt, len);
	warm_up();
	_send_counter = 0;
	_send_me_pls = true;
}
