/*********************************************
 * pcap_postman.cpp
 * Author: kamuszhou@tencent.com kamuszhou@qq.com
 * website: v.qq.com  http://blog.ykyi.net
 * Created on: 25 Mar, 2014
 * Praise Be to the Lord. BUG-FREE CODE !
 ********************************************/

#include <boost/lambda/lambda.hpp>
#include "pcap_postman.h"
#include "cute_logger.h"
#include "configuration.h"
#include "ip_pkt_hdr_only.h"

void pcaphandler(unsigned char* user, const pcap_pkthdr* hdr, const unsigned char* bytes)
{
	pcap_postman* postman = reinterpret_cast<pcap_postman*>(user);

	if (!postman->_hdr_only && hdr->caplen < hdr->len)
	{
		postman->_truncated_pkt_count++;
		return;
	}

	const char* ippkt = strip_l2head(postman->_pcap_handle, reinterpret_cast<const char*>(bytes));
	if (NULL == ippkt)
	{
		std::cerr << "Failed to detect the Link Layer header." << std::endl;
		return;
	}

	if (postman->_hdr_only)
	{
		if (hdr->caplen < 14 + 20 + 20)
		{
			postman->_truncated_pkt_count++;
			return;
		}

		ip_packet_parser(ippkt);
		if (hdr->caplen < iphdr_len + tcphdr_len)
		{
			postman->_truncated_pkt_count++;
			return;
		}
	}

	if (!postman->_hdr_only)
	{
		boost::shared_ptr<ip_pkt> pkt = boost::make_shared<ip_pkt>(ippkt);
		postman->push_recved_ippkt(pkt);
	}
	else
	{
		boost::shared_ptr<ip_pkt> pkt = boost::make_shared<ip_pkt_hdr_only>(ippkt);
		postman->push_recved_ippkt(pkt);
	}
}

void pcap_postman::recv_impl()
{
	int n = pcap_dispatch(_pcap_handle, 512, pcaphandler, reinterpret_cast<unsigned char*>(this));
}

pcap_postman::pcap_postman()
{
	_truncated_pkt_count = 0;
	_pcap_handle = NULL;
}

pcap_postman::~pcap_postman()
{
	pcap_breakloop(_pcap_handle);

	if (NULL != _pcap_handle)
	{
		pcap_close(_pcap_handle);
	}
}

void pcap_postman::get_ready4subclass()
{
	std::ostringstream ss;

	assert(0 == _truncated_pkt_count);
	assert(0 == _pcap_handle);

	if (g_configuration.get_lua_scripts_home())
	{
		_hdr_only = false;
		_snaplen = 65535;
	}
	else
	{
		_hdr_only = true;
		_snaplen = 100;
	}

	_pcap_handle = pcap_open_live(NULL, _snaplen, 0, 0, _errbuf);
	if (NULL == _pcap_handle)
	{
		g_logger.printf(_errbuf);
		abort();
	}

	ss << "tcp and src port " << g_configuration.get_dst_port();
	// pcap_compile in some old version of pcap libraries accept the third parameter as char*
	if (-1 == pcap_compile(_pcap_handle, &_filter, (char*)ss.str().c_str(), 0, 0))
	{
		g_logger.printf("%s\n", pcap_geterr(_pcap_handle));
		abort();
	}

	if (-1 == pcap_setfilter(_pcap_handle, &_filter))
	{
		g_logger.printf("Failed to set pcap filter: %s\n", ss.str().c_str());
		pcap_freecode(&_filter);
		abort();
	}

	pcap_freecode(&_filter);

//	_recv_fd = pcap_get_selectable_fd(_pcap_handle);
//	if (_recv_fd == -1)
//	{
//		g_logger.printf("pcap_get_selectable_fd failed.\n");
//		abort();
//	}
//	if (-1 == pcap_setnonblock(_pcap_handle, 1/*nonblock is on*/, _errbuf))
//	{
//		g_logger.printf("%s\n", _errbuf);
//		abort();
//	}
}
