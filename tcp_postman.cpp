/*********************************************
 * tcppostman.cpp
 * Author: kamuszhou@tencent.com kamuszhou@qq.com
 * website: v.qq.com  http://blog.ykyi.net
 * Created on: 25 Mar, 2014
 * Praise Be to the Lord. BUG-FREE CODE !
 ********************************************/

#include "tcp_postman.h"
#include "configuration.h"
#include "ip_pkt_hdr_only.h"

tcp_postman::tcp_postman()
{
	_listening_fd = -1;
	_conn_fd = -1;
	_buffer_used_len = 0;
}

tcp_postman::~tcp_postman()
{
	if (-1 != _listening_fd)
	{
		close(_listening_fd);
	}

	if (-1 != _conn_fd)
	{
		close(_conn_fd);
	}
}

void tcp_postman::get_ready4subclass()
{
	int opt, ret, flags;
	struct sockaddr_in addr;

	assert(-1 == _listening_fd);
	assert(-1 == _conn_fd);
	assert(0 == _buffer_used_len);

	if (g_configuration.get_lua_scripts_home())
	{
		// capture the whole packet content if test suite is on.
		_hdr_only = false;
	}
	else
	{
		_hdr_only = true;
	}

	_listening_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (_listening_fd == -1)
	{
		perror("socket");
		abort();
	}

	memset(&addr, 0, sizeof(addr));
	addr.sin_port = ntohs(_listening_port);
	addr.sin_family = AF_INET;

	opt = 1;
	ret = setsockopt(_listening_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
	if (ret == -1)
	{
		perror("setsockopt");
		abort();
	}

//	flags = fcntl(_listening_fd, F_GETFL, 0);
//	if (flags < 0)
//	{
//		perror("fcntl");
//		abort();
//	}
//
//	if (fcntl(_listening_fd, F_SETFL, flags|O_NONBLOCK) < 0)
//	{
//		perror("fcntl");
//		abort();
//	}

	if (bind(_listening_fd, (struct sockaddr *)&addr, sizeof(addr)) == -1)
	{
		perror("bind");
		abort();
	}

	if (listen(_listening_fd, 3) == -1)
	{
		perror("listen");
		abort();
	}
}

void tcp_postman::recv_impl()
{
	if (_conn_fd < 0)
	{
		_conn_fd = accept(_listening_fd, NULL, NULL);

		if (_conn_fd > 0)
		{
			_last_recorded_recv_time = g_timer.get_jiffies();
			int flags = fcntl(_conn_fd, F_GETFL, 0);
			if (flags < 0)
			{
				perror("fcntl");
				_conn_fd = -1;
				return;
			}

			if (fcntl(_conn_fd, F_SETFL, flags|O_NONBLOCK) < 0)
			{
				perror("fcntl");
				_conn_fd = -1;
				return;
			}
		}
		else
		{
			perror("accept");
		}
	}

	if (_conn_fd > 0)
	{
		save_peer_response_to_buffer();
	}

	boost::this_thread::sleep(boost::posix_time::milliseconds(1)) ;
}

void tcp_postman::save_peer_response_to_buffer()
{
	int ret;
	char* buff_ptr;
	int buff_available_len;

	while (true)
	{
		buff_ptr = _buffer_block + _buffer_used_len;
		buff_available_len = _buffer_block_len - _buffer_used_len;

		ret = read(_conn_fd, buff_ptr, buff_available_len);
		if (ret > 0)
		{
			_buffer_used_len += ret;
			parse_buffer_and_get_all_ip_pkts();
			_last_recorded_recv_time = g_timer.get_jiffies();
		}
		else if (ret <= 0)
		{
			uint64_t now = g_timer.get_jiffies();
			// in the case the other side of this tcp connection performs close() or quit,
			// but on this side, we don't know for some reasons.
			if (now - _last_recorded_recv_time > HZ*5)
			{
				goto _quit;
			}

			if (errno == EAGAIN)
			{
				return;
			}

			if (ret == 0 && buff_available_len == 0)
			{
				const char* hint = "Make sure the two options have been specified:\n"
						"1. -s 0 was specified to avoid truncated IP packages.\n"
						"2. -w - was specified to output captured IP packages in binary format.\n";
				write(_conn_fd, hint, strlen(hint));
			}
			else
			{
				char buff[1024];
				char *ptr = strerror_r(errno, buff, sizeof(buff));
				write(_conn_fd, ptr, strlen(ptr));
			}

_quit:
			close(_conn_fd);
			_conn_fd = -1;
			_buffer_used_len = 0;

			return;
		}
	} // end of while
}

void tcp_postman::parse_buffer_and_get_all_ip_pkts()
{
	char* buff_ptr;
	struct iphdr* iphdr;
	struct tcphdr* tcphdr;
	int buff_len, i, ip_tot_len;
	int sentinel;
	uint16_t sum, checksum;
	uint16_t dst_port_in_netbyte_order;

	buff_ptr = _buffer_block;
	buff_len = _buffer_used_len;
	sentinel = 0;

	dst_port_in_netbyte_order = htons(g_configuration.get_dst_port());

	for (i = 0; i <= buff_len - 40;)
	{
		char ch;
		char* ptr;
		ptr = buff_ptr + i;
		ch = (*ptr & 0xf0);

		if (ch != 0x40)
		{
			i++;
			continue;
		}

		iphdr = (struct iphdr*)ptr;
		if(iphdr->version != 4)
		{
			i++;
			continue;
		}

		checksum = compute_ip_checksum(iphdr);
		sum = iphdr->check;
		if (checksum != sum)
		{
			i++;
			continue;
		}

		ip_tot_len = ntohs(iphdr->tot_len);
		if (!_hdr_only && buff_len - i < ip_tot_len)
		{
			break;
		}

		if (_hdr_only && buff_len -i < 100)
		{
			break;
		}

		tcphdr = (struct tcphdr*)(ptr + iphdr->ihl*4);
		if (tcphdr->source != dst_port_in_netbyte_order)
		{
			i++;
			continue;
		}

		if (!_hdr_only)
		{
			// most kernel has the TCP checksum offload option turned on.
			// so, if horos, or tcpgo, runs on the same machine as the testing
			// server, the tcp checksum will fail.
//			sum = tcphdr->check;
//			checksum = compute_tcp_checksum(iphdr, tcphdr);
//			tcphdr->check = sum;
//			if (checksum != sum)
//			{
//				 i++;
//				 continue;
//			}
		}

		if (!_hdr_only)
		{
			// now, a IP packet is detected
			boost::shared_ptr<ip_pkt> pkt = boost::make_shared<ip_pkt>(ptr);
			push_recved_ippkt(pkt);
			i += ip_tot_len;
			sentinel = i;
		}
		else
		{
			boost::shared_ptr<ip_pkt> pkt = boost::make_shared<ip_pkt_hdr_only>(ptr);
			push_recved_ippkt(pkt);
			// step forward in the most safest way, though it brings a little efficiency penalty.
			i += 40;
			sentinel = i;
		}

	} // end of for loop

	if (0 != sentinel)
	{
		int remaining_data_len;
		remaining_data_len = buff_len - sentinel;
		if (remaining_data_len > 0)
		{
			memmove(buff_ptr, buff_ptr + sentinel, remaining_data_len);
		}
		_buffer_used_len = remaining_data_len;
	}
}
