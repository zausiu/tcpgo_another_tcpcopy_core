/*********************************************
 * postman.cpp
 * Author: kamuszhou@tencent.com kamuszhou@qq.com
 * website: v.qq.com  http://blog.ykyi.net
 * Created on: 10 Mar, 2014
 * Praise Be to the Lord. BUG-FREE CODE !
 ********************************************/

#include <boost/make_shared.hpp>
#include "cute_logger.h"
#include "postman.h"
#include "postoffice.h"
#include "cascade.h"

postman::postman()
{
}

postman::~postman()
{
	_done_recv_thrd = true;
	_done_snd_thrd = true;

	close(_send_fd);

	_recv_thrd.join();
	_send_thrd.join();
}

void postman::get_ready()
{
	const char* err_hint;
	int on;

	_done_recv_thrd = false;
	_done_snd_thrd = false;

	_send_fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (_send_fd == -1)
	{
		err_hint = "socket";
		goto _err;
	}

	on = 1;
	if (setsockopt(_send_fd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0)
	{
		err_hint = "setsockopt";
		goto _err;
	}

	// use blocking file descriptor.
//	flags = fcntl(_send_fd, F_GETFL, 0);
//	if (flags < 0)
//	{
//		err_hint = "fcntl";
//		goto _err;
//	}
//
//	if (fcntl(_send_fd, F_SETFL, flags|O_NONBLOCK) < 0)
//	{
//		err_hint = "fcntl";
//		goto _err;
//	}

	_asio_thrd_num = g_configuration.get_asio_thrd_num();
	_recv_queues.resize(_asio_thrd_num);
	_snd_queues.resize(_asio_thrd_num);
	_count_recv_queues.resize(_asio_thrd_num);
	_count_snd_queues.resize(_asio_thrd_num);

	for (int i = 0; i < _asio_thrd_num; i++)
	{
		_recv_queues[i].reset(new LockFreeQueue());
		_snd_queues[i].reset(new LockFreeQueue());
		_count_recv_queues[i].reset(new boost::atomic_int);
		_count_recv_queues[i]->operator=(0);
		_count_snd_queues[i].reset(new boost::atomic_int);
		_count_snd_queues[i]->operator=(0);
	}

	get_ready4subclass();

	_recv_thrd = boost::thread(boost::bind(&postman::recv_thrd_entry, this));
	_send_thrd = boost::thread(boost::bind(&postman::send_thrd_entry, this));

	return;

_err:
	perror(err_hint);
	abort();
}

bool postman::recv(int asio_idx, boost::shared_ptr<ip_pkt>& pkt)
{
	bool success;

	success = _recv_queues[asio_idx]->pop(pkt);

	if (success)
	{
		_count_recv_queues[asio_idx]->operator--();
		// std::cout << "postman::recv _count_recv_queues[asio_idx]  " << *_count_recv_queues[asio_idx] << std::endl;
	}
	else
	{
	//	std::cout << "postman::recv _count_recv_queues[asio_idx]  " << *_count_recv_queues[asio_idx] << std::endl;
	}

	return success;
}

bool postman::send(int asio_idx, boost::shared_ptr<ip_pkt> pkt)
{
	bool success;

	success = _snd_queues[asio_idx]->push(pkt);

	if (success)
	{
		_count_snd_queues[asio_idx]->operator++();
	}
	else
	{
		//abort();
	}

	return success;
}

bool postman::send_sync(boost::shared_ptr<ip_pkt> pkt)
{
	send_core(pkt.get());
	return true;
}

void postman::recv_thrd_entry()
{
	while (!_done_recv_thrd)
	{
		recv_impl();
	}
}

void postman::send_thrd_entry()
{
	while (!_done_snd_thrd)
	{
		send_impl();
	}
}

void postman::send_impl()
{
	bool success;
	bool need_a_break;
	boost::shared_ptr<ip_pkt> pkt;

	need_a_break = true;

	for (int i = 0; i < _asio_thrd_num; i++)
	{
		do
		{
			success = _snd_queues[i]->pop(pkt);
			if (success)
			{
				send_core(pkt.get());
				_count_snd_queues[i]->operator--();
				need_a_break = false;
			}
		}while(success);
	}  // end of for loop

	if (need_a_break)
	{
		// i need the sending thread keeping busy.
	//	boost::this_thread::sleep(boost::posix_time::milliseconds(1));
	}
}

void postman::send_core(ip_pkt* pkt)
{
	struct sockaddr_in dst_addr;
	const char* starting_addr;
	int tot_len;
	int ret;

	dst_addr.sin_family = AF_INET;
	dst_addr.sin_addr.s_addr = pkt->get_iphdr()->daddr;

	starting_addr = pkt->get_starting_addr();
	tot_len = pkt->get_tot_len();

	ret = sendto(_send_fd, starting_addr, tot_len, 0,
			reinterpret_cast<struct sockaddr*>(&dst_addr), sizeof(dst_addr));
}

void postman::push_recved_ippkt(boost::shared_ptr<ip_pkt> pkt)
{
	bool success;
	int asio_idx;
	while (true && !_done_recv_thrd)
	{
		int pkt_tot_len = pkt->get_actual_tot_len();
		const char* pkt_addr = pkt->get_starting_addr();
		boost::shared_ptr<MemBlock> mem_block = boost::make_shared<MemBlock>(pkt_tot_len);
		memcpy(mem_block->data(), pkt_addr, pkt_tot_len);
		g_cascade.push_back(mem_block);

		asio_idx = pkt->get_asio_idx_inbound();

		while (!_recv_queues[asio_idx]->push(pkt))
		{
			// i really suspect it can afford to sleep here ???
			// or take a busy loop approach.
			// boost::this_thread::sleep(boost::posix_time::milliseconds(1));
		}
		_count_recv_queues[asio_idx]->operator++();

		// std::cout << "push_recved_ippkt  " << *_count_recv_queues[asio_idx] << std::endl;

		return;
	}
}
