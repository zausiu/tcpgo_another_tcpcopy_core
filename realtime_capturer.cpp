/*********************************************
 * realtime_capturer.cpp
 * Author: kamuszhou@tencent.com 16236914@qq.com
 * website: v.qq.com  http://blog.ykyi.net
 * Created on: 27 Dec, 2013
 * Praise Be to the Lord. BUG-FREE CODE !
 ********************************************/

#include "misc.h"
#include "realtime_capturer.h"
#include "cute_logger.h"
#include "ip_pkt.h"
#include "session_manager.h"
#include "proactor.h"

realtime_capturer g_realtime_capturer;

realtime_capturer::realtime_capturer() // : _ippkt_queue(100000)
{
	_traffic_listening_port = 1993;
}

realtime_capturer::~realtime_capturer()
{
}

int realtime_capturer::get_ready()
{
	g_proactor.listen(_traffic_listening_port, boost::bind(&realtime_capturer::handle_accept, this, _1, _2));
	_strand.reset(new boost::asio::strand(g_proactor.get_io_service()));

	_asio_thrd_num = g_configuration.get_asio_thrd_num();
	_ippkt_queues.resize(_asio_thrd_num);
	_queue_sizes.resize(_asio_thrd_num);

	for (int i = 0; i < _asio_thrd_num; i++)
	{
		_ippkt_queues[i].reset(new Queue);
		_queue_sizes[i].reset(new boost::atomic_int);
		_queue_sizes[i]->operator=(0);
	}

	_jam_control = false;
	_pkt_count_received = 0;

	return 0;
}

void realtime_capturer::pluck_out_and_inject_realtime_ippkts(int asio_idx, int most)
{
	ip_pkt* pkt;
	boost::shared_ptr<ip_pkt> smart_pkt;
	int num = 0;
	while (_ippkt_queues[asio_idx]->pop(pkt))
	{
		smart_pkt.reset(pkt);
		session_manager::instance(asio_idx).inject_a_realtime_ippkt(smart_pkt);
		_queue_sizes[asio_idx]->operator--();
		num++;

		if (num >= most)
		{
			return;
		}
	}
	// std::cout << num << std::endl;
}

void realtime_capturer::handle_accept(boost::shared_ptr<boost::asio::ip::tcp::socket> s, const boost::system::error_code& error)
{
	uint64_t key = generate_sess_key(s);
	ConnInfo& conn = _conns[key];

	conn._memblock.resize(_buffer_len_for_traffic);
	conn._used_len = 0;
	conn._timer = g_proactor.produce_a_timer();

	s->async_read_some(boost::asio::buffer(conn._memblock),
			_strand->wrap(boost::bind(&realtime_capturer::handle_read, this, s,
						boost::asio::placeholders::error,
						boost::asio::placeholders::bytes_transferred)));
}

void realtime_capturer::handle_read(boost::shared_ptr<boost::asio::ip::tcp::socket> s,
									const boost::system::error_code& error,
									std::size_t bytes_transferred)
{
	uint64_t key = generate_sess_key(s);

	// thanks to the shared_ptr, don't have to worry about the fd leak.
	// if ((boost::asio::error::eof == error) ||
	   //     (boost::asio::error::connection_reset == error))
	boost::asio::ip::tcp::endpoint point = s->remote_endpoint();

	if (boost::asio::error::eof == error)
	{
		// normal termination
		_conns.erase(key);
		g_logger.printf("%s.%hu closed the connection.\n", point.address().to_v4().to_string().c_str(), point.port());
		return;
	}
	else if (error)
	{
		_conns.erase(key);
		g_logger.printf("connection from %s.%hu is broken.\n", point.address().to_v4().to_string().c_str(), point.port());
	//	throw boost::system::system_error(error);  // some other error.
		return;
	}

	ConnInfo& conn = _conns[key];
	MemBlock& mb = conn._memblock;
	conn._used_len += bytes_transferred;
	assert(conn._used_len <= _buffer_len_for_traffic);

	// do the job
	parse_buff_and_get_ip_pkts(conn);

	if (_buffer_len_for_traffic == conn._used_len)
	{
//		_conns.erase(key);
//		s->close();
	}

	if (!_jam_control)
	{
		s->async_read_some(boost::asio::buffer(mb.data() + conn._used_len, mb.size() - conn._used_len),
				_strand->wrap(boost::bind(&realtime_capturer::handle_read, this, s,
								boost::asio::placeholders::error,
								boost::asio::placeholders::bytes_transferred)));
	}
	else
	{
		conn._timer->cancel();
		conn._timer->expires_from_now(boost::posix_time::seconds(2));
		conn._timer->async_wait(_strand->wrap(
				boost::bind(&realtime_capturer::delayed_read, this, s, boost::asio::placeholders::error)
				));
	}
}

void realtime_capturer::delayed_read(boost::shared_ptr<boost::asio::ip::tcp::socket> s,
									const boost::system::error_code& error)
{
	using namespace boost::asio;

	if (!error)
	{
	    // Timer expired.
	}

	// whatever happend, even a timer error occured, issue a async read.
	uint64_t key = generate_sess_key(s);
	ConnInfo& conn = _conns[key];
	MemBlock& mb = conn._memblock;

	s->async_read_some(boost::asio::buffer(mb.data() + conn._used_len, mb.size() - conn._used_len),
			_strand->wrap(boost::bind(&realtime_capturer::handle_read, this, s,
							boost::asio::placeholders::error,
							boost::asio::placeholders::bytes_transferred)));
}

uint64_t realtime_capturer::generate_sess_key(boost::shared_ptr<boost::asio::ip::tcp::socket> s)
{
	boost::asio::ip::tcp::socket::endpoint_type point = s->remote_endpoint();
	boost::asio::ip::address_v4 addr = point.address().to_v4();
	unsigned short port = point.port();
	uint64_t key = make_sess_key(addr.to_ulong(), port);

	return key;
}

void realtime_capturer::parse_buff_and_get_ip_pkts(ConnInfo& conn)
{
	char* buff_ptr;
	struct iphdr* iphdr;
	struct tcphdr* tcphdr;
	int buff_len, i, iphdr_len, ip_tot_len;
	int sentinel;
	uint16_t src_port;
	uint16_t sum, checksum;

	if (_jam_control)
	{
		for (int i = 0; i < _queue_sizes.size(); i++)
		{
			if ( *_queue_sizes[i] < 100)
			{
				_jam_control = false;
				break;
			}
		}

		return;
	}

	buff_ptr = conn._memblock.data();
	buff_len = conn._used_len;
	sentinel = 0;

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
		iphdr_len = iphdr->ihl << 2;
		if (iphdr_len < 20)
		{
			i++;
			continue;
		}
		sum = iphdr->check;
		checksum = compute_ip_checksum(iphdr);
		iphdr->check = sum;
		if (checksum != sum)
		{
			i++;
			continue;
		}
		ip_tot_len = ntohs(iphdr->tot_len);
		if (buff_len - i < ip_tot_len)
		{
			break;
		}
		tcphdr = (struct tcphdr*)(ptr + iphdr->ihl*4);
		/* the following code snippet sould be optimized ! TODO.
		 * because source port is possibly be modified in the following code, so tcp checksum will fail.
		sum = tcphdr->check;
		checksum = compute_tcp_checksum(iphdr, tcphdr);
		tcphdr->check = sum;
		if (checksum != sum)
		{
			i++;
			continue;
		}*/
		src_port = ntohs(tcphdr->source);
		tcphdr->source = htons(generate_the_port(src_port)); // modify the source port.

		// pluck out the incoming ip packet.
		ip_pkt* pkt = new ip_pkt(ptr);
		int asio_idx = pkt->get_asio_idx_outbound();

		// ugly and error-prone c grammar.
		if (0xff == ((char*)&(pkt->get_iphdr()->saddr))[0] || 0xff == ((char*)&(pkt->get_iphdr()->saddr))[3] ||
			127 == ((char*)&(pkt->get_iphdr()->saddr))[3] ||
			0x0 == ((char*)&(pkt->get_iphdr()->daddr))[0] || 0x0 == ((char*)&(pkt->get_iphdr()->daddr))[3])
		{
			i++;
			continue;
		}

		if (!_ippkt_queues[asio_idx]->push(pkt))
		{
			g_logger.printf("one of realtime_capturer's queue is full. _count: %d\n", (int)*_queue_sizes[asio_idx]);
			_jam_control = true;

			break;
		}

//		g_logger.printf("%lu packets have received.\n", ++_pkt_count_received);

		_queue_sizes[asio_idx]->operator++();
		i += ip_tot_len;
		sentinel = i;
	} // end of for loop.

	if (0 != sentinel)
	{
		// discards the outdated traffic.
		int remaining_data_len;
		remaining_data_len = buff_len - sentinel;
		assert(remaining_data_len >= 0);
		if (remaining_data_len > 0)
		{
			memmove(buff_ptr, buff_ptr + sentinel, remaining_data_len);
		}
		conn._used_len = remaining_data_len;
	}
}
