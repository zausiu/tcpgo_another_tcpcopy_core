/*********************************************
 * realtime_capturer.h
 * Author: kamuszhou@tencent.com kamuszhou@qq.com
 * website: v.qq.com  http://blog.ykyi.net
 * Created on: 27 Dec, 2013
 * Praise Be to the Lord. BUG-FREE CODE !
 ********************************************/

#ifndef _REALTIME_CAPTUREER_H_
#define _REALTIME_CAPTUREER_H_

#include <boost/lockfree/queue.hpp>
#include <boost/lockfree/spsc_queue.hpp>
#include "misc.h"
#include "utils.h"
#include "ip_pkt.h"

class realtime_capturer;
extern realtime_capturer g_realtime_capturer;

class realtime_capturer
{
public:
	realtime_capturer();

	/**
	 * @return 0 on success, non-zero otherwise.
	 */
	int get_ready();

	void pluck_out_and_inject_realtime_ippkts(int asio_idx, int most);

	bool is_in_traffic_jam_control()
	{
		return _jam_control;
	}

	virtual ~realtime_capturer();

private:
	/**
	 * the asio accept completion handler.
	 */
	void handle_accept(boost::shared_ptr<boost::asio::ip::tcp::socket> s, const boost::system::error_code& error);

	/**
	 * the asio read commpletion handler.
	 */
	void handle_read(boost::shared_ptr<boost::asio::ip::tcp::socket> s,  const boost::system::error_code& error,
					std::size_t bytes_transferred);

	/**
	 * called when traffic is in jam.
	 */
	void delayed_read(boost::shared_ptr<boost::asio::ip::tcp::socket> s, const boost::system::error_code& error);

	uint64_t generate_sess_key(boost::shared_ptr<boost::asio::ip::tcp::socket> s);

	struct ConnInfo
	{
		MemBlock _memblock;
		int _used_len;

		boost::shared_ptr<boost::asio::deadline_timer> _timer;
	};
	/**
	 * parse the buffer and get all the ip pakckets there
	 * then these pakcets will be removed from buffer.
	 * @param index the connection index.
	 */
	void parse_buff_and_get_ip_pkts(ConnInfo& conn);

private:
	int  _asio_thrd_num;
	uint16_t _traffic_listening_port;   ///< in host byte order.

	static const int _buffer_len_for_traffic = 4096*28;
	static const int _ippkt_queue_capacity = 200000;
	// static const int _ippkt_queue_capacity = 500; test

	/// key is created using make_sess_key(ip, port).
	std::map<uint64_t, ConnInfo>  _conns;    // for every connections that supply realtime traffic
//	boost::lockfree::queue<ip_pkt*> _ippkt_queue;  ///< it's not that efficient as i suppose.
	typedef boost::lockfree::spsc_queue<ip_pkt*, boost::lockfree::capacity<_ippkt_queue_capacity> > Queue;

	std::vector<boost::shared_ptr<Queue> > _ippkt_queues;
	std::vector<boost::shared_ptr<boost::atomic_int> > _queue_sizes;

	bool _jam_control;

	boost::shared_ptr<boost::asio::io_service::strand> _strand;   ///< used to serialize the asynchronous I/O

	boost::shared_ptr<boost::asio::deadline_timer> _deadline_timer;

	uint64_t _pkt_count_received;
};

#endif /* _REALTIME_CAPTUREER_H_ */
