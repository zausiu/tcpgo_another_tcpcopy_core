/*********************************************
 * tcppostman.h
 * Author: kamuszhou@tencent.com kamuszhou@qq.com
 * website: v.qq.com  http://blog.ykyi.net
 * Created on: 25 Mar, 2014
 * Praise Be to the Lord. BUG-FREE CODE !
 ********************************************/

#ifndef _TCPPOSTMAN_H_
#define _TCPPOSTMAN_H_

#include "postman.h"

class tcp_postman : public postman
{
public:
	tcp_postman();
	virtual ~tcp_postman();

private:
	virtual void get_ready4subclass();
	virtual void recv_impl();

	/**
	 * blocks until a error occurred or the connection is closed.
	 */
	void save_peer_response_to_buffer();

	/**
	 * parser the buffer and get all the IP packet there and pluck them out from the buffer.
	 */
	void parse_buffer_and_get_all_ip_pkts();

private:
	int _listening_fd;
	int _conn_fd;
	static const int _listening_port = 1992;
	static const int _buffer_block_len = 4096*10;
	char _buffer_block[_buffer_block_len];
	int _buffer_used_len;
	bool _hdr_only;    ///< if capture IP and TCP header only when sniff the traffic from peer.
	uint64_t _last_recorded_recv_time;
};

#endif /* _TCPPOSTMAN_H_ */
