/*********************************************
 * postman.h
 * Author: kamuszhou@tencent.com kamuszhou@qq.com
 * website: v.qq.com  http://blog.ykyi.net
 * Created on: 10 Mar, 2014
 * Praise Be to the Lord. BUG-FREE CODE !
 ********************************************/

#ifndef _POSTMAN_H_
#define _POSTMAN_H_

#include <boost/thread/thread.hpp>
#include <boost/lockfree/spsc_queue.hpp>
#include <boost/atomic.hpp>
#include "misc.h"
#include "ip_pkt.h"
#include "reactor.h"
#include "thetimer.h"
#include "cascade.h"

class postoffice;

class postman
{
public:
	postman();
	virtual ~postman();

	/**
	 * return the internal file descriptor.
	 */
	virtual void get_ready();

	/**
	 * sniff the traffic.
	 * pkt is a OUT parameter.
	 * return true on success, otherwise false.
	 */
	virtual bool recv(int asio_idx, boost::shared_ptr<ip_pkt>& pkt);

	/**
	 * send the packet.
	 * return true on success, otherwise false.
	 */
	virtual bool send(int asio_idx, boost::shared_ptr<ip_pkt> pkt);

	/**
	 * used for satisfy debug's purpose.
	 * It only returns when the packet has been send.
	 */
	virtual bool send_sync(boost::shared_ptr<ip_pkt> pkt);

protected:
	// Derived classes must implement the following two virtual functions.
	virtual void get_ready4subclass() = 0;
	virtual void recv_impl() = 0;

	// The default implementation utilizes raw socket.
	virtual void send_impl();

	virtual void send_core(ip_pkt* pkt);

	// push_recved_ippkt blocks until either pkt is pushed to recv queue
	// or thread is exiting.
	void push_recved_ippkt(boost::shared_ptr<ip_pkt> pkt);

private:
	void recv_thrd_entry();
	void send_thrd_entry();

private:
	static const int QueueCapacity = 1000000;
	typedef boost::lockfree::spsc_queue<boost::shared_ptr<ip_pkt>, boost::lockfree::capacity<QueueCapacity> > LockFreeQueue;

	std::vector<boost::shared_ptr<LockFreeQueue> > _recv_queues;
	std::vector<boost::shared_ptr<LockFreeQueue> > _snd_queues;

	std::vector<boost::shared_ptr<boost::atomic_int> > _count_recv_queues;
	std::vector<boost::shared_ptr<boost::atomic_int> > _count_snd_queues;

	boost::thread _recv_thrd;
	boost::thread _send_thrd;

	boost::atomic<bool> _done_recv_thrd;
	boost::atomic<bool> _done_snd_thrd;

	int _send_fd;

	int _asio_thrd_num;

//	boost::mutex _mutex4recv;
//	boost::mutex _mutex4snd;
//	boost::condition_variable _con_var4recv;
//	boost::condition_variable _con_var4snd;
};

#endif /* _POSTMAN_H_ */
