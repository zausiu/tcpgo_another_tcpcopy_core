/*********************************************
 * tcpsession.cpp
 * Author: kamuszhou@tencent.com, 16236914@qq.com
 * website: http://blog.ykyi.net
 * Created on: Dec 9, 2013
 * Praise Be to the Lord. BUG-FREE CODE !
 ********************************************/

#include "tcpsession.h"
#include "utils.h"
#include "cute_logger.h"
#include "session_manager.h"
#include "configuration.h"
#include "politburo.h"
#include "statistics_bureau.h"
#include "testsuite.h"

#ifdef _DEBUG

boost::atomic_long tcpsession::_ended_sess_count;

#endif

tcpsession::tcpsession(int asio_idx, uint32_t ip, uint16_t port)
{
	struct in_addr inaddr;
	inaddr.s_addr = ip;

	_client_src_ip_num = ip;
	_client_src_ip_str = inet_ntoa(inaddr);
	_client_src_port = ntohs(port);
	_session_key = make_sess_key(ip, port);

	_response_from_peer_time_out = g_configuration.get_response_from_peer_time_out();
	_have_to_send_data_within_this_timeperiod = g_configuration.get_have_to_send_data_within_this_timeperiod();
	_retransmit_time_interval = g_configuration.get_retransmit_time_interval();
	_wait_for_fin_from_peer_time_out = g_configuration.get_wait_for_fin_from_peer_time_out();
	_enable_active_close = g_configuration.get_enable_active_close();

	struct iphdr *iphdr = (struct iphdr*)_pure_ack_template;
	struct tcphdr *tcphdr = (struct tcphdr*)(_pure_ack_template + 20);
	memset(_pure_ack_template, 0, 40);
	iphdr->ihl = 5;
	iphdr->version = 4;
	iphdr->tos = 0;
	iphdr->tot_len = htons(40);
	iphdr->id = 0;
	iphdr->frag_off = 0;
	iphdr->ttl = 255;
	iphdr->protocol = IPPROTO_TCP;
	iphdr->check = 0;
	iphdr->saddr = ip;
	iphdr->daddr = 0;

	tcphdr->source = port;
	tcphdr->dest = 0;
	tcphdr->seq = 0;
	tcphdr->ack_seq = 0;
	tcphdr->ack = 1;
	tcphdr->doff = 5;
	tcphdr->window = htons(65535);
	tcphdr->check = 0;
	tcphdr->urg_ptr = 0;

	memcpy(_pure_rst_template, _pure_ack_template, sizeof(_pure_rst_template));
	tcphdr = (struct tcphdr*)(_pure_rst_template + 20);
	tcphdr->ack = 0;
	tcphdr->rst = 1;

	_asio_idx = asio_idx;
	_ready = false;
}

tcpsession::tcpsession()
{
}

tcpsession::~tcpsession()
{
}

void tcpsession::kill_me(cause_of_death cause)
{    _dead = true;
	g_logger.printf("session: %s.%hu ended: %s\n",
			_client_src_ip_str.c_str(), _client_src_port, map_cause_code_to_str(cause));
	g_testsuite.report_sess_traffic(_asio_idx, _client_src_ip_str, _client_src_port, _traffic_history, cause);

	if (PEER_TIME_OUT == cause || DORMANCY == cause)
	{
		_reset_the_peer = true;
	}
	session_manager::instance(_asio_idx).decrease_healthy_sess_count();

#ifdef _DEBUG
	_ended_sess_count++;
	long l = _ended_sess_count;
	g_logger.printf("%ld sessions have been processed.\n", l);
#endif
}

bool tcpsession::still_alive()
{
	return !_dead;
}

boost::shared_ptr<tcpsession> tcpsession::clone()
{
	boost::shared_ptr<tcpsession> sess = boost::make_shared<tcpsession>();
	uint32_t old_src_ip_num = _client_src_ip_num;
	uint32_t new_src_ip_num = next_avail_ip(old_src_ip_num);

	*sess = *this;

	struct in_addr inaddr;
	inaddr.s_addr = new_src_ip_num;

	sess->_client_src_ip_num = new_src_ip_num;
	sess->_client_src_ip_str = inet_ntoa(inaddr);

	sess->_session_key = make_sess_key(new_src_ip_num, htons(_client_src_port));

	sess->_ippkts_samples.clear();
	for (std::list<boost::shared_ptr<ip_pkt> >::iterator ite = _ippkts_samples.begin();
			ite != _ippkts_samples.end();
			++ite)
	{
		ip_pkt* pkt = ite->get();
		boost::shared_ptr<ip_pkt> smart_pkt = pkt->clone();
		sess->_ippkts_samples.push_back(smart_pkt);
	}

	sess->_sliding_window_left_boundary = sess->_ippkts_samples.begin();
	sess->_sliding_window_right_boundary = sess->_sliding_window_left_boundary;
	sess->_sliding_window_right_boundary.operator++();

	ip_pkt* pkt = sess->_sliding_window_left_boundary->get();
	assert(pkt->is_syn_set());

	return sess;
}

void tcpsession::append_ip_sample(boost::shared_ptr<ip_pkt> ippkt)
{
	struct iphdr* iphdr; 

	assert(ippkt);
	iphdr = (struct iphdr*)ippkt.get();

	_ippkts_samples.push_back(ippkt);
}

void tcpsession::inject_a_realtime_ippkt(boost::shared_ptr<ip_pkt> ippkt)
{
	bool complete;
	std::list<boost::shared_ptr<ip_pkt> >::iterator ite;

	if (ACCUMULATING_TRAFFIC != _sess_state)
	{
		return;
	}

	if (ippkt->is_rst_set())
	{
		postoffice::instance(_asio_idx).register_callback(_session_key, this);
		_sess_state = ABORT;

		return;
	}

	if (ippkt->is_syn_set())
	{
		_got_syn_pkt = true;
	}
	else if (ippkt->is_fin_set())
	{
		_got_fin_pkt = true;
	}

	_last_injecting_rt_traffic_time = g_timer.get_jiffies();

	if (ippkt->get_tcp_payload_len() == 0 && !ippkt->is_fin_set() && !ippkt->is_syn_set())
	{
		return;
	}

	_ippkts_samples.push_back(ippkt);

	complete = false;
	if (_got_syn_pkt && _got_fin_pkt)
	{
		_ippkts_samples.sort();
		complete = (0 == sanitize());
	}

	if (complete)
	{
		g_logger.printf("session %s.%hu is ready to work.\n", _client_src_ip_str.c_str(), _client_src_port);

		_sliding_window_left_boundary = _ippkts_samples.begin();
		ite = _sliding_window_left_boundary;
		++ite;
		_sliding_window_right_boundary = ite;

		assert((*_sliding_window_left_boundary)->is_syn_set());

		_sess_state = SENDING_TRAFFIC;

		_injecting_rt_traffic_timer->cancel();

		postoffice::instance(_asio_idx).register_callback(_session_key, this);

		session_manager::instance(_asio_idx).increase_healthy_sess_count();

		session_manager::instance(_asio_idx).clone_sessions(*this);
	}
}

void tcpsession::injecting_rt_traffic_timeout_checker(const boost::system::error_code& error)
{
	uint64_t now;
	int timeout;
	sess_state prev_sess_state;

	if (error)
	{
		return;
	}

	if (_sess_state != ACCUMULATING_TRAFFIC)
		return;

	prev_sess_state = _sess_state; // for debug's convenience.

	now = g_timer.get_jiffies();
	timeout = g_configuration.get_injecting_rt_traffic_timeout();

	// no incoming real time traffic in a period of time.
	if (now - _last_injecting_rt_traffic_time > timeout)
	{
		assert(ACCUMULATING_TRAFFIC == _sess_state);
		_sess_state = ABORT;

		postoffice::instance(_asio_idx).register_callback(_session_key, this);
		g_logger.printf("session %s.%hu aborts.\n", _client_src_ip_str.c_str(), _client_src_port);
	}
	else
	{
		_injecting_rt_traffic_timer = g_politburo.enqueue_a_timer_handler(_asio_idx,
				boost::posix_time::milliseconds(g_configuration.get_injecting_rt_traffic_timeout()*10),
				boost::bind(&tcpsession::injecting_rt_traffic_timeout_checker, this, boost::asio::placeholders::error)
		);
	}
}

int32_t tcpsession::sanitize()
{
	int32_t size_saved, size_now;
	int32_t i;   // for the convenience of debug.
	uint32_t seq;
	uint32_t expected_next_seq;
	int32_t tcp_payload_len;

	i = 0;
	std::list<boost::shared_ptr<ip_pkt> >::iterator ite;
	// reomve the packet without tcp playload. e.g. the tcp keep-alive segments which are
	// used to elicit an ACK from the receiver.
	for(ite = _ippkts_samples.begin(); ite != _ippkts_samples.end();)
	{
		ip_pkt* pkt = ite->get();
		int tot_len = pkt->get_tot_len();
		int iphdr_len = pkt->get_iphdr_len();
		int tcphdr_len = pkt->get_tcphdr_len();
		bool fin_set = pkt->is_fin_set();
		bool ack_set = pkt->is_ack_set();
		bool syn_set = pkt->is_syn_set();
		bool rst_set = pkt->is_rst_set();

		tcp_payload_len = pkt->get_tcp_payload_len();

		// remove usefuless samples
		if (0 == tcp_payload_len && !syn_set && !fin_set ) // && !rst_set)  // rst is not allowed any more.
		{
			_ippkts_samples.erase(ite++);
		}
		// remove  corrupted sample, this case occurs rarely.
		else if (tot_len != iphdr_len + tcphdr_len + tcp_payload_len)
		{
			//std::cerr << "detected corrupted ip packet." << pkt->get_src_addr() << " : " << pkt->get_src_port()
							//<< " --> " << pkt->get_dst_addr() << " : " << pkt->get_dst_port() << std::endl;
			++ite;
		}
		else
		{
			++ite;
		}
	}

	size_saved = _ippkts_samples.size();
	if (0 == size_saved)
	{
		goto _err;
	}
	_ippkts_samples.sort();
	_ippkts_samples.unique();   // remove duplicates.
	size_now = _ippkts_samples.size();
	if (size_now != size_saved)
	{
		//	g_logger.printf("tcpsession:%s:%hu has %d duplicated packets dropped.\n",
		//			_client_src_ip_str.c_str(), _client_src_port, size_saved - size_now);
	}

	ite = _ippkts_samples.begin();
	// the first packet is not a syn, so these samples are considered as incomplete.
	if (!(*ite)->is_syn_set())
	{
		goto _err;
	}
	expected_next_seq = (*ite)->get_seq() + 1;
	++ite;
	++i;
	for (; ite != _ippkts_samples.end(); ++ite, ++i)
	{
		ip_pkt* pkt = ite->get();
		seq = pkt->get_seq();
		if(expected_next_seq != seq)
		{
			// The last IP packet has rst set. In this case, the seq may be the last seq plus one.
			// But in most cases as I observed, it doesn't increase the last seq.
//			if (i + 1 == size_now && ite->is_rst_set() && expected_next_seq + 1 == seq) // Deprecated !!!
//			{
//				_ippkts_samples.erase(++ite, _ippkts_samples.end());
//				return 0;
//			}

			goto _err;
		}
		tcp_payload_len = pkt->get_tcp_payload_len();
		if (tcp_payload_len > 0)
		{
			expected_next_seq += tcp_payload_len;
		}

		if(pkt->is_fin_set())
		{
			// from the perspective of most servers, it makes non sense for the client to
			// make a quest only but have no interest in the response.
			// so, for the sake of simplicity, this kind of session is removed.
			if (0 == pkt->get_tcp_payload_len())
			{
				_ippkts_samples.erase(++ite, _ippkts_samples.end());
				return 0;
			}
			else
			{
				goto _err;
			}
		}
	}

_err:
	return 1;
}

void tcpsession::get_ready_for_rt_traffic()
{
	_sess_state = ACCUMULATING_TRAFFIC;
	get_ready();
}

void tcpsession::get_ready_for_offline_traffic()
{
	_sess_state = SENDING_TRAFFIC;
	session_manager::instance(_asio_idx).increase_healthy_sess_count();
	get_ready();
}

void tcpsession::get_ready()
{
	std::list<boost::shared_ptr<ip_pkt> >::iterator ite, tmp_ite;
	uint64_t now;

	assert(false == _ready);

	now = g_timer.get_jiffies();

	_dead = false;
	_reset_the_peer = false;
	_current_state = tcpsession::CLOSED;
	_expected_next_sequence_from_peer = 0;
	_latest_acked_sequence_by_peer = 0;
	_expected_last_ack_seq_from_peer = 0;
	_last_seq_beyond_fin_at_localhost_side = 0;
	_advertised_window_size = 1000*1000*1000;
	_sliding_window_left_boundary = _ippkts_samples.begin();
	if (!_ippkts_samples.empty())
	{
		tmp_ite = _sliding_window_left_boundary;
		++tmp_ite;
		_sliding_window_right_boundary = tmp_ite;
	}
	else
	{
		// empty
		_sliding_window_right_boundary = _ippkts_samples.end();
	}

	_syn_sending_time = -1;
	_last_recorded_recv_time = -1;
	_last_recorded_recv_time_with_payload = -1;
	_last_recorded_snd_time = now;

//	for(ite = _ippkts_samples.begin(); ite != _ippkts_samples.end(); ++ite)
//	{
//		// add code to fiddle with every IP packets.
//	}

	g_logger.printf("session %s.%hu is created.[%d]\n", _client_src_ip_str.c_str(), _client_src_port, _asio_idx);

	_last_injecting_rt_traffic_time = now;

	if (ACCUMULATING_TRAFFIC == _sess_state)
	{
		_injecting_rt_traffic_timer = g_politburo.enqueue_a_timer_handler(_asio_idx,
				boost::posix_time::milliseconds(g_configuration.get_injecting_rt_traffic_timeout()*10),
				boost::bind(&tcpsession::injecting_rt_traffic_timeout_checker, this, boost::asio::placeholders::error)
		);
	}

	_got_syn_pkt = false;
	_got_fin_pkt = false;

	_ready = true;
}

int tcpsession::pls_send_these_packets(std::vector<boost::shared_ptr<ip_pkt> >& pkts)
{
	int count;
	ip_pkt* pkt;
	uint64_t jiffies;
	bool fin_has_been_sent;
	bool pkt_will_be_sent;
	std::list<boost::shared_ptr<ip_pkt> >::iterator ite;
	uint64_t now = g_timer.get_jiffies();

	pkts.clear();
	jiffies = g_timer.get_jiffies();

	if (ABORT == _sess_state)
	{
		g_statistics_bureau.inc_sess_aborted_count();
		_injecting_rt_traffic_timer->cancel();

		return postoffice_callback_interface::REMOVE;
	}
	assert(SENDING_TRAFFIC == _sess_state);

	if (!still_alive())
	{
		if (_reset_the_peer)  // send two RSTs in a row.
		{
			char buff0[40];
			char buff1[40];

			memcpy(buff0, _pure_rst_template, sizeof(buff0));
			struct tcphdr* tcphdr = (struct tcphdr*)(buff0 + 20);
			tcphdr->seq = htonl(_latest_acked_sequence_by_peer);

			memcpy(buff1, _pure_rst_template, sizeof(buff1));
			tcphdr = (struct tcphdr*)(buff1 + 20);
			tcphdr->seq = htonl(_latest_acked_sequence_by_peer);

			boost::shared_ptr<ip_pkt>  pure_rst_pkt0 = boost::make_shared<ip_pkt>(buff0);
			boost::shared_ptr<ip_pkt>  pure_rst_pkt1 = boost::make_shared<ip_pkt>(buff1);

			pure_rst_pkt0->rebuild_num(g_configuration.get_dst_addr_uint32(),
									g_configuration.get_dst_port(), _expected_next_sequence_from_peer);
			pkts.push_back(pure_rst_pkt0);

			pure_rst_pkt1->rebuild_num(g_configuration.get_dst_addr_uint32(),
									g_configuration.get_dst_port(), _expected_next_sequence_from_peer);
			pkts.push_back(pure_rst_pkt1);

			_reset_the_peer = false;

			return 2;  // send two RST packets.
		}
		else
		{
			return postoffice_callback_interface::REMOVE;
		}
	}

#ifdef _DEBUG_
	int distance = std::distance(_sliding_window_left_boundary, _sliding_window_right_boundary);
#endif

	// the following logic determines that if some packets should be send.
	// retransmit timer has not expired.
	for (ite = _sliding_window_left_boundary; ite != _sliding_window_right_boundary; ++ite)
	{
		ip_pkt* pkt = ite->get();
		uint64_t last_recorded_send_time = pkt->get_last_recorded_snd_time();
		if (jiffies - last_recorded_send_time > _retransmit_time_interval)
		{
			pkt->mark_me_should_be_sent();
		}
	}

	// if reach here, some packets should be send.

	pkt_will_be_sent = false;
	fin_has_been_sent = false;
	// iterate over the sliding window.
	for(std::list<boost::shared_ptr<ip_pkt> >::iterator ite = _sliding_window_left_boundary;
			ite != _sliding_window_right_boundary;)
	{

		bool is_syn_set, is_ack_set, is_fin_set, is_rst_set, send_me_pls;
		int tcp_payload_len;

		pkt = ite->get();

		is_syn_set = pkt->is_syn_set();
		is_ack_set = pkt->is_ack_set();
		is_fin_set = pkt->is_fin_set();
		is_rst_set = pkt->is_rst_set();
		send_me_pls = pkt->should_send_me();

		tcp_payload_len = pkt->get_tcp_payload_len();

		if (is_fin_set)  // FIN packet
		{
			if (_enable_active_close)
			{
				fin_has_been_sent = true;
			}
			else   // passive close
			{
				if (_current_state != ESTABLISHED)
				{
					fin_has_been_sent = true;
				}
				else // halt my FIN and wait for FIN from the peer.
				{
					// _current_state == ESTABLISHED
					// though FIN packet is in the sliding window, the following break
					// cause it be halted. FIN will not be pushed into sending
					// vector returned from within this method call.
					break;
				}
			}
		} // end of if(is_fin_set)

		// if this is a pure ack
		if (is_ack_set && 0 == tcp_payload_len && !is_syn_set && !is_rst_set && !is_fin_set )
		{
			int sent_count;
			sent_count = pkt->get_send_counter();

			if (0 == sent_count)  // record the pure ack that will be send.
			{
				_traffic_history.push_back(*ite);
			}
			else  // pure ack is one-shot only.
			{
				if (ite == _sliding_window_left_boundary)
				{
					++_sliding_window_left_boundary;
				}
				_ippkts_samples.erase(ite++);

				continue;
			}
		}

		pkt->rebuild_num(g_configuration.get_dst_addr_uint32(),
						g_configuration.get_dst_port(), _expected_next_sequence_from_peer);
		pkts.push_back(*ite);

		if (send_me_pls)
		{
			if (pkt->is_syn_set() || pkt->is_fin_set())
			{
				pkt_will_be_sent = true;
			}
			else if (0 != pkt->get_tcp_payload_len()) // cannot count pure ack
			{
				pkt_will_be_sent = true;
			}
		}

		++ite;
	} // end the loop of the sliding window

	count = pkts.size();

	// is it the first hand shake
	if (0 != count && pkts[0]->is_syn_set() && pkts[0]->should_send_me())
	{
		if (-1 == _syn_sending_time)
		{
			_syn_sending_time = now;
		}
		_current_state = tcpsession::SYN_SENT;
		g_logger.printf("session: %s.%hu moves to state SYN_SENT from state CLOSED.\n",
				_client_src_ip_str.c_str(), _client_src_port);
		// I cannot remember why I write this line, it looks like unnecessary.
		// So i comment it out.
		// _last_recorded_recv_time = jiffies;
	}

	// timeout. No responses have received from peer for a long time.
	if (_last_recorded_recv_time_with_payload != -1 &&
			jiffies - _last_recorded_recv_time_with_payload > _response_from_peer_time_out)
	{
		g_logger.printf("session: %s.%hu no valid payload have received from peer in %d milliseconds. I commit a suicide.\n",
				_client_src_ip_str.c_str(), _client_src_port, _response_from_peer_time_out*10);
		g_statistics_bureau.inc_sess_cancelled_by_no_response_count();
		kill_me(PEER_TIME_OUT);

		return 0;
	}

	if (0 != count && pkts[0]->is_syn_set())
	{
		ip_pkt* pkt = pkts[0].get();
		int syn_sent_count = pkt->get_send_counter();
		uint64_t handshake_time_elapsed = _retransmit_time_interval * syn_sent_count;
		if (handshake_time_elapsed > _response_from_peer_time_out)
		{
			g_logger.printf("session: %s.%hu %d SYNs have been sent without elicited SYN-ACK from peer in %d milliseconds. I commit a suicide.\n",
					_client_src_ip_str.c_str(), _client_src_port, syn_sent_count, _response_from_peer_time_out*10);
			g_statistics_bureau.inc_sess_cancelled_by_no_response_count();
			kill_me(PEER_TIME_OUT);

			return 0;
		}
	}

	if (0 != count && fin_has_been_sent)
	{
		const ip_pkt* pkt = pkts[count-1].get();
		if (_current_state == tcpsession::ESTABLISHED) // active close
		{
			_current_state = tcpsession::FIN_WAIT_1;
			g_logger.printf("session: %s.%hu moves to state FIN_WAIT_1 from state ESTABLISHED.\n",
					_client_src_ip_str.c_str(), _client_src_port);
			_expected_last_ack_seq_from_peer = pkt->get_seq() + pkt->get_tcp_payload_len();
		}
		else if (_current_state == tcpsession::CLOSE_WAIT) // passive close
		{
			_current_state = tcpsession::LAST_ACK;
			g_logger.printf("session: %s.%hu moves to state LAST_ACK from state CLOSE_WAIT.\n",
					_client_src_ip_str.c_str(), _client_src_port);
			_expected_last_ack_seq_from_peer = pkt->get_seq() + pkt->get_tcp_payload_len();
		}
		_last_seq_beyond_fin_at_localhost_side = pkt->get_seq() + pkt->get_tcp_payload_len();
	}

	if (count > 0 && _current_state == tcpsession::TIME_WAIT)
	{
		// Give only one chance for peer's FIN to be acked.
		g_logger.printf("session %s.%hu exits from state TIME_WAIT.\n", _client_src_ip_str.c_str(), _client_src_port);
		g_statistics_bureau.inc_sess_active_close_count();
		g_statistics_bureau.inc_total_sess_time_duration(now - _syn_sending_time);
		kill_me(ACTIVE_CLOSE);
	}

	if (pkt_will_be_sent)
	{
		_last_recorded_snd_time = jiffies;
	}
	else if (jiffies - _last_recorded_snd_time > _have_to_send_data_within_this_timeperiod)
	{
		bool dormancy = false;

		if (_enable_active_close && _current_state == ESTABLISHED)
		{
			dormancy = true;
		}

		if (!_enable_active_close && _current_state == ESTABLISHED)
		{
			if (_sliding_window_left_boundary != _sliding_window_right_boundary)
			{
				if (!(*_sliding_window_left_boundary)->is_fin_set())
				{
					dormancy = true;
				}
			}
			else
			{
				dormancy = true;
			}
		}

		if (dormancy)
		{
			g_statistics_bureau.inc_sess_dormancy_count();
			kill_me(DORMANCY);
		}
		else
		{
			// wait for the peer time out.
		}

		return 0;
	}

	return count;
}

void tcpsession::got_a_packet(boost::shared_ptr<ip_pkt> ippkt)
{
	uint64_t jiffies = g_timer.get_jiffies();
	_last_recorded_recv_time = jiffies;
	if (0 != ippkt->get_tcp_payload_len() || ippkt->is_syn_set() || ippkt->is_fin_set())
	{
		_last_recorded_recv_time_with_payload = jiffies;
	}

	if (!still_alive())
		return;

	if (ippkt->is_rst_set())
	{
		g_logger.printf("session: %s.%hu reset kills me.\n", _client_src_ip_str.c_str(), _client_src_port);
		g_statistics_bureau.inc_sess_killed_by_reset_count();
		_traffic_history.push_back(ippkt);
		kill_me(RESET);
		return;
	}

	switch(_current_state)
	{
	case CLOSED:
		closed_state_handler(ippkt);
		break;

	case LISTEN: 
		listen_state_handler(ippkt);
		break;

	case SYN_RCVD: 
		syn_rcvd_state_handler(ippkt);
		break;

	case SYN_SENT:
		syn_sent_state_handler(ippkt);
		break;

	case ESTABLISHED: 
		established_state_handler(ippkt);
		break;

	case CLOSE_WAIT:
		close_wait_state_handler(ippkt);
		break;

	case LAST_ACK:
		last_ack_state_handler(ippkt);
		break;

	case FIN_WAIT_1:
		fin_wait_1_state_handler(ippkt);
		break;

	case FIN_WAIT_2:
		fin_wait_2_state_handler(ippkt);
		break;

	case CLOSING:
		closing_state_handler(ippkt);
		break;

	case TIME_WAIT:
		time_wait_state_handler(ippkt);
		break;

	default:
		// catch ya. only god and bug knows how to reach here.
		abort();
	}
}

boost::shared_ptr<ip_pkt> tcpsession::build_an_ack_without_payload(uint32_t seq)
{
	struct tcphdr* tcphdr;
	char buff[40];
	memcpy(buff, _pure_ack_template, sizeof(buff));

	tcphdr = (struct tcphdr*)(buff + 20);
	tcphdr->seq = htons(seq);
	tcphdr->ack = 1;

	boost::shared_ptr<ip_pkt> pkt = boost::make_shared<ip_pkt>(buff);

	return pkt;
}

void tcpsession::closed_state_handler(boost::shared_ptr<ip_pkt> pkt)
{
	// do nothing, it's assumed the peer will got a time out event finally.
}

void tcpsession::listen_state_handler(boost::shared_ptr<ip_pkt> pkt)
{
	// not supposed to reach here.
	abort();
}

void tcpsession::syn_rcvd_state_handler(boost::shared_ptr<ip_pkt> pkt)
{
	// this event rarely happens in real world.
	// TODO. add code to handle this case.
}

void tcpsession::syn_sent_state_handler(boost::shared_ptr<ip_pkt> pkt)
{
	if (pkt->is_syn_set())
	{
		if (pkt->is_ack_set())
		{
			_current_state = tcpsession::ESTABLISHED;
			g_logger.printf("session: %s.%hu moves to state ESTABLISHED from state SYN_SENT.\n",
					_client_src_ip_str.c_str(), _client_src_port);
		}
		else
		{
			_current_state = tcpsession::SYN_RCVD; // rarely happens.
			g_logger.printf("session: %s.%hu moves to state SYN_RCVD from state SYN_SENT.\n",
					_client_src_ip_str.c_str(), _client_src_port);
		}
	}
	refresh_status(pkt);
}

void tcpsession::established_state_handler(boost::shared_ptr<ip_pkt> pkt)
{
	if (pkt->is_fin_set())
	{
		_current_state = tcpsession::CLOSE_WAIT;
		g_logger.printf("session %s.%hu moves to state CLOSE_WAIT from state ESTABLISHED.\n",
				_client_src_ip_str.c_str(), _client_src_port);

		do
		{
			ip_pkt* pkt = _ippkts_samples.front().get();
			if (0 == pkt->get_tcp_payload_len() && !pkt->is_fin_set())
			{
				_ippkts_samples.erase(_ippkts_samples.begin());
			}
			else
			{
				break;
			}
		}while(true);
		_sliding_window_left_boundary = _ippkts_samples.begin();
		_sliding_window_right_boundary = _ippkts_samples.end();
	}
	else
	{
		// only one fin packet is in ip_pkts_samples, the received pakt has no payload and _enable_active_close is not allowed.
		if (_ippkts_samples.front()->is_fin_set() && 0 != pkt->get_tcp_payload_len() && !_enable_active_close)
		{
			boost::shared_ptr<ip_pkt> pure_ack = build_an_ack_without_payload(_latest_acked_sequence_by_peer);
			pure_ack->rebuild_num(g_configuration.get_dst_addr_uint32(),
						g_configuration.get_dst_port(), _expected_next_sequence_from_peer);
			_ippkts_samples.push_front(pure_ack);
			_sliding_window_left_boundary = _ippkts_samples.begin();
			_sliding_window_right_boundary = _ippkts_samples.end();
		}
	}
	refresh_status(pkt);
}

void tcpsession::close_wait_state_handler(boost::shared_ptr<ip_pkt> pkt)
{
	// this state will be transformed to LAST_ACK in the sending logic, refer to pls_send_these_packets().
	refresh_status(pkt);

	assert(!_ippkts_samples.empty());
}

void tcpsession::last_ack_state_handler(boost::shared_ptr<ip_pkt> pkt)
{
	uint32_t ack_seq;
	uint64_t now;

	refresh_status(pkt);

	now = g_timer.get_jiffies();
	ack_seq = pkt->get_ack_seq();
	if (pkt->is_ack_set() && seq_before_eq(_expected_last_ack_seq_from_peer, ack_seq))
	{
		_current_state = tcpsession::CLOSED;
		g_logger.printf("session %s.%hu moves to state CLOSED from state LAST_ACK.\n",
				_client_src_ip_str.c_str(), _client_src_port);
		g_statistics_bureau.inc_sess_passive_close_count();
		g_statistics_bureau.inc_total_sess_time_duration(now - _syn_sending_time);
		_traffic_history.push_back(pkt);
		kill_me(PASSIVE_CLOSE);
		return;
	}
}

void tcpsession::fin_wait_1_state_handler(boost::shared_ptr<ip_pkt> pkt)
{
	bool my_fin_has_been_acked;
	uint32_t ack_seq;

	ack_seq = pkt->get_ack_seq();
	if (pkt->is_ack_set() && seq_before_eq(_expected_last_ack_seq_from_peer, ack_seq))
	{
		my_fin_has_been_acked = true;
		_my_fin_acked_time = g_timer.get_jiffies();
	}
	else
	{
		my_fin_has_been_acked = false;
	}

	if (my_fin_has_been_acked && !pkt->is_fin_set() )
	{
		_current_state = tcpsession::FIN_WAIT_2;
		g_logger.printf("session: %s.%hu moves to state FIN_WAIT_2 from state FIN_WAIT_1.\n",
				_client_src_ip_str.c_str(), _client_src_port);
	}
	else if (my_fin_has_been_acked && pkt->is_fin_set())
	{
		_current_state = tcpsession::TIME_WAIT;
		g_logger.printf("session: %s.%hu moves to state TIME_WAIT from state FIN_WAIT_1.\n",
				_client_src_ip_str.c_str(), _client_src_port);
	}
	else if(pkt->is_fin_set())
	{
		_current_state = tcpsession::CLOSING;
		g_logger.printf("session: %s.%hu moves to state CLOSING from state FIN_WAIT_1.\n",
				_client_src_ip_str.c_str(), _client_src_port);
	}

	refresh_status(pkt);
	if (my_fin_has_been_acked)
	{
		if (_ippkts_samples.empty())
		{
			boost::shared_ptr<ip_pkt> pure_ack = build_an_ack_without_payload(_last_seq_beyond_fin_at_localhost_side);
			_ippkts_samples.push_back(pure_ack);
		}
		_sliding_window_left_boundary = _ippkts_samples.begin();
		_sliding_window_right_boundary = _ippkts_samples.end();
	}
}

void tcpsession::fin_wait_2_state_handler(boost::shared_ptr<ip_pkt> pkt)
{
	uint64_t now;
	now = g_timer.get_jiffies();
	// my impatience is limited. My FIN has been sent for a long time without your FIN as a response.
	// I will commit a suicide.
	if (now - _last_recorded_recv_time > _wait_for_fin_from_peer_time_out)
	{
		g_logger.printf("session: %s.%hu No patience for your FIN. I commit a suicide.\n",
				_client_src_ip_str.c_str(), _client_src_port);
		g_statistics_bureau.inc_sess_active_close_timeout_count();
		_traffic_history.push_back(pkt);
		kill_me(NO_FIN_FROM_PEER);
		return;
	}

	if (pkt->is_fin_set())
	{
		_current_state = tcpsession::TIME_WAIT;
		g_logger.printf("session: %s.%hu moves to state TIME_WAIT from state FIN_WAIT_2.\n",
				_client_src_ip_str.c_str(), _client_src_port);
	}

	refresh_status(pkt);

	if (pkt->get_tcp_payload_len())
	{
		if (_ippkts_samples.empty())
		{
			boost::shared_ptr<ip_pkt> pure_ack = build_an_ack_without_payload(_last_seq_beyond_fin_at_localhost_side);
			_ippkts_samples.push_back(pure_ack);
		}
		_sliding_window_left_boundary = _ippkts_samples.begin();
		_sliding_window_right_boundary = _ippkts_samples.end();
	}
}

void tcpsession::closing_state_handler(boost::shared_ptr<ip_pkt> pkt)
{
	uint32_t ack_seq;

	ack_seq = pkt->get_ack_seq();
	if (pkt->is_ack_set() && seq_before_eq(_expected_last_ack_seq_from_peer, ack_seq))
	{
		_current_state = tcpsession::TIME_WAIT;
		g_logger.printf("session: %s.%hu moves to state TIME_WAIT from state CLOSING.\n",
				_client_src_ip_str.c_str(), _client_src_port);
		_my_fin_acked_time = g_timer.get_jiffies();
	}
	refresh_status(pkt);

	if (_ippkts_samples.empty())
	{
		boost::shared_ptr<ip_pkt> pure_ack = build_an_ack_without_payload(_last_seq_beyond_fin_at_localhost_side);
		_ippkts_samples.push_back(pure_ack);
	}
	_sliding_window_left_boundary = _ippkts_samples.begin();
	_sliding_window_right_boundary = _ippkts_samples.end();
}

void tcpsession::time_wait_state_handler(boost::shared_ptr<ip_pkt> pkt)
{
	refresh_status(pkt);

	if (_ippkts_samples.empty())
	{
		boost::shared_ptr<ip_pkt> pure_ack = build_an_ack_without_payload(_last_seq_beyond_fin_at_localhost_side);
		_ippkts_samples.push_back(pure_ack);
	}
	_sliding_window_left_boundary = _ippkts_samples.begin();
	_sliding_window_right_boundary = _ippkts_samples.end();
}

std::list<boost::shared_ptr<ip_pkt> >::iterator tcpsession::check_ippkts_continuity(
		std::list<boost::shared_ptr<ip_pkt> >::iterator begin,
		std::list<boost::shared_ptr<ip_pkt> >::iterator end)
{
	uint32_t seq, expected_next_seq;
	int tcp_payload_len;
	std::list<boost::shared_ptr<ip_pkt> >::iterator ite, ite_pre;

	ite = begin;
	ite_pre = ite;
	if (begin == end)
	{
		return ite_pre;
	}

	seq = (*ite)->get_seq();
	expected_next_seq = seq + (*ite)->get_tcp_payload_len();
	if ((*ite)->is_syn_set())
	{
		expected_next_seq++;
	}
	++ite;

	for (; ite != end; ++ite)
	{
		seq = (*ite)->get_seq();
		if(expected_next_seq != seq)
		{
			break;
		}
		tcp_payload_len = (*ite)->get_tcp_payload_len();
		assert(tcp_payload_len >= 0);
		expected_next_seq += tcp_payload_len;
		ite_pre = ite;
	}

	return ite_pre;
}

void tcpsession::adjust_sliding_window()
{
	int distance;
	std::list<boost::shared_ptr<ip_pkt> >::iterator ite;

	// should the sliding window be reduced.
	int current_sliding_win_size = 0;
	int ippkt_count_walked_through = 0;
	for (ite = _sliding_window_left_boundary;
			ite != _sliding_window_right_boundary;)
	{
		current_sliding_win_size += (*ite)->get_tot_len();
		if (current_sliding_win_size > _advertised_window_size)
		{
			// make sure at least one IP packet are available to be sent.
			if(0 == ippkt_count_walked_through)
			{
				break;
			}
			else  // reduce the window size
			{
				// update the right boundary.
				_sliding_window_right_boundary = ite;
				break;
			}
		}
		ippkt_count_walked_through++;
		++ite;
	}

#ifdef _DEBUG_
	distance = std::distance(_sliding_window_left_boundary, _sliding_window_right_boundary);
	g_logger.printf("%d packet(s) is(are) in the sliding window.\n", distance);
#endif

	// should the sliding window size be increased.
	if (current_sliding_win_size < _advertised_window_size)
	{
		// try to determine how far it can go to increase sliding window.
		std::list<boost::shared_ptr<ip_pkt> >::iterator right_gap, ite_left;
		if (_sliding_window_right_boundary != _ippkts_samples.end()) // got the chance to expand the window
		{
			ite_left = _sliding_window_left_boundary;
			right_gap = check_ippkts_continuity(ite_left, _ippkts_samples.end());

			assert(right_gap != _ippkts_samples.end());
			// increase it because of open interval (excluding right boundary)
			++right_gap;
		}
		else // cannot expand the window size by any means.
		{
			right_gap = _sliding_window_right_boundary;
		}

		while (current_sliding_win_size < _advertised_window_size
				&& _sliding_window_right_boundary != right_gap)
		{
			++_sliding_window_right_boundary;
			current_sliding_win_size += (*ite)->get_tot_len();
			if (current_sliding_win_size > _advertised_window_size)
			{
				break;
			}
		}

#ifdef _DEBUG_
		distance = std::distance(_sliding_window_left_boundary, _sliding_window_right_boundary);

		g_logger.printf("sliding window has been expanded to %d packets.\n", distance);
		g_logger.printf("%d packet(s) is(are) in the _ippkts_samples.\n", _ippkts_samples.size());
#endif
	}
}

void tcpsession::refresh_status(boost::shared_ptr<ip_pkt> pkt)
{
	uint32_t seq;
	uint32_t ack_seq;
	uint32_t ack_seq_tmp;
	uint16_t win_size_saved;

	std::list<boost::shared_ptr<ip_pkt> >::iterator ite;

	seq = pkt->get_seq();
	ack_seq = pkt->get_ack_seq();

	// the following logic compute some sequence number
	if (pkt->is_syn_set() && pkt->is_ack_set())   // the second handshake.
	{
		_expected_next_sequence_from_peer = pkt->get_seq() + 1;
		_latest_acked_sequence_by_peer = pkt->get_ack_seq();
		_advertised_window_size = pkt->get_win_size();
	}
	else
	{
		uint32_t next_sequence_from_peer = pkt->get_seq() + pkt->get_tcp_payload_len();
		if (seq == _expected_next_sequence_from_peer)
		{
			_expected_next_sequence_from_peer = next_sequence_from_peer;
			if (pkt->is_fin_set())
			{
				_expected_next_sequence_from_peer++;
			}
		}
		else
		{
			// drop the outdated incoming packets.
			if(seq_before(next_sequence_from_peer, _expected_next_sequence_from_peer))
			{
				return;
			}
			else  // lost packets or packets are out of order. just let it go.
			{
				// NOTICE. Packets losing or packets out of order will be found in the traffic history.
			}
		}
	}

	if (pkt->is_ack_set() && !pkt->is_syn_set())
	{
		// the peer acked new packet.
		if (seq_before(_latest_acked_sequence_by_peer, ack_seq))
		{
			_latest_acked_sequence_by_peer = ack_seq;
		}
	}

	// eliminate acked packets.
	for (ite = _sliding_window_left_boundary;
			ite != _sliding_window_right_boundary;)
	{
		if (seq_before((*ite)->get_seq(), _latest_acked_sequence_by_peer))
		{
			_traffic_history.push_back(*ite);  // save the outgoing packets that have been sent
			_ippkts_samples.erase(ite++);
			_sliding_window_left_boundary = ite;
		}
		else
		{
			break;
		}
	}
	_traffic_history.push_back(pkt);  // save the incoming traffic.

	win_size_saved = _advertised_window_size;
	_advertised_window_size = pkt->get_win_size();

	adjust_sliding_window();
}
