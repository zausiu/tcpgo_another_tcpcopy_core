/*********************************************
 * tcpsession.h
 * Author: kamuszhou@tencent.com, kamuszhou@qq.com
 * website: http://blog.ykyi.net
 * Created on: Dec 9, 2013
 * Praise Be to the Lord. BUG-FREE CODE !
 ********************************************/

#ifndef _TCPSESSION_H_
#define _TCPSESSION_H_

#include <list>
#include "misc.h"
#include "postoffice.h"
#include "ip_pkt.h"

class tcpsession : public postoffice_callback_interface
{
public:
	/**
	 *@param port in network byte order.
	 */
	tcpsession(int asio_idx, uint32_t ip, uint16_t port);
	tcpsession();
	virtual ~tcpsession();

	/**
	 * adds a ip packet to this session as a sample.
	 * used when ip packets are read from pcap file.
	 */
	void append_ip_sample(boost::shared_ptr<ip_pkt> ippkt);

	/**
	 * invoked when ip packets are from real time traffic.
	 */
	void inject_a_realtime_ippkt(boost::shared_ptr<ip_pkt> ippkt);

	/**
	 * as the function name suggests. rt is real time for short.
	 */
	void injecting_rt_traffic_timeout_checker(const boost::system::error_code& error);

	/**
	 * This function will also remove ack packets without playload.
	 * @return return 0 if all packets in this session is consecutive and other conditions are met,
	 * otherwise return non-zero error code.
	 */
	int sanitize();

	/**
	 * This session is for real time traffic.
	 */
	void get_ready_for_rt_traffic();

	/**
	 * This session is for offline traffic.
	 */
	void get_ready_for_offline_traffic();

	const std::string& get_client_src_ip_str()const
	{
		return _client_src_ip_str;
	}

	uint16_t get_client_src_port()const
	{
		return _client_src_port;
	}

	uint64_t get_session_key()
	{
		return _session_key;
	}

	// create a clone of myself, with source IP changed.
	boost::shared_ptr<tcpsession> clone();

public:
	/// refer to the interface postoffice_callback_interface for details.
	virtual int pls_send_these_packets(std::vector<boost::shared_ptr<ip_pkt> >& pkts);
	virtual void got_a_packet(boost::shared_ptr<ip_pkt> ippkt);

public:
    /// declares causes of session death.
	/// PHANTOM: is used for debug's purpose.
	enum cause_of_death{ACTIVE_CLOSE = 1, PASSIVE_CLOSE, PEER_TIME_OUT, DORMANCY, RESET, NO_FIN_FROM_PEER, PHANTOM};

	static const char* map_cause_code_to_str(tcpsession::cause_of_death casue)
	{
		switch(casue)
		{
		case ACTIVE_CLOSE:
			return "ACTIVE_CLOSE";

		case PASSIVE_CLOSE:
			return "PASSIVE_CLOSE";

		case PEER_TIME_OUT:
			return "PEER_TIME_OUT";

		case DORMANCY:
			return "DORMANCY";

		case RESET:
			return "RESET";

		case NO_FIN_FROM_PEER:
			return "NO_FIN_FROM_PEER";

		default:
			return "PHANTOM";
		}
	}

private:
	void get_ready();

	/// a. in the case of active close and the sent FIN has be acked by peer, _ippkts_samples is empty at this time
	/// if a tcp segment received, ack cann't be piggybacked by sample, so create a pure ack without payload just
	/// for the sake of acknowledge.
	/// b. in the case of passive close. The some logic applies.
	boost::shared_ptr<ip_pkt> build_an_ack_without_payload(uint32_t seq);

private:
	/// eleven member functions for their respective TCP state.
	void closed_state_handler(boost::shared_ptr<ip_pkt> pkt);
	void listen_state_handler(boost::shared_ptr<ip_pkt> pkt);
	void syn_rcvd_state_handler(boost::shared_ptr<ip_pkt> pkt);
	void syn_sent_state_handler(boost::shared_ptr<ip_pkt> pkt);
	void established_state_handler(boost::shared_ptr<ip_pkt> pkt);
	void close_wait_state_handler(boost::shared_ptr<ip_pkt> pkt);
	void last_ack_state_handler(boost::shared_ptr<ip_pkt> pkt);
	void fin_wait_1_state_handler(boost::shared_ptr<ip_pkt> pkt);
	void fin_wait_2_state_handler(boost::shared_ptr<ip_pkt> pkt);
	void closing_state_handler(boost::shared_ptr<ip_pkt> pkt);
	void time_wait_state_handler(boost::shared_ptr<ip_pkt> pkt);

private:
	/**
	 * @param begin closed interval
	 * @param end open interval
	 * @return a iterator that points to the leftmost ip packet that is in a continuous sequence.
	 */
	std::list<boost::shared_ptr<ip_pkt> >::iterator check_ippkts_continuity(
			std::list<boost::shared_ptr<ip_pkt> >::iterator begin,
			std::list<boost::shared_ptr<ip_pkt> >::iterator end
			);

	/**
	 * @param advertised_window_size adjust the sliding window based on the advertised window size.
	 */
	void adjust_sliding_window();

	void refresh_status(boost::shared_ptr<ip_pkt> pkt);

	void kill_me(cause_of_death cause);

	bool still_alive();

private:
	///< The ip packages which will be used to emulate the pseudo-client.
	std::list<boost::shared_ptr<ip_pkt> >  _ippkts_samples;

	///< Records the traffic of this session.
	std::list<boost::shared_ptr<ip_pkt> > _traffic_history;

	char _pure_ack_template[40];   ///< a template to create a ack without payload.
	char _pure_rst_template[40];   ///< a template to create a rst without payload.

	// reserved for the possible future version if i can still play with this stuff.
//	std::list<ip_pkt>  _ippkts_received;   // The ip packages received from the server will be saved here.

	/// eleven industry standard TCP state.
	/// refer to http://en.wikipedia.org/wiki/File:Tcp_state_diagram_fixed.svg. (recv/send)
	enum tcp_state_machine{CLOSED, LISTEN, SYN_RCVD, SYN_SENT, ESTABLISHED, CLOSE_WAIT, LAST_ACK, FIN_WAIT_1,
			FIN_WAIT_2, CLOSING, TIME_WAIT};
	tcp_state_machine _current_state;
	uint32_t _expected_next_sequence_from_peer;   ///< in host byte order
	uint32_t _latest_acked_sequence_by_peer;      ///< in host byte order. It's the seq_ack in the latest peer's response packet.
	uint32_t _last_seq_beyond_fin_at_localhost_side;   ///< in host byte order
	uint32_t _expected_last_ack_seq_from_peer;    ///< in host byte order
	int _advertised_window_size;                  ///< in host byte order
	std::list<boost::shared_ptr<ip_pkt> >::iterator _sliding_window_left_boundary;  ///< closed interval (including)
	std::list<boost::shared_ptr<ip_pkt> >::iterator _sliding_window_right_boundary; ///< open interval (excluding)

	uint64_t _syn_sending_time;       ///< record the first time the syn is sent.

	uint64_t _last_recorded_recv_time;   ///< used for session timeout
	uint64_t _last_recorded_recv_time_with_payload; ///< won't count pure ack packet.
	int      _response_from_peer_time_out;    ///< in unit of jiffy. refer to class the_timer

	uint64_t _last_recorded_snd_time;    ///< sending speed control and detect disabled tcp session.
	int      _retransmit_time_interval;         ///< in unit of jiffy.
	int      _have_to_send_data_within_this_timeperiod;  ///< self-explanatory

	uint64_t _my_fin_acked_time;         ///< don't wanna wait for fin from peer forever
	int      _wait_for_fin_from_peer_time_out; ///< as the variable name suggests.

	uint32_t _client_src_ip_num;
	std::string _client_src_ip_str;
	uint16_t _client_src_port;      ///< in host byte order

	uint64_t _session_key;

	bool _dead;
	bool _enable_active_close;     ///< default to false. That means tcpsession default to close passively.

	bool _reset_the_peer;   ///< indicate if a RESET packet will be sent when session closes ungracefully.

	/**
	 * ACCUMULATING_TRAFFIC: effective when capture real time traffic.
	 * SENDING_TRAFFIC: as the name suggests.
	 * ABORT: abort this session.
	 */
	enum sess_state{ACCUMULATING_TRAFFIC, SENDING_TRAFFIC, ABORT};
	sess_state _sess_state;
	uint64_t _last_injecting_rt_traffic_time;
	boost::shared_ptr<boost::asio::deadline_timer> _injecting_rt_traffic_timer;
	bool _got_syn_pkt;
	bool _got_fin_pkt;

	bool _ready;  ///< indicate if this tcpsession instance has called get_ready() yet

	int _asio_idx;

#ifdef _DEBUG
	static boost::atomic_long _ended_sess_count;
#endif
};

#endif /* _TCPSESSION_H_ */
