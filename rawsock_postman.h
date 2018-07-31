/*********************************************
 * rawsockpostmann.h
 * Author: kamuszhou@tencent.com kamuszhou@qq.com
 * website: v.qq.com  http://blog.ykyi.net
 * Created on: 25 Mar, 2014
 * Praise Be to the Lord. BUG-FREE CODE !
 ********************************************/

#ifndef _RAWSOCK_POSTMANN_H_
#define _RAWSOCK_POSTMANN_H_

#include "postman.h"

class rawsock_postman : public postman
{
public:
	rawsock_postman();
	virtual ~rawsock_postman();

private:
	virtual void get_ready4subclass();
	virtual void recv_impl();

private:
	int _recv_fd;
	int _svr_port;
	int _l2hdr_len; ///< layer 2 header length
	char _buff[8192];
};

#endif /* _RAWSOCK_POSTMANN_H_ */
