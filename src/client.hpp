#ifndef CLIENT_HPP
#define CLIENT_HPP

#include "auth_message.hpp"
#include <boost/asio.hpp>

using boost::asio::ip::tcp;
class client:boost::asio::coroutine
{
public:
	client(boost::asio::io_service& io_service, const std::string& address, const std::string& port);

	void operator()(boost::system::error_code ec = boost::system::error_code(), std::size_t n = 0);

	void send_auth_info(const auth_info& msg);
	void do_send_auth_info(const auth_info& msg);

private:
	auth_message auth_message_;
	tcp::socket socket_;
};

#endif