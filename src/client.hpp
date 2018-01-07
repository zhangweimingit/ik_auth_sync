#ifndef CLIENT_HPP
#define CLIENT_HPP

#include "auth_message.hpp"
#include "kernel_event.hpp"
#include <boost/asio.hpp>
#include <string>

using std::string;
using boost::asio::io_service;
using boost::asio::ip::tcp;
using boost::system::error_code;
using boost::asio::local::datagram_protocol;
using boost::asio::posix::stream_descriptor;


class client
{

public:
	client(io_service& io_service, const string& address, const string& port,
	int host_pipe, int auth_pipe,const string& dhcp_path, KernelEvtThr& kernel_event);

	void start1();//Read host information from pipes and DHCP
	void start2();//Read auth information from pipes and send to server
	void close();//close tcp socket
	void operator()(boost::system::error_code ec = boost::system::error_code(), std::size_t n = 0);

private:
	void do_read_host_pipe();
	void handle_host_pipe(const error_code&ec, std::size_t);
	void do_read_auth_pipe();
	void handle_read_dhcp(const boost::system::error_code&ec, std::size_t);
	void do_read_dhcp();
	void handle_read_auth_pipe(const boost::system::error_code&ec, std::size_t);

	boost::asio::io_service& io_service_;
	auth_message auth_message_;
	std::string address_;
	std::string port_;
	tcp::socket socket_;
	stream_descriptor host_pipe_;
	stream_descriptor auth_pipe_;
	datagram_protocol::socket dhcp_sock_;
	KernelEvtThr& kernel_event_;
	std::map<std::string, auth_info> mac_auth_;

	union 
	{
		kernel_info kernel_host_info_;
		char host_buffer_[sizeof(kernel_info)];
	};

	union
	{
		kernel_info kernel_auth_info_;
		char auth_buffer_[sizeof(kernel_info)];
	};

	char dhcp_buffer_[128];
	boost::asio::coroutine coroutine_;
};

#endif