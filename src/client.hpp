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
	client(io_service& io_service, tcp::resolver::iterator iterator);

	void start1();//Read host information from pipes and DHCP
	void start2(const error_code& ec);//Read auth information from pipes and send to server
	void close();//close tcp socket

	//main loop
	void operator()(error_code ec = error_code(), std::size_t n = 0);

private:
	void do_read_host_pipe();
	void handle_host_pipe(const error_code& ec, std::size_t);

	void do_read_auth_pipe();
	void handle_read_auth_pipe(const error_code&ec, std::size_t);

	void do_read_dhcp();
	void handle_read_dhcp(const error_code&ec, std::size_t);

	void find_auth_info_to_kernel(const string& mac);

	tcp::resolver::iterator iterator_;

	tcp::socket socket_;
	std::shared_ptr<stream_descriptor> host_pipe_;
	std::shared_ptr<stream_descriptor> auth_pipe_;
	std::shared_ptr<datagram_protocol::socket> dhcp_sock_;

	//Provides an interface to send authentication information to the kernel
	std::shared_ptr<KernelEvtThr> kernel_event_;

	//buffer for tcp socket
	auth_message auth_message_;

	//buffer for recv host info from kernel host pipe
	union 
	{
		kernel_info kernel_host_info_;
		char host_buffer_[sizeof(kernel_info)];
	};

	 //buffer for recv auth info from kernel auth pipe
	union
	{
		kernel_info kernel_auth_info_;
		char auth_buffer_[sizeof(kernel_info)];
	};

	//buffer for recv dhcp host from unix domain socket
	char dhcp_buffer_[128];

	//Storing all authentication information
	std::map<string, auth_info> mac_auth_;

	// stackless coroutines
	boost::asio::coroutine coroutine_;
};

#endif