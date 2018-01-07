#include "client.hpp"
#include "auth_config.hpp"
#include <unistd.h>
#include <functional>
#include <sstream>
#include <iostream>
#include <boost/asio/yield.hpp>

using namespace std;
using std::placeholders::_1;
using std::placeholders::_2;
using boost::system::error_code;
using boost::serialization::singleton;

client::client(boost::asio::io_service& io_service, const std::string& address, const std::string& port,
	int host_pipe, int auth_pipe, const std::string&dhcp_path, KernelEvtThr& kernel_event)
	: io_service_(io_service),
	address_(address), port_(port),
	socket_(io_service),
	host_pipe_(io_service, host_pipe),
	auth_pipe_(io_service, auth_pipe),
	dhcp_sock_(io_service, dhcp_path),
	kernel_event_(kernel_event)
{
}
void client::start1()
{
	do_read_host_pipe();
	do_read_dhcp();
}

void client::start2()
{
	boost::system::error_code ec;
	tcp::resolver resolver(io_service_);
	tcp::resolver::query query(address_, port_);
	tcp::resolver::iterator iterator = resolver.resolve(query);
	boost::asio::connect(socket_, iterator);

	do_read_auth_pipe();
	(*this)();
}
void client::operator()(boost::system::error_code ec, std::size_t n)
{
	auth_info auth;

	if (!ec) reenter(this) for (;;)
	{

		yield boost::asio::async_read(socket_, boost::asio::buffer(auth_message_.header_buffer_),std::ref(*this));
		auth_message_.parse_header();
		yield boost::asio::async_read(socket_, boost::asio::buffer(auth_message_.recv_body_), std::ref(*this));
		switch (auth_message_.header_.type_)
		{
		case CHECK_CLIENT:
			auth_message_.parse_check_client_req_msg();
			auth_message_.constuct_check_client_res_msg();
			yield boost::asio::async_write(socket_, auth_message_.send_buffers_, std::ref(*this));
			break;
		case AUTH_RESPONSE:
			auth_message_.parse_auth_res_msg(auth);
			auth.auth_time_ = time(0);
			mac_auth_[auth.mac_] = auth;
			break;
		default:
			break;
		}
	}
	else
	{
		socket_.close();
		throw boost::system::system_error(ec);
	}
}
void client::do_read_host_pipe()
{
	boost::asio::async_read(host_pipe_, boost::asio::buffer(host_buffer_), 
		std::bind(&client::handle_host_pipe,this,_1, _2));
}

void client::handle_host_pipe(const boost::system::error_code&ec, std::size_t)
{
	if (!ec)
	{
		std::cout << "client recv host from kernel" << kernel_host_info_.mac_ << std::endl;
		if (mac_auth_.count(kernel_host_info_.mac_))
		{
			auto & auth = mac_auth_[kernel_host_info_.mac_];
			if ((time(NULL) - auth.auth_time_) < auth.duration_)
			{
				kernel_info info;
				memcpy(info.mac_, auth.mac_.c_str(),mac_str_len);
				info.mac_[mac_str_len] = '\0';
				info.attr_ = auth.attr_;
				//kernel_event_.(info);
				std::ostringstream output;
				output << "/usr/ikuai/ssend_auth_to_kernelcript/Action/webauth-up  remote_auth_sync mac=" << auth.mac_ << "  authtype=" << auth.attr_ << " timeout=" << auth.duration_ - (time(NULL) - auth.auth_time_);
				system(output.str().c_str());
				std::cout << "send auth to kernel " << kernel_host_info_.mac_ << std::endl;
			}
			else
			{
				mac_auth_.erase(kernel_host_info_.mac_);
			}
		}
		do_read_host_pipe();
	}
	else
	{
		exit(1);
	}
}
void client::do_read_auth_pipe()
{
	boost::asio::async_read(auth_pipe_, boost::asio::buffer(auth_buffer_),
		std::bind(&client::handle_read_auth_pipe, this, _1, _2));
}
void client::handle_read_auth_pipe(const boost::system::error_code&ec, std::size_t)
{
	auth_config& sync_config = singleton<auth_config>::get_mutable_instance();
	if (!ec)
	{
		std::cout << "client recv auth from kernel " << kernel_auth_info_.mac_ << std::endl;
		if (socket_.is_open())
		{
			auth_info info;
			info.mac_ = kernel_auth_info_.mac_;
			info.attr_ = kernel_auth_info_.attr_;
			info.duration_ = sync_config.expired_time;
			auth_message_.constuct_auth_res_msg(info);
			boost::asio::async_write(socket_, boost::asio::buffer(auth_message_.send_buffers_),
				[](const boost::system::error_code&ec, size_t bytes_transfered) {});
			do_read_auth_pipe();
		}

	}
	else
	{
		exit(1);
	}
}
void client::do_read_dhcp()
{
	dhcp_sock_.async_receive(boost::asio::buffer(dhcp_buffer_),
		std::bind(&client::handle_read_dhcp, this, _1, _2));
}

void client::handle_read_dhcp(const boost::system::error_code&ec, std::size_t)
{
	if (!ec)
	{
		string dhcp(dhcp_buffer_);
		string::size_type pos = dhcp.find('|');
		if (pos != string::npos && pos < dhcp.size() - 1)
		{
			string mac = dhcp.substr(pos + 1, mac_str_len);
			cout << "dhcp new host " << mac << " found" << endl;
			if (mac_auth_.count(mac))
			{
				auto & auth = mac_auth_[mac];
				if ((time(NULL) - auth.auth_time_) < auth.duration_)
				{
					kernel_info info;
					memcpy(info.mac_, auth.mac_.c_str(), mac_str_len);
					info.mac_[mac_str_len] = '\0';
					info.attr_ = auth.attr_;
					//kernel_event_.send_auth_to_kernel(info);
					std::ostringstream output;
					output << "/usr/ikuai/script/Action/webauth-up  remote_auth_sync mac=" << auth.mac_ << "  authtype=" << auth.attr_ << " timeout=" << auth.duration_ - (time(NULL) - auth.auth_time_);
					system(output.str().c_str());
				}
				else
				{
					mac_auth_.erase(mac);
				}
			}
		}
		do_read_dhcp();
	}
	else
	{
		exit(1);
	}

}


