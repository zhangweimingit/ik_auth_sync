#include "client.hpp"
#include "auth_config.hpp"
#include <unistd.h>
#include <functional>
#include <sstream>
#include <iostream>
#include <boost/asio/yield.hpp>

using std::placeholders::_1;
using std::placeholders::_2;
using boost::serialization::singleton;
using boost::asio::async_read;
using boost::asio::async_write;

//Constructor
client::client(io_service& io_service, tcp::resolver::iterator iterator)
	: iterator_(iterator),
	socket_(io_service)
{
}

void client::start1()
{
	int newhost_pipe[2];
	int newauth_pipe[2];

	if (pipe(newhost_pipe)) 
	{
		std::cerr << "Fail to open newhost pipe" << std::endl;
		exit(1);
	}
	if (pipe(newauth_pipe)) 
	{
		std::cerr << "Fail to open newauth pipe" << std::endl;
		exit(1);
	}

	kernel_event_ = std::make_shared<KernelEvtThr>(newhost_pipe[1], newauth_pipe[1]);

	if (!kernel_event_->init())
	{
		std::cerr << "Fail to init event thr" << std::endl;
		exit(1);
	}

	if (!kernel_event_->start())
	{
		std::cerr << "Fail to start event thr" << std::endl;
		exit(1);
	}

	host_pipe_ = std::make_shared<stream_descriptor>(socket_.get_io_service(), newhost_pipe[0]);
	auth_pipe_ = std::make_shared<stream_descriptor>(socket_.get_io_service(), newauth_pipe[0]);
	
	std::remove("/tmp/dhcp_option_info_auth");
	dhcp_sock_ = std::make_shared<datagram_protocol::socket>(socket_.get_io_service(), "/tmp/dhcp_option_info_auth");

	do_read_host_pipe();
	do_read_dhcp();
}

void client::start2(const error_code& ec)
{
	if (!ec)
	{
		boost::asio::connect(socket_, iterator_);

		std::cout << "success to connect server!" << std::endl;
		//must init
		coroutine_ = boost::asio::coroutine();

		//execute coroutine
		(*this)();

	}
	else
	{
		throw boost::system::system_error(ec);
	}

}

void client::close()
{
	error_code ignore_error;
	socket_.close(ignore_error);
}

void client::operator()(error_code ec, std::size_t n)
{
	if (!ec) reenter(coroutine_) for (;;)
	{
		//read header
		yield async_read(socket_, boost::asio::buffer(auth_message_.header_buffer_),std::ref(*this));
		auth_message_.parse_header();

		//read body
		yield async_read(socket_, boost::asio::buffer(auth_message_.recv_body_), std::ref(*this));

		if (auth_message_.header_.type_ == CHECK_CLIENT)
		{
			auth_message_.parse_check_client_req_msg();
			auth_message_.constuct_check_client_res_msg();
			yield async_write(socket_, auth_message_.send_buffers_, std::ref(*this));
			do_read_auth_pipe();//Auth information can be read only when server is authed
		}
		else if (auth_message_.header_.type_ == AUTH_RESPONSE)
		{
			auth_info auth;
			auth_message_.parse_auth_res_msg(auth);
			mac_auth_[auth.mac_] = auth; 
			std::cout << "recv auth from server mac is " << auth.mac_ << " attr is " << auth.attr_
				<< "duration is " << auth.duration_ << std::endl;
		}
	}
	else
	{
		error_code ignore_error;
		socket_.close(ignore_error);
		throw boost::system::system_error(ec);
	}
}

void client::do_read_host_pipe()
{
	async_read(*host_pipe_, boost::asio::buffer(host_buffer_), 
		std::bind(&client::handle_host_pipe, this, _1, _2));
}

void client::handle_host_pipe(const error_code&ec, std::size_t)
{
	if (!ec)
	{
		std::cout << "client recv host from kernel " << kernel_host_info_.mac_ << std::endl;
		find_auth_info_to_kernel(kernel_host_info_.mac_);
		do_read_host_pipe();
	}
	else
	{
		std::cerr << "read host pipe error!!" << std::endl;
		exit(1);
	}
}

void client::do_read_auth_pipe()
{
	async_read(*auth_pipe_, boost::asio::buffer(auth_buffer_),
		std::bind(&client::handle_read_auth_pipe, this, _1, _2));
}

void client::handle_read_auth_pipe(const error_code&ec, std::size_t)
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
			async_write(socket_, auth_message_.send_buffers_,[](const error_code&ec, size_t) {});
			do_read_auth_pipe();
		}

	}
	else
	{
		std::cerr << "read auth pipe error!!" << std::endl;
		exit(1);
	}
}

void client::do_read_dhcp()
{
	dhcp_sock_->async_receive(boost::asio::buffer(dhcp_buffer_),
		std::bind(&client::handle_read_dhcp, this, _1, _2));
}

void client::handle_read_dhcp(const boost::system::error_code&ec, std::size_t)
{
	if (!ec)
	{
		string dhcp(dhcp_buffer_);
		std::cout << "recv dhcp: " << dhcp << std::endl;
		string::size_type pos = dhcp.find('|');
		string mac = dhcp.substr(pos + 1, mac_str_len);
		find_auth_info_to_kernel(mac);
		do_read_dhcp();
	}
	else
	{
		std::cerr << "read dhcp socket error!!" << std::endl;
		exit(1);
	}

}

void client::find_auth_info_to_kernel(const string& mac)
{
	if (mac_auth_.count(mac))
	{
		auto & auth = mac_auth_[mac];

		if ( (time(0) - auth.auth_time_) < auth.duration_)
		{
			kernel_info info;
			memcpy(info.mac_, auth.mac_.data(), mac_str_len);
			info.mac_[mac_str_len] = '\0';
			info.attr_ = auth.attr_;
			kernel_event_->send_auth_to_kernel(info);

			std::ostringstream output;
			output << "/usr/ikuai/script/Action/webauth-up  remote_auth_sync mac="
				<< auth.mac_ << "  authtype=" << auth.attr_ << " timeout=" << auth.duration_ - (time(NULL) - auth.auth_time_);
			system(output.str().c_str());
			std::cout << "send_auth_to_kernel" << std::endl;
		}
		else
		{
			mac_auth_.erase(mac);
		}
	}
}
