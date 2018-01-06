#include "client.hpp"
#include <functional>
#include <boost/asio/yield.hpp>
using std::placeholders::_1;
using boost::system::error_code;

client::client(boost::asio::io_service& io_service, const std::string& address, const std::string& port)
	: socket_(io_service)
{
	boost::system::error_code ec;
	tcp::resolver resolver(io_service);
	tcp::resolver::query query(address, port);
	tcp::resolver::iterator iterator = resolver.resolve(query);

	boost::asio::connect(socket_, iterator);
}

void client::operator()(error_code ec, std::size_t n)
{
	if (!ec) reenter(this)
	{
		for (;;)
		{
			yield boost::asio::async_read(socket_, boost::asio::buffer(auth_message_.header_buffer_),*this);
			auth_message_.parse_header();
			yield boost::asio::async_read(socket_, boost::asio::buffer(auth_message_.recv_body_), *this);
			switch (auth_message_.header_.type_)
			{
			case CHECK_CLIENT:
				auth_message_.parse_check_client_req_msg();
				auth_message_.constuct_check_client_res_msg();
				yield boost::asio::async_write(socket_, boost::asio::buffer(auth_message_.send_buffers_), *this);
				break;
			default:
				break;
			}
		}
	}
}


void client::send_auth_info(const auth_info& msg)
{
	socket_.get_io_service().post(std::bind(&client::do_send_auth_info, this, msg));
}

void client::do_send_auth_info(const auth_info& msg)
{
	auth_message_.constuct_auth_res_msg(msg);
	boost::asio::async_write(socket_, boost::asio::buffer(auth_message_.send_buffers_),
		[](const error_code&ec, size_t bytes_transfered) {});
}