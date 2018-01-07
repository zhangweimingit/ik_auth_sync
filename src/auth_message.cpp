#include "auth_message.hpp"
#include "auth_config.hpp"
#include <iostream>
#include <algorithm>
#include <stdexcept>
#include <random>
#include <sstream>
#include <boost/archive/binary_iarchive.hpp>
#include <boost/archive/binary_oarchive.hpp>
#include "md5.hpp"

using namespace std;
using boost::serialization::singleton;
using boost::asio::detail::socket_ops::host_to_network_short;
using boost::asio::detail::socket_ops::network_to_host_short;


//The head must be set before sending
void auth_message::set_header(Msg_Type type)
{
	header_.version_ = 1;
	header_.type_ = type;
	header_.len_ = host_to_network_short(send_body_.size());
	header_.res1_ = 0;
	header_.res2_ = 0;
}

//Parsing the header information received from the server
void auth_message::parse_header()
{
	header_.len_  = network_to_host_short(header_.len_);
	header_.res1_ = network_to_host_short(header_.res1_);
	header_.res2_ = network_to_host_short(header_.res2_);

	if (header_.version_ != 1 || header_.len_ == 0)
	{
		throw runtime_error("header invalid");
	}
	if (header_.type_ == MSG_INVALID_TYPE || header_.type_ >= MSG_TYPE_NR) 
	{
		throw runtime_error("header type invalid");
	}

	recv_body_.resize(header_.len_);//Adjust the size, be ready to accept the message body
}

//Return the authentication information to the server
void auth_message::constuct_check_client_res_msg()
{
	std::ostringstream os;
	boost::archive::binary_oarchive oa(os);
	oa << server_chap_;
	send_body_ = os.str();

	set_header(CHECK_CLIENT_RESPONSE);
	send_buffers_.clear();
	send_buffers_.push_back(boost::asio::buffer(header_buffer_));
	send_buffers_.push_back(boost::asio::buffer(send_body_));
}

//Verify the validity of the client
void auth_message::parse_check_client_req_msg()
{
	const auth_config& config = singleton<auth_config>::get_const_instance();

	chap client_chap;
	std::istringstream is(string(recv_body_.begin(), recv_body_.end()));
	boost::archive::binary_iarchive ia(is);
	ia >> client_chap;
	
	string comp = client_chap.chap_str_ + config.server_pwd_;

	md5 md5;
	uint8_t ret[16];

	if (client_chap.chap_str_.size() != 32)
	{
		throw runtime_error("chap length error");
	}

	md5.md5_once(const_cast<char*>(comp.data()), comp.size(), ret);
	server_chap_.chap_str_.assign(reinterpret_cast<char*>(ret), 16);
	server_chap_.gid_  = config.gid;
	server_chap_.res1_ = 0;
}

//Sending the authentication information to the client
void auth_message::constuct_auth_res_msg(const auth_info& auth)
{
	std::ostringstream os;
	boost::archive::binary_oarchive oa(os);
	oa << auth;
	send_body_ = os.str();

	set_header(AUTH_RESPONSE);
	send_buffers_.clear();
	send_buffers_.push_back(boost::asio::buffer(header_buffer_));
	send_buffers_.push_back(boost::asio::buffer(send_body_));
}

//Parsing authentication information received from the client
void auth_message::parse_auth_res_msg(auth_info& auth)
{
	std::istringstream is(string(recv_body_.begin(), recv_body_.end()));
	boost::archive::binary_iarchive ia(is);
	ia >> auth;
}
