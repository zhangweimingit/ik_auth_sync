#include "auth_message.hpp"
#include "auth_config.hpp"
#include <iostream>
#include <algorithm>
#include <stdexcept>
#include <random>
#include <sstream>
#include <boost/property_tree/ptree.hpp>  
#include <boost/property_tree/json_parser.hpp>  
#include "md5.hpp"

using namespace std;
using boost::serialization::singleton;
using boost::asio::detail::socket_ops::host_to_network_short;
using boost::asio::detail::socket_ops::network_to_host_short;
using boost::property_tree::write_json;
using boost::property_tree::read_json;
using boost::property_tree::ptree;

//The head must be set before sending
void auth_message::set_header(Msg_Type type)
{
	header_.version_ = 1;
	header_.type_ = type;
	header_.len_ = host_to_network_short(send_body_.size());
	header_.res1_ = 0;
	header_.res2_ = 0;
}

//Parsing the header information received from the client
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

//Verify the validity of the client
void auth_message::constuct_check_client_res_msg()
{
	ptree root;
	stringstream stream;
	root.put("gid_", server_chap_.gid_);
	root.put("res1_", server_chap_.res1_);
	root.put("chap_str_", server_chap_.chap_str_);

	write_json(stream, root,false);
	send_body_ = stream.str();

	set_header(CHECK_CLIENT_RESPONSE);
	send_buffers_.clear();
	send_buffers_.push_back(boost::asio::buffer(header_buffer_));
	send_buffers_.push_back(boost::asio::buffer(send_body_));
}

//Verify the validity of the client
void auth_message::parse_check_client_req_msg()
{
	const auth_config& config = singleton<auth_config>::get_const_instance();

	ptree root;
	stringstream str_stream(string(recv_body_.begin(), recv_body_.end()));
	read_json(str_stream, root);
	
	chap client_chap;
	client_chap.chap_str_ = root.get<string>("chap_str_");
	client_chap.gid_ = root.get<uint32_t>("gid_");
	client_chap.res1_ = root.get<uint32_t>("res1_");

	string comp = client_chap.chap_str_ + config.server_pwd_;

	md5 md5;
	uint8_t ret[16];

	if (client_chap.chap_str_.size() != 32)
	{
		throw runtime_error("chap length error");
	}

	md5.md5_once(const_cast<char*>(comp.data()), comp.size(), ret);
	server_chap_.chap_str_.assign(reinterpret_cast<char*>(ret), 16);
	server_chap_.gid_ = config.gid;
}

//Sending the authentication information to the client
void auth_message::constuct_auth_res_msg(const auth_info& auth)
{
	stringstream stream;
	boost::property_tree::ptree root;
	root.put("mac_", auth.mac_);
	root.put("attr_", auth.attr_);
	root.put("duration_", auth.duration_);
	root.put("auth_time_", auth.auth_time_);
	root.put("res1_", auth.res1_);
	root.put("res2_", auth.res2_);

	write_json(stream, root);
	send_body_ = stream.str();

	set_header(AUTH_RESPONSE);
	send_buffers_.clear();
	send_buffers_.push_back(boost::asio::buffer(header_buffer_));
	send_buffers_.push_back(boost::asio::buffer(send_body_));
}

//Parsing authentication information received from the client
void auth_message::parse_auth_res_msg(auth_info& auth)
{
	ptree root;
	stringstream str_stream(string(recv_body_.begin(), recv_body_.end()));
	read_json(str_stream, root);

	auth.mac_ = root.get<string>("mac_");
	auth.attr_ = root.get<uint16_t>("attr_");
	auth.auth_time_ = time(0);
	auth.duration_ = root.get<uint32_t>("duration_");
	auth.res1_ = root.get<uint32_t>("res1_");
	auth.res2_ = root.get<uint32_t>("res2_");
}
