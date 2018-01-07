//
// auth_message.hpp
// ~~~~~~~~~
//
// Copyright (c) 2003-2017 Christopher M. Kohlhoff (chris at kohlhoff dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef AUTH_MESSAGEH_HPP
#define AUTH_MESSAGEH_HPP

#include <string>
#include <vector>
#include <boost/asio.hpp>

enum Msg_Type
{
	MSG_INVALID_TYPE,

	CHECK_CLIENT,
	CHECK_CLIENT_RESPONSE,

	AUTH_REQUEST,	// Request client auth 
	AUTH_RESPONSE,	// client auth result

	MSG_TYPE_NR
};

// Structure to hold information about a single stock.
 struct header
{
	uint8_t version_;
	uint8_t type_;
	uint16_t len_; //Don't include the header
	uint16_t res1_; // reserve
	uint16_t res2_; // reserve
};
struct auth_info
{
	std::string mac_;
	uint16_t attr_;
	uint32_t duration_;         
	uint32_t auth_time_;      
	uint32_t res1_;// reserve
	uint32_t res2_;// reserve

	template<class Archive>
	void serialize(Archive& ar, const unsigned int version)
	{
		ar & mac_;
		ar & attr_;
		ar & duration_;
		ar & auth_time_;
		ar & res1_;
		ar & res2_;
	}
};

//Challenge Handshake Authentication Protocol
struct chap
{
	uint32_t gid_; //Clients report their group ID
	uint32_t res1_;// reserve
	std::string chap_str_;//Encrypting data by MD5 algorithm

	template<class Archive>
	void serialize(Archive& ar, const unsigned int version)
	{
		ar & gid_;
		ar & res1_;
		ar & chap_str_;
	}
};

class auth_message
{
public:
	
	void set_header(Msg_Type msg);//The head must be set before sending
	void parse_header();//Parsing the header information received from the server
	
	void constuct_check_client_res_msg();//Return the check client msg to the server
	void parse_check_client_req_msg();

	void constuct_auth_res_msg(const auth_info& auth);//Sending the auth information to the server
	void parse_auth_res_msg(auth_info& auth); //Parsing auth information received from the server

private:
	friend class client;

	union 
	{
		header header_;
		char header_buffer_[sizeof(header)];
	};
	chap server_chap_;
	std::string send_body_;
	std::vector<char> recv_body_;
	std::vector<boost::asio::const_buffer> send_buffers_;
};
#endif // AUTH_MESSAGEH_HPP