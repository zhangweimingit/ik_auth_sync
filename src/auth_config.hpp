#ifndef AUTH_CONFIG_HPP_
#define AUTH_CONFIG_HPP_

#include <string>
#include <boost/serialization/singleton.hpp>

struct auth_config 
{
	bool parse(std::string &config_file);

	std::string host_;
	std::string port_;

	std::string server_pwd_;

	uint32_t na_queue_size; // new auth queue size, buffer the auth which is not sent successfully
	uint32_t gid;
	uint32_t expired_time; /*sec*/
};

#endif

