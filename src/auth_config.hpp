#ifndef AUTH_CONFIG_HPP_
#define AUTH_CONFIG_HPP_

#include <string>
#include <boost/serialization/singleton.hpp>

struct auth_config 
{
	bool parse(std::string &config_file);

	std::string host_;//server host
	std::string port_;//server port

	std::string server_pwd_;//The cipher of the MD5 algorithm

	uint32_t gid;//Authentication group ID
	uint32_t duration_; /*sec*/
};

#endif

