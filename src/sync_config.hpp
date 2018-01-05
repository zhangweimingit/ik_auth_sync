#ifndef SYNC_CONFIG_HPP_
#define SYNC_CONFIG_HPP_

#include <sys/types.h>
#include <sys/socket.h>

#include <string>
#include <vector>
#include <boost/serialization/singleton.hpp>

struct ServerAddr {
	struct sockaddr addr_;
	socklen_t addrlen_;
};

struct SyncConfig 
{
	bool parse_config_file(std::string &config_file);
	std::string host_;
	uint16_t port_;
	
	std::string client_pwd_;
	std::string server_pwd_;

	uint32_t na_queue_size; // new auth queue size, buffer the auth which is not sent successfully
	
	uint32_t gid;
	uint32_t expired_time; /*sec*/

	std::vector<ServerAddr> addrs_;
};

#endif

