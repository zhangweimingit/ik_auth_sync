#include <iostream>
#include <fstream>
#include <boost/property_tree/ptree.hpp>  
#include <boost/property_tree/json_parser.hpp>  

#include "auth_config.hpp"

using namespace std;
using boost::property_tree::ptree;
using boost::property_tree::read_json;
bool auth_config::parse(string &config_file)
{
	try
	{
		ifstream input(config_file);
		if (input)
		{
			ptree root;
			read_json<ptree>(input, root);

			host_ = root.get<string>("host");
			port_ = root.get<string>("port");
			server_pwd_ = root.get<string>("server_pwd");
			na_queue_size = root.get<uint32_t>("auth_queue_size");
			gid = root.get<uint32_t>("gid");
			expired_time = root.get<uint32_t>("auth_expired_time");
		}
		else
		{
			cerr << "read json file error:" << config_file << endl;
			return false;
		}
	}
	catch (const std::exception&e)
	{
		cerr << "json file invalid:" << e.what() << endl;
		return false;
	}

	return true;
}


