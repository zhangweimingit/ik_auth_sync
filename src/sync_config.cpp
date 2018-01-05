#include <iostream>
#include <fstream>
#include <boost/property_tree/ptree.hpp>  
#include <boost/property_tree/json_parser.hpp>  

#include "sync_config.hpp"

using namespace std;

bool SyncConfig::parse_config_file(string &config_file)
{

	try
	{
		ifstream input(config_file);
		if (input)
		{
			boost::property_tree::ptree root;
			boost::property_tree::ptree items;
			boost::property_tree::read_json<boost::property_tree::ptree>(input, root);

			host_ = root.get<string>("host");
			port_ = root.get<unsigned>("port");
			client_pwd_ = root.get<string>("client_pwd");
			server_pwd_ = root.get<string>("server_pwd");
			na_queue_size = root.get<unsigned>("auth_queue_size");
			gid = root.get<unsigned>("gid");
			expired_time = root.get<unsigned>("auth_expired_time");
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


