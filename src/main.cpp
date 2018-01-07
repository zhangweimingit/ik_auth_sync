#include <unistd.h>
#include <cstdio>
#include <thread>
#include <iostream>
#include <sstream>
#include <vector>
#include <map>
#include <boost/program_options.hpp>
#include "auth_config.hpp"
#include "kernel_event.hpp"
#include "auth_message.hpp"
#include "client.hpp"
using namespace std;
namespace po = boost::program_options;
using boost::serialization::singleton;

/***********************************************************************/
int main(int argc, const char **argv)
{
	po::options_description desc("Allow options");
	
	desc.add_options()
		("help", "print help messages")
		("config", po::value<string>()->default_value("/etc/auth_sync.conf"), "Specify the config file")
		("daemon", "Running as daemon");
		;

	po::variables_map vm;
	try {
		po::store(po::parse_command_line(argc, argv, desc), vm);
		po::notify(vm);
	}
	catch (const exception &e) {
		cout << e.what() << endl;
		cout << desc << "\n";
		return -1;
	}
	if (vm.count("help")) {
		cout << desc << endl;
		return 0;
	}

	cout << "ik_as_client start" << endl;

	auto config_file_name = vm["config"].as<string>();
	auth_config& sync_config = singleton<auth_config>::get_mutable_instance();
	if (!sync_config.parse(config_file_name)) 
	{
		cerr << "parse_config_file failed" << endl;
		exit(1);
	}

	if (vm.count("daemon")) 
	{
		cout << "ik_as_client is ready to become a daemon" << endl;
		if (daemon(1, 1)) 
		{
			cerr << "Fail to daemon" << endl;
			exit(1);
		}
	}



	boost::asio::io_service io_service;
	boost::asio::io_service::work work(io_service);
	tcp::resolver resolver(io_service);
	tcp::resolver::query query(sync_config.host_, sync_config.port_);
	tcp::resolver::iterator iterator = resolver.resolve(query);

	std::remove("/tmp/dhcp_option_info_auth");
	client client(io_service, iterator,"/tmp/dhcp_option_info_auth");

	client.start1();

	while (1) 
	{
		try
		{
			client.start2();

			std::cout << "success to connect server!" << std::endl;
			io_service.run();
			break;
		}
		catch (const std::exception&e)
		{
			client.close();
			std::cout << "server close because of " << e.what() << std::endl;
		}

		sleep(3);
		std::cout << "try to connect server.... " <<  std::endl;
	}

	close(newhost_pipe[0]);
	close(newhost_pipe[1]);
	close(newauth_pipe[0]);
	close(newauth_pipe[1]);

	cout << "ik_as_client exit" << endl;
	
	return 0;
}


