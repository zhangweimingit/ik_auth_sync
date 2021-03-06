#include <unistd.h>
#include <cstdio>
#include <thread>
#include <iostream>
#include <sstream>
#include <vector>
#include <map>
#include <boost/program_options.hpp>
#include <boost/asio/system_timer.hpp>
#include "auth_config.hpp"
#include "kernel_event.hpp"
#include "auth_message.hpp"
#include "client.hpp"

namespace po = boost::program_options;
using namespace std;;
using boost::serialization::singleton;
using std::placeholders::_1;

static void process_command(int argc, const char **argv);
/***********************************************************************/
int main(int argc, const char **argv)
{
	process_command(argc, argv);
	const auth_config& sync_config = singleton<auth_config>::get_const_instance();

	boost::asio::io_service io_service;
	boost::asio::io_service::work work(io_service);
	boost::asio::system_timer timer(io_service);
	tcp::resolver resolver(io_service);
	tcp::resolver::query query(sync_config.host_, sync_config.port_);
	tcp::resolver::iterator iterator = resolver.resolve(query);

	client client(io_service, iterator);

	client.start1();//process new host and dhcp event

	while (true) 
	{
		try
		{
			timer.async_wait(std::bind(&client::start2,&client,_1));//process new auth event
			io_service.run();
			break;
		}
		catch (const std::exception&e)
		{
			client.close();
			std::cout << "server close because of " << e.what() << std::endl;
		}

		std::cout << "try to connect server.... " <<  std::endl;
		timer.expires_from_now(std::chrono::seconds(3));
	}

	cout << "client exit" << endl;
	return 0;
}

static void process_command(int argc, const char **argv)
{
	po::options_description desc("Allow options");

	desc.add_options()
		("help", "print help messages")
		("config", po::value<string>()->default_value("/etc/auth_sync.conf"), "Specify the config file")
		("daemon", "Running as daemon");

	po::variables_map vm;
	try 
	{
		po::store(po::parse_command_line(argc, argv, desc), vm);
		po::notify(vm);
	}
	catch (const exception &e) 
	{
		cout << e.what() << endl;
		cout << desc << endl;
		exit(1);
	}
	if (vm.count("help")) 
	{
		cout << desc << endl;
		exit(0);
	}

	string config_file_name = vm["config"].as<string>();

	auth_config& sync_config = singleton<auth_config>::get_mutable_instance();

	if (!sync_config.parse(config_file_name))
	{
		cerr << "parse_config_file failed" << endl;
		exit(1);
	}

	if (vm.count("daemon"))
	{
		cout << "client is ready to become a daemon" << endl;
		if (daemon(1, 1))
		{
			cerr << "Fail to daemon" << endl;
			exit(1);
		}
	}
}


