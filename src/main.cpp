#include <unistd.h>

#include <iostream>
#include <sstream>
#include <vector>
#include <map>
#include <boost/program_options.hpp>
#include "auth_config.hpp"
#include "kernel_event.hpp"
#include "capacity_queue.hpp"
#include "auth_message.hpp"
#include "client.hpp"
using namespace std;
namespace po = boost::program_options;
using boost::serialization::singleton;
using boost::asio::ip::tcp;
using boost::asio::local::datagram_protocol;
using boost::asio::posix::stream_descriptor;

std::map<std::string, auth_message> g_mac_auth;
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

	int newhost_pipe[2];
	int newauth_pipe[2];

	if (pipe(newhost_pipe)) {
		cerr << "Fail to open newhost pipe" << endl;
		exit(1);
	}
	if (pipe(newauth_pipe)) {
		cerr << "Fail to open newauth pipe" << endl;
		exit(1);
	}

	//KernelEvtThr evt_thr(newhost_pipe[1], newauth_pipe[1]);

	//if (!evt_thr.init()) 
	//{
	//	cerr << "Fail to init event thr" << endl;
	//	exit(1);
	//}

	//if (!evt_thr.start()) 
	//{
	//	cerr << "Fail to start event thr" << endl;
	//	exit(1);
	//}

	
	CapacityQueue<kernel_info> auth_queue(sync_config.na_queue_size);

	boost::asio::io_service io_service;

	::unlink("/tmp/dhcp_option_info_auth");
	datagram_protocol::socket dhcp_sock(io_service,"/tmp/dhcp_option_info_auth",);

	cerr << "Fail to start event thr" << endl;
	stream_descriptor host_pipe(io_service, newhost_pipe[0]);
	stream_descriptor auth_pipe(io_service, newhost_pipe[0]);


	while (1) 
	{
		client client(io_service,sync_config.host_,sync_config.port_);
		client();
		io_service.run();

		sleep(3);
		continue;
	}

	close(newhost_pipe[0]);
	close(newhost_pipe[1]);
	close(newauth_pipe[0]);
	close(newauth_pipe[1]);

	cout << "ik_as_client exit" << endl;
	
	return 0;
}


