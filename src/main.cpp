#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <errno.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
/* According to POSIX.1-2001 */
#include <sys/select.h>

/* According to earlier standards */
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <iostream>
#include <sstream>
#include <vector>
#include <deque>
#include <map>
#include <boost/program_options.hpp>

#include "sync_config.hpp"
#include "sync_client.hpp"
#include "event_poll.hpp"
#include "kernel_event.hpp"
#include "capacity_queue.hpp"
#include "sync_msg.hpp"

using namespace std;
using namespace cppbase;
namespace po = boost::program_options;

std::map<std::string, ClintAuthInfo> g_mac_auth;
/***********************************************************************/
int main(int argc, const char **argv)
{
	int dhcp_fd = -1;
	char recv_buf[1024] = { 0 };

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
	SyncConfig& sync_config = boost::serialization::singleton<SyncConfig>::get_mutable_instance();
	if (!sync_config.parse_config_file(config_file_name)) {
		cerr << "parse_config_file failed" << endl;
		exit(1);
	}

	if (vm.count("daemon")) {
		cout << "ik_as_client is ready to become a daemon" << endl;
		if (daemon(1, 1)) {
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

	KernelEvtThr evt_thr(newhost_pipe[1], newauth_pipe[1]);

	if (!evt_thr.init()) {
		cerr << "Fail to init event thr" << endl;
		exit(1);
	}

	if (!evt_thr.start()) {
		cerr << "Fail to start event thr" << endl;
		exit(1);
	}

	EventPoll evp;	
	if (!evp.init()) {
		cerr << "Fail to init event_poll" << endl;
		exit(1);
	}
	if ((dhcp_fd = ik_create_dhcp_fd()) < 0) {
		cerr << "Fail to create dhcp fd" << endl;
		exit(1);
	}

	if (!evp.epoll_add_fd(newhost_pipe[0], EventPoll::EPOLL_EPOLLIN)) {
		cerr << "Fail to add newhost_pipe into epoll" << endl;
		exit(1);
	}
	if (!evp.epoll_add_fd(newauth_pipe[0], EventPoll::EPOLL_EPOLLIN)) {
		cerr << "Fail to add newauth_pipe into epoll" << endl;
		exit(1);
	}

	if (!evp.epoll_add_fd(dhcp_fd, EventPoll::EPOLL_EPOLLIN)) {
		cerr << "Fail to add dhcp_fd into epoll" << endl;
		exit(1);
	}

	CapacityQueue<ClintAuthInfo> auth_queue(sync_config.na_queue_size);
	while (1) {
		SyncClient sync_client;
		char client_mac[MAC_STR_LEN];
		ssize_t size;
		
		vector<EventPoll::EPEvent> evts;
		if (!sync_client.init()) {
			cerr << "Fail to init sync_client" << endl;
			goto wait;
		}

		if (!evp.epoll_add_fd(sync_client.get_fd(), EventPoll::EPOLL_EPOLLIN|EventPoll::EPOLL_EPOLLRDHUP)) {
			cerr << "Fail to add sync_client fd into epoll" << endl;
			goto wait;
		}

		while (1) {
			if (sync_client.need_write_msg() || auth_queue.size()) {
				if (!evp.epoll_modify_fd(sync_client.get_fd(), EventPoll::EPOLL_ALL_FLAGS)) {
					cerr << "Fail to modify sync_client epoll events" << endl;
					goto wait;
				}
			}
		
			uint32_t ret = evp.epoll_wait(evts, -1);
			if (ret) {
				cout << "There are " << ret << " ready events" << endl;
			
				for (auto it = evts.begin(); it != evts.end(); ++it) {
					if (it->fd_ == newhost_pipe[0]) {
						size = read(newhost_pipe[0], client_mac, sizeof(client_mac));
						if (size != sizeof(client_mac)) {
							cerr << "Only read " << size << " bytes from newhost_pipe" << endl;
							exit(1);
						}

						string mac = string(client_mac,MAC_STR_LEN);
						cout << "new host " << mac << " found" << endl;

						if (g_mac_auth.count(mac))
						{
							auto & auth = g_mac_auth[mac];
							if ((time(NULL) - auth.auth_time_) < auth.duration_)
							{
								sync_client.send_auth_to_kernel(auth);
								ostringstream output;
								output << "/usr/ikuai/script/Action/webauth-up  remote_auth_sync mac=" << mac << "  authtype=" << auth.attr_ << " timeout=" << auth.duration_ - (time(NULL) - auth.auth_time_);
								system(output.str().c_str());
							}
							else
							{
								g_mac_auth.erase(mac);
							}
						}

					} else if (it->fd_ == newauth_pipe[0]) {
						ClintAuthInfo auth;

						memset(&auth, 0, sizeof(auth));

						size = read(newauth_pipe[0], &auth, sizeof(auth));
						if (size != sizeof(auth)) {
							cerr << "Only read " << size << " bytes from newauth_pipe" << endl;
							exit(1);
						}

						auth.duration_ = sync_config.expired_time;
						cout << "new auth " << auth.mac_ << " found" << ":timeout is " << auth.duration_ << endl;
						if (!sync_client.send_client_auth_res(sync_config.gid, auth)) {
							auth_queue.push_back(auth);
						}
					}
					else if (it->fd_ == dhcp_fd){

						if (recvfrom(dhcp_fd, recv_buf, sizeof(recv_buf), 0, NULL, NULL) < 0) {
							cout << "recvfrom dhcp_fd failed " <<  endl;
							exit(1);
						}

						string dhcp(recv_buf);
						string::size_type pos = dhcp.find('|');
						if (pos != string::npos && pos < dhcp.size() - 1)
						{
							string mac = dhcp.substr(pos + 1, MAC_STR_LEN);
							cout << "dhcp new host " << mac << " found" << endl;
							if (g_mac_auth.count(mac))
							{
								auto & auth = g_mac_auth[mac];
								if ((time(NULL) - auth.auth_time_) < auth.duration_)
								{
									sync_client.send_auth_to_kernel(auth);
									ostringstream output;
									output << "/usr/ikuai/script/Action/webauth-up  remote_auth_sync mac=" << mac << "  authtype=" << auth.attr_ << " timeout=" << auth.duration_ - (time(NULL) - auth.auth_time_);
									system(output.str().c_str());
								}
								else
								{
									g_mac_auth.erase(mac);
								}
							}
						}
					}
					else if (it->fd_ == sync_client.get_fd()) {
						cout << "It's sync_client event, flags is " << it->events_ << endl;					
						// sync conn
						if (it->events_ & EventPoll::EPOLL_EPOLLRDHUP) {
							// peer is closed.
							cout << "SyncServer close the sync conn" << endl;
							goto wait;
						}
						if (it->events_ & EventPoll::EPOLL_EPOLLIN) {
							cout << "SyncClient has msg to read" << endl;
							if (!sync_client.read_msg()) {
								cerr << "SyncClient fail to read msg" << endl;
								goto wait;
							}
						}
						if (it->events_ & EventPoll::EPOLL_EPOLLOUT) {
							cout << "SyncClient could write now" << endl;
							if (!sync_client.write_msg()) {
								cerr << "SyncClient fail to write msg" << endl;
								goto wait;
							}

							/* Send the auth queue backlog */
							while (auth_queue.size()) {
								ClintAuthInfo &auth = auth_queue.front();
								cout << "Send backlog new auth " << auth.mac_ << endl;
								if (!sync_client.send_client_auth_res(sync_config.gid, auth)) {
									cerr << "Fail to send client_auth_res" << endl;
									break;
								}
								auth_queue.pop_front();
							}

							if (!sync_client.need_write_msg() || auth_queue.size() == 0) {
								// Remove the write event
								if (!evp.epoll_modify_fd(sync_client.get_fd(),
										EventPoll::EPOLL_EPOLLIN|EventPoll::EPOLL_EPOLLRDHUP)) {
									cerr << "Fail to add sync_client fd into epoll" << endl;
									goto wait;
								}
							}
						}
					}
				}
			}
		}
		
wait:
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


