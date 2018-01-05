#include <netdb.h>
#include <errno.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/socket.h>
#include <linux/netlink.h>

#include <ctype.h>
#include <iostream>
#include <sstream>
#include <algorithm>
#include <map>

#include "lib_event.h"
#include "ik_def.h"
#include "ik_base_type.h"
#include "ik_api_dev.h"
#include "ik_comm_utils.h"

#include "sync_config.hpp"
#include "sync_client.hpp"
#include "md5.hpp"
#include "pseudo_random.hpp"


using namespace std;
using namespace cppbase;

extern std::map<std::string, ClintAuthInfo> g_mac_auth;

bool SyncClient::init(void)
{
	if (!create_netlink_sock()) {
		cerr << "Fail to create netlink sock" << endl;
		return false;
	}

	if (!sock_.open(AF_INET, SOCK_STREAM, 0, 0)) {
		cerr << "Fail to open sync_client sock" << endl;
		return false;
	}
	
	if (!resolve_server_addr()) {
		cerr << "Fail to resolve server addr" << endl;
		return false;
	}
	
	if (!connect_sync_server()) {
		return false;
	}

	return true;
}

int SyncClient::get_fd(void)
{
	return sock_.sock_;
}

bool SyncClient::read_msg(void)
{
	uint32_t expect_size;
	uint8_t buf[1024];
	ssize_t size;
	

	switch (msg_status_) {
		case MSG_NONE:
			expect_size = sizeof(SyncMsgHeader)-rcv_buf_.size();
			break;
		case MSG_HEADER:
			expect_size = sizeof(SyncMsgHeader)+header_.len_-rcv_buf_.size();
			break;
		default:
			return false;
	}

	size = read(sock_.sock_, buf, expect_size);
	if (0 == size) {
		cout << "Read 0 byte, peer is closed" << endl;
		return false;
	}
	
	switch (msg_status_) {
		case MSG_NONE:
			rcv_buf_.insert(rcv_buf_.end(), buf, buf+expect_size);
			memset(&header_, 0, sizeof(header_));
			header_ = *reinterpret_cast<SyncMsgHeader*>(&rcv_buf_[0]);
			header_.len_ = ntohs(header_.len_);
			header_.res_ = ntohs(header_.res_);

			if (!validate_sync_msg_header(header_)) {
				cerr << "Invalid msg version(" << header_.version_ << ") "
					<< "or msg type(" << header_.type_ << ") " << endl;
				return false;
			}
			
			msg_status_ = MSG_HEADER;
			
			if (header_.len_ == 0) {
				// No data;
				msg_status_ = MSG_NONE;
				rcv_buf_.clear();
			}
			break;
		case MSG_HEADER:
			rcv_buf_.insert(rcv_buf_.end(), buf, buf+expect_size);
			if (rcv_buf_.size() == sizeof(SyncMsgHeader)+header_.len_) {
				// Get all data
				DataOption opts;
				if (!parse_tlv_data(&rcv_buf_[sizeof(SyncMsgHeader)], header_.len_, opts)) {
					cerr << "Invalid tlv data" << endl;
					return false;
				}
				
				rcv_buf_.clear();

				if (!process_sync_msg(opts)) {
					cerr << "Fail to process sync_msg" << endl;
					return false;
				}
				msg_status_ = MSG_NONE;
			}
			break;
		default:
			cerr << "Invalid msg_status(" << msg_status_ << ")" << endl;
			break;
	}

	return true;
}

bool SyncClient::process_sync_msg(const DataOption &opts)
{
	SyncConfig& sync_config = boost::serialization::singleton<SyncConfig>::get_mutable_instance();

	switch (header_.type_) {
		case AUTH_REQUEST:
			{
				auto it = opts.find(CHAP_STR);
				if (it == opts.end()) {
					return false;
				}
				
				cppbase::MD5 md5;
				uint8_t ret[16];
				string comp = it->second+sync_config.client_pwd_;
				string chap_res;
				uint32_t len;
				size_t size;
				
				md5.md5_once(const_cast<char*>(comp.data()), comp.size(), ret);
				chap_res.append(reinterpret_cast<char*>(ret), 16);
				
				len = construct_sync_auth_res_msg(sync_config.gid, chap_res, data_);
				size = write(sock_.sock_, data_.data_, len);
				cout << "Send sync_auth_res msg with len(" << size << ")" << endl;
			}
			break;
		case AUTH_RESPONSE:
			if (server_status_ == SERVER_CHAP_REQ) {
				auto it = opts.find(CHAP_RES);
				if (it == opts.end()) {
					cerr << "No chap_res" << endl;
					return false;
				}
				
				if (!validate_chap_str(it->second, chap_req_, sync_config.server_pwd_)) {
					cerr << "Invalid chap_res" << endl;
					return false;
				}
				server_status_ = SERVER_AUTHED;
				cout << "SyncServer become AUTHED" << endl;
			} else {
				cerr << "Recv auth_response in server status(" << server_status_ << ")" << endl;
			}
			break;
		case CLI_AUTH_RES:
			if (server_status_ == SERVER_AUTHED) {
				auto it = opts.find(CLIENT_AUTH);
				if (it == opts.end()) {
					cerr << "No client mac" << endl;
					break;
				}

				ClintAuthInfo auth = *reinterpret_cast<const ClintAuthInfo*>(it->second.c_str());
				auth.attr_ = ntohs(auth.attr_);
				auth.duration_ = ntohl(auth.duration_);


				cout << "The mac(" << auth.mac_ << ") attr(" << auth.attr_
					<< ") is authed by remote " << "Residual timeout time " << auth.duration_ << endl;

				auth.auth_time_ = time(NULL);
				g_mac_auth[auth.mac_] = auth;
				
			} else {
				cerr << "The server didn't pass auth" << endl;
			}
			break;
		case CLI_AUTH_REQ:
			cout << "Receive the msg we don't care" << endl;
			break;
		default:
			cerr << "Receive wrong type msg(" << header_.type_ << ")" << endl;
			break;
	}

	return true;
}

bool SyncClient::need_write_msg(void)
{
	if (server_status_ == SERVER_INIT) {
		return true;
	}

	return false;
}

bool SyncClient::write_msg(void)
{
	uint32_t data_len;
	size_t size;

	if (server_status_ == SERVER_INIT) {
		// send chap request
		get_random_string(chap_req_, CHAP_STR_LEN);
		data_len = constuct_sync_auth_req_msg(chap_req_, data_);
		size = write(sock_.sock_, data_.data_, data_len);
		cout << "SyncClient send auth_req msg(" << size << ") bytes" << endl;
		server_status_ = SERVER_CHAP_REQ;
		return true;
	}
	return true;
}

bool SyncClient::send_client_auth_res(unsigned gid, const ClintAuthInfo &auth)
{
	uint32_t data_len = construct_sync_cli_auth_res_msg(gid, auth, data_);

	if (write(sock_.sock_, data_.data_, data_len) == static_cast<ssize_t>(data_len)) {
		cout << "SyncClient send cli_auth_res successfully" << endl;
		return true;
	} else {
		cerr << "SyncClient fail to send cli_auth_res" << endl;
		return false;
	}
}

bool SyncClient::resolve_server_addr(void)
{
	SyncConfig& sync_config = boost::serialization::singleton<SyncConfig>::get_mutable_instance();
	struct addrinfo hint;
	struct addrinfo *result, *rp;
	int ret;
	Socket sock;
	stringstream port_str;

	memset(&hint, 0, sizeof(hint));
	hint.ai_family = AF_INET;
	hint.ai_socktype = SOCK_STREAM;

	port_str << sync_config.port_;

	ret = getaddrinfo(sync_config.host_.c_str(), port_str.str().c_str(), &hint, &result);
	if (ret != 0) {
		cerr << "resolve server " << sync_config.host_ << " failed: "
			<< gai_strerror(errno) << endl; 
		return false;
	}

	sync_config.addrs_.clear();
	
	for (rp = result; rp != NULL; rp = rp->ai_next) {
		ServerAddr addr;		
		struct sockaddr_in *in_addr;

		addr.addr_ = *rp->ai_addr;
		addr.addrlen_ = rp->ai_addrlen;

		in_addr = reinterpret_cast<struct sockaddr_in *>(&addr.addr_);
		
		cout << "Get server: " << inet_ntoa(in_addr->sin_addr)
			<< " port: " << ntohs(in_addr->sin_port)
			<< " len: " << addr.addrlen_ << endl;

		sync_config.addrs_.push_back(addr);	
	}

	freeaddrinfo(result);

	cout << "We got " << sync_config.addrs_.size() << " server addresses totally" << endl;

	return sync_config.addrs_.size() > 0;
}

bool SyncClient::connect_sync_server(void)
{	
	SyncConfig& sync_config = boost::serialization::singleton<SyncConfig>::get_mutable_instance();

	for (auto it = sync_config.addrs_.begin(); it != sync_config.addrs_.end(); ++it) {
		if (sock_.connect(&it->addr_, it->addrlen_)) {
			cout << "Connect SyncServer successfully" << endl;
			return true;
		}

		struct sockaddr_in *addr;
		addr = reinterpret_cast<struct sockaddr_in *>(&it->addr_);

		cerr << "Fail to connect server " << inet_ntoa(addr->sin_addr) << endl;
	}

	cerr << "Fail to connect SyncServer" << endl;
	return false;
}

bool SyncClient::create_netlink_sock(void)
{
	struct sockaddr_nl saddr;
	int buf_len;

	netlink_fd_ = socket(PF_NETLINK, SOCK_RAW, IK_NETLINK_CTL);
	if (netlink_fd_ < 0) {
		cerr << "Fail to create netlink socket: " << strerror(errno) << endl;
		return false;
	}

	memset(&saddr, 0, sizeof(saddr));
	saddr.nl_family = AF_NETLINK;
	saddr.nl_pid = getpid();  /* self pid */
	saddr.nl_groups = 0;  /* not in mcast groups */
	if (::bind(netlink_fd_, (struct sockaddr*)&saddr, sizeof(saddr))<0) {
		cerr << "Fail to bind netlink socket: " << strerror(errno) << endl;
		return false;
	}

	
	buf_len = 2048 > sizeof(struct ik_cntl_msg) ?: sizeof(struct ik_cntl_msg);
	if (setsockopt(netlink_fd_, SOL_SOCKET, SO_SNDBUFFORCE, &buf_len, sizeof(buf_len)) < 0 &&
		setsockopt(netlink_fd_, SOL_SOCKET, SO_SNDBUF, &buf_len, sizeof(buf_len)) < 0) {
		cerr << "Fail to set send buffer: " << strerror(errno) << endl;
		return false;
	}

	buf_len = 2048;
	if (setsockopt(netlink_fd_, SOL_SOCKET, SO_RCVBUFFORCE, &buf_len, sizeof(buf_len)) < 0 &&
		setsockopt(netlink_fd_, SOL_SOCKET, SO_RCVBUF, &buf_len, sizeof(buf_len)) < 0) {
		cerr << "Fail to set recv buffer: " << strerror(errno) << endl;
		return false;
	}

	return true;
}

/*
Copy the codes from ik_cntl
*/
void SyncClient::send_auth_to_kernel(const ClintAuthInfo &auth)
{
	struct ik_cntl_msg ctl_msg;

	memset(&ctl_msg, 0, sizeof(ctl_msg));

	int v;
	for (uint32_t i = 0; i < 6; i++) {
		sscanf(auth.mac_ + 3 * i, "%2x", &v);
		ctl_msg.auth_config.mac[i] = (char)v;
	}

	ctl_msg.msg_type = IK_CNTL_AUTH_MSG;
	ctl_msg.auth_config.msg_type = AUTH_ADD_MAC;
	ctl_msg.auth_config.auth = 1;
	ctl_msg.auth_config.attr_value = auth.attr_;
	ctl_msg.auth_config.is_remote_auth = 1;

	// send to kernel
	struct sockaddr_nl daddr;
	struct msghdr msg;
	struct nlmsghdr *nlh;
	struct iovec iov;

	memset(&msg, 0, sizeof(msg));
	memset(&daddr, 0, sizeof(daddr));
	daddr.nl_family = AF_NETLINK;
	daddr.nl_pid = 0;   /* For Linux Kernel */
	daddr.nl_groups = 0; /* unicast */

	nlh=(struct nlmsghdr *)malloc(NLMSG_SPACE(sizeof(ctl_msg)));
	if (!nlh) {
		cerr << "Fail to malloc nhl" << endl;
		return;
	}
	/* Fill the netlink message header */
	nlh->nlmsg_len = NLMSG_LENGTH(sizeof(ctl_msg));
	nlh->nlmsg_pid = getpid();  /* self pid */
	nlh->nlmsg_flags = 0;
	/* Fill in the netlink message payload */
	memcpy(NLMSG_DATA(nlh), &ctl_msg, sizeof(ctl_msg));

	iov.iov_base = (void *)nlh;
	iov.iov_len = nlh->nlmsg_len;
	msg.msg_name = (void *)&daddr;
	msg.msg_namelen = sizeof(daddr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	cout << "Send auth msg to kernel" << endl;
	if (sendmsg(netlink_fd_, &msg, 0) == -1) {
		cerr << "sendmsg failed: " << strerror(errno) << endl;
	}
	free(nlh);
}

