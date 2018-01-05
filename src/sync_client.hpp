#ifndef SYNC_CLIENT_HPP_
#define SYNC_CLIENT_HPP_

#include <vector>

#include "socket.hpp"
#include "sync_msg.hpp"
#include "kernel_event.hpp"

class SyncClient {
	enum MsgStatus {
		MSG_NONE,
		MSG_HEADER,
	};

	enum ServerStatus {
		SERVER_INIT,
		SERVER_CHAP_REQ,
		SERVER_AUTHED,


		SERVER_STATUS_NR,
	};

public:
	SyncClient()
		:netlink_fd_(-1), msg_status_(MSG_NONE), server_status_(SERVER_INIT) {
	}

	~SyncClient(){
		if (netlink_fd_ != -1) {
			close(netlink_fd_);
		}
	}

	bool init(void);
	int get_fd(void);
	
	bool read_msg(void);
	bool need_write_msg(void);
	bool write_msg(void);

	bool send_client_auth_res(unsigned gid, const ClintAuthInfo &auth);
	void send_auth_to_kernel(const ClintAuthInfo &auth);
	
private:
	bool create_netlink_sock(void);


	bool resolve_server_addr(void);
	bool connect_sync_server(void);
	bool process_sync_msg(const DataOption &opts);
	
	cppbase::Socket sock_;
	int netlink_fd_;
	
	std::vector<uint8_t> rcv_buf_;
	SyncMsgHeader header_;
	MsgStatus msg_status_;
	ServerStatus server_status_;

	RawData data_;
	std::string chap_req_;
};

#endif

