#ifndef KERNEL_EVENT_HPP_
#define KERNEL_EVENT_HPP_

#include "sync_msg.hpp"

class KernelEvtThr {
public:
	KernelEvtThr(int newhost_pipe, int newauth_pipe)
		: newhost_pipe_(newhost_pipe), newauth_pipe_(newauth_pipe) {
	}

	bool init(void);
	bool start(void);

	void receive_new_host(const char mac[MAC_STR_LEN]);
	void receive_new_auth(const ClintAuthInfo &auth_info);
	
private:
	void start_work(void *data);

	int newhost_pipe_;
	int newauth_pipe_;
};

#endif

