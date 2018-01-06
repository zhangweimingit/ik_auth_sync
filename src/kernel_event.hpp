#ifndef KERNEL_EVENT_HPP_
#define KERNEL_EVENT_HPP_

const unsigned mac_str_len = 17;

struct kernel_info 
{
	char mac_[mac_str_len + 1]; /*mac_str_len = 17*/
	uint16_t attr_;
	uint32_t duration_;
};

class KernelEvtThr {
public:
	KernelEvtThr(int newhost_pipe, int newauth_pipe)
		: newhost_pipe_(newhost_pipe), newauth_pipe_(newauth_pipe) {
	}

	bool init(void);
	bool start(void);

	void receive_new_host(const kernel_info &info);
	void receive_new_auth(const kernel_info &info);
	void send_auth_to_kernel(const kernel_info &info);
private:
	void start_work();
	bool create_netlink_sock(void);

	int newhost_pipe_;
	int newauth_pipe_;
	int netlink_fd_;
};

#endif

