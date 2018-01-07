#include <unistd.h>
#include <netdb.h>
#include <errno.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/socket.h>
#include <linux/netlink.h>
#include <stdlib.h>
#include <string.h>

#include <functional>
#include <iostream>
#include <string>

//#include <lib_event.h>
//#include <ik_types.h>
//#include <ik_def.h>
#include <thread>
#include "kernel_event.hpp"

using namespace std;
/********************************************************************************/
static void receive_new_host_event(int module, int event, unsigned char *data, unsigned int length, void* self_data);
static void receive_new_auth_event(int module, int event, unsigned char *data, unsigned int length, void* self_data);
/********************************************************************************/

bool KernelEvtThr::init(void)
{
	int ret = 0;

	//ret += ik_register_event_callback(IK_NOTIFY_MODULE_STATS, IK_STATS_NEW_IP,
	//		receive_new_host_event, this);
	//ret += ik_register_event_callback(IK_NOTIFY_MODULE_AUTH, IK_AUTH_NEW_AUTH,
	//		receive_new_auth_event, this);

	
	return ret == 0 && create_netlink_sock();
}

bool KernelEvtThr::start(void)
{
	thread thr(bind(&KernelEvtThr::start_work, this));
	thr.detach();
	return true;
}

void KernelEvtThr::start_work()
{
	cout << "Ready to receive kernel event" << endl;

	kernel_info info;
	memcpy(info.mac_, "aa:bb:cc:ee:dd::ff", mac_str_len);
	info.mac_[mac_str_len] = '\0';
	receive_new_host(info);
	sleep(3);


	memcpy(info.mac_, "11:bb:cc:ee:dd::ff", mac_str_len);
	info.mac_[mac_str_len] = '\0';
	receive_new_auth(info);
	//ik_event_loop();
}

void KernelEvtThr::receive_new_host(const kernel_info &info)
{
	cout << "KernelEvtThr: receive new host " << info.mac_ << endl;

	auto size = write(newhost_pipe_, &info, sizeof(kernel_info));
	if (size == sizeof(kernel_info)) 
	{
		cout << "KernelEvtThr: write one new host to pipe" << endl;
	} else 
	{
		cerr << "KernelEvtHtr: fail to write new host to pipe" << endl;
	}
}

void KernelEvtThr::receive_new_auth(const kernel_info &info)
{
	cout << "KernelEvtThr: receive new auth " << info.mac_ << endl; 

	auto size = write(newauth_pipe_, &info, sizeof(kernel_info));
	if (size == sizeof(kernel_info))
	{
		cout << "KernelEvtThr: write one new auth to pipe" << endl;
	} else 
	{
		cerr << "KernelEvtHtr: fail to write new auth to pipe" << endl;
	}}

/*
event:192.168.10.2 00:50:56:c0:00:08 2017-11-23 17:46:23
*/
//static void receive_new_host_event(int module, int event, unsigned char *data, unsigned int length, void* self_data)
//{
//	KernelEvtThr *kernel_evt = reinterpret_cast<KernelEvtThr *>(self_data);
//	string str(reinterpret_cast<char*>(data), length);
//	
//	cout << "Receive one new_host event: " << str << endl;
//
//	/* The event format is fixed, so don't check error */
//	string::size_type n;
//	n = str.find(' ');
//	n++;
//
//	kernel_info info;
//	memcpy(info.mac_, &str[n], mac_str_len);
//	info.mac_[mac_str_len] = '\0';
//
//	kernel_evt->receive_new_host(info);
//}
//
///*
//event:12:34:56:78:90:ab attr(1,2,3) local/remote
//*/
//static void receive_new_auth_event(int module, int event, unsigned char *data, unsigned int length, void* self_data)
//{
//	KernelEvtThr *kernel_evt = reinterpret_cast<KernelEvtThr *>(self_data);
//	string str(reinterpret_cast<char*>(data), length);
//	kernel_info info;
//
//	cout << "Receive one new_auth event: " << str << endl;
//
//	/* The event format is fixed, so don't check errror */
//	memcpy(info.mac_, &str[0], mac_str_len);
//	info.mac_[mac_str_len] = '\0';
//
//	// attribute value
//	string::size_type n;
//	n = str.find(' ');
//	n++;
//	info.attr_ = atoi(&str[n]);
//
//	n = str.find(' ', n);
//	n++;
//	info.duration_ = atoi(&str[n]);
//
//	n = str.find(' ', n);
//	n++;
//	if (strcmp(&str[n], "local") == 0) 
//	{
//		kernel_evt->receive_new_auth(info);
//	}
//}
bool KernelEvtThr::create_netlink_sock(void)
{
	//struct sockaddr_nl saddr;
	//int buf_len;

	//netlink_fd_ = socket(PF_NETLINK, SOCK_RAW, IK_NETLINK_CTL);
	//if (netlink_fd_ < 0) {
	//	cerr << "Fail to create netlink socket: " << strerror(errno) << endl;
	//	return false;
	//}

	//memset(&saddr, 0, sizeof(saddr));
	//saddr.nl_family = AF_NETLINK;
	//saddr.nl_pid = getpid();  /* self pid */
	//saddr.nl_groups = 0;  /* not in mcast groups */
	//if (::bind(netlink_fd_, (struct sockaddr*)&saddr, sizeof(saddr))<0) {
	//	cerr << "Fail to bind netlink socket: " << strerror(errno) << endl;
	//	return false;
	//}


	//buf_len = 2048 > sizeof(struct ik_cntl_msg) ? : sizeof(struct ik_cntl_msg);
	//if (setsockopt(netlink_fd_, SOL_SOCKET, SO_SNDBUFFORCE, &buf_len, sizeof(buf_len)) < 0 &&
	//	setsockopt(netlink_fd_, SOL_SOCKET, SO_SNDBUF, &buf_len, sizeof(buf_len)) < 0) {
	//	cerr << "Fail to set send buffer: " << strerror(errno) << endl;
	//	return false;
	//}

	//buf_len = 2048;
	//if (setsockopt(netlink_fd_, SOL_SOCKET, SO_RCVBUFFORCE, &buf_len, sizeof(buf_len)) < 0 &&
	//	setsockopt(netlink_fd_, SOL_SOCKET, SO_RCVBUF, &buf_len, sizeof(buf_len)) < 0) {
	//	cerr << "Fail to set recv buffer: " << strerror(errno) << endl;
	//	return false;
	//}

	return true;
}

/*
Copy the codes from ik_cntl
*/
//void KernelEvtThr::send_auth_to_kernel(const kernel_info &info)
//{
//	struct ik_cntl_msg ctl_msg;
//
//	memset(&ctl_msg, 0, sizeof(ctl_msg));
//
//	int v;
//	for (uint32_t i = 0; i < 6; i++) {
//		sscanf(info.mac_ + 3 * i, "%2x", &v);
//		ctl_msg.auth_config.mac[i] = (char)v;
//	}
//
//	ctl_msg.msg_type = IK_CNTL_AUTH_MSG;
//	ctl_msg.auth_config.msg_type = AUTH_ADD_MAC;
//	ctl_msg.auth_config.auth = 1;
//	ctl_msg.auth_config.attr_value = auth.attr_;
//	ctl_msg.auth_config.is_remote_auth = 1;
//
//	// send to kernel
//	struct sockaddr_nl daddr;
//	struct msghdr msg;
//	struct nlmsghdr *nlh;
//	struct iovec iov;
//
//	memset(&msg, 0, sizeof(msg));
//	memset(&daddr, 0, sizeof(daddr));
//	daddr.nl_family = AF_NETLINK;
//	daddr.nl_pid = 0;   /* For Linux Kernel */
//	daddr.nl_groups = 0; /* unicast */
//
//	nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(sizeof(ctl_msg)));
//	if (!nlh) {
//		cerr << "Fail to malloc nhl" << endl;
//		return;
//	}
//	/* Fill the netlink message header */
//	nlh->nlmsg_len = NLMSG_LENGTH(sizeof(ctl_msg));
//	nlh->nlmsg_pid = getpid();  /* self pid */
//	nlh->nlmsg_flags = 0;
//	/* Fill in the netlink message payload */
//	memcpy(NLMSG_DATA(nlh), &ctl_msg, sizeof(ctl_msg));
//
//	iov.iov_base = (void *)nlh;
//	iov.iov_len = nlh->nlmsg_len;
//	msg.msg_name = (void *)&daddr;
//	msg.msg_namelen = sizeof(daddr);
//	msg.msg_iov = &iov;
//	msg.msg_iovlen = 1;
//
//	cout << "Send auth msg to kernel" << endl;
//	if (sendmsg(netlink_fd_, &msg, 0) == -1) {
//		cerr << "sendmsg failed: " << strerror(errno) << endl;
//	}
//	free(nlh);
//}




