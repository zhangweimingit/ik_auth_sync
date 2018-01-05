#include <stdlib.h>
#include <string.h>

#include <functional>
#include <iostream>
#include <string>

#include <lib_event.h>
#include <ik_types.h>
#include <ik_def.h>

#include "thread.hpp"

#include "kernel_event.hpp"

using namespace std;
using namespace cppbase;

#define IK_AUTH_SYNC_ATTR		(666)

/********************************************************************************/
static void receive_new_host_event(int module, int event, unsigned char *data, unsigned int length, void* self_data);
static void receive_new_auth_event(int module, int event, unsigned char *data, unsigned int length, void* self_data);
/********************************************************************************/

bool KernelEvtThr::init(void)
{
	int ret = 0;

	ret += ik_register_event_callback(IK_NOTIFY_MODULE_STATS, IK_STATS_NEW_IP,
			receive_new_host_event, this);
	ret += ik_register_event_callback(IK_NOTIFY_MODULE_AUTH, IK_AUTH_NEW_AUTH,
			receive_new_auth_event, this);

	return ret == 0;
}

bool KernelEvtThr::start(void)
{
	Thread thr("kernel_evt_thr");
	auto func = bind(&KernelEvtThr::start_work, this, placeholders::_1);

	thr.set_thread_func(func);
	
	thr.start();

	return true;
}

void KernelEvtThr::start_work(void *data)
{
	cout << "Ready to receive kernel event" << endl;
	ik_event_loop();
}

void KernelEvtThr::receive_new_host(const char mac[MAC_STR_LEN])
{
	cout << "KernelEvtThr: receive new host " << string(mac) << endl;

	auto size = write(newhost_pipe_, mac, MAC_STR_LEN);
	if (size == MAC_STR_LEN) {
		cout << "KernelEvtThr: write one new host to pipe" << endl;
	} else {
		cerr << "KernelEvtHtr: fail to write new host to pipe" << endl;
	}
}

void KernelEvtThr::receive_new_auth(const ClintAuthInfo &auth_info)
{
	cout << "KernelEvtThr: receive new auth " << string(auth_info.mac_) << endl; 

	auto size = write(newauth_pipe_, &auth_info, sizeof(auth_info));
	if (size == sizeof(auth_info)) {
		cout << "KernelEvtThr: write one new auth to pipe" << endl;
	} else {
		cerr << "KernelEvtHtr: fail to write new auth to pipe" << endl;
	}}

/*
event:192.168.10.2 00:50:56:c0:00:08 2017-11-23 17:46:23
*/
static void receive_new_host_event(int module, int event, unsigned char *data, unsigned int length, void* self_data)
{
	KernelEvtThr *kernel_evt = reinterpret_cast<KernelEvtThr *>(self_data);
	string str(reinterpret_cast<char*>(data), length);
	
	cout << "Receive one new_host event: " << str << endl;

	/* The event format is fixed, so don't check error */
	string::size_type n;
	n = str.find(' ');
	n++;

	kernel_evt->receive_new_host(&str[n]);
}

/*
event:12:34:56:78:90:ab attr(1,2,3) local/remote
*/
static void receive_new_auth_event(int module, int event, unsigned char *data, unsigned int length, void* self_data)
{
	KernelEvtThr *kernel_evt = reinterpret_cast<KernelEvtThr *>(self_data);
	string str(reinterpret_cast<char*>(data), length);
	ClintAuthInfo auth;

	cout << "Receive one new_auth event: " << str << endl;

	/* The event format is fixed, so don't check errror */
	memcpy(auth.mac_, &str[0], MAC_STR_LEN);
	auth.mac_[MAC_STR_LEN] = '\0';

	// attribute value
	string::size_type n;
	n = str.find(' ');
	n++;
	auth.attr_ = atoi(&str[n]);
	
	n = str.find(' ', n);
	n++;
	auth.duration_ = atoi(&str[n]);

	n = str.find(' ', n);
	n++;
	if (strcmp(&str[n], "local") == 0) {
		kernel_evt->receive_new_auth(auth);
	}
}

