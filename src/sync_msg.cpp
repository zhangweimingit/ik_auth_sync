#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/un.h>
#include <utility>
#include <iostream>

#include "md5.hpp"
#include "sync_msg.hpp"

#define DHCP_OPTION_AUTH_PATH "/tmp/dhcp_option_info_auth"

using namespace std;
using namespace cppbase;

/****************************************************************/
static uint32_t construct_sync_msg(uint8_t msg_type, DataOption &opts, RawData &raw_data);
/****************************************************************/
uint32_t constuct_sync_auth_req_msg(const string &chap_req, RawData &raw_data)
{
	DataOption opts;

	/* add the chap request str */
	opts.insert(make_pair(CHAP_STR, chap_req));

	return construct_sync_msg(AUTH_REQUEST, opts, raw_data);
}

uint32_t construct_sync_auth_res_msg(unsigned gid, const string &chap_res, RawData &raw_data)
{
	DataOption opts;

	ClintAuthInfo auth;
	auth.gid_ = htonl(gid);
	string s(reinterpret_cast<char*>(&auth),sizeof(ClintAuthInfo));

	opts.insert(make_pair(CLIENT_MAC, s));
	/* add the chap request str */
	opts.insert(make_pair(CHAP_RES, chap_res));

	return construct_sync_msg(AUTH_RESPONSE, opts, raw_data);
}

uint32_t construct_sync_cli_auth_res_msg(unsigned gid, const ClintAuthInfo &auth, RawData &raw_data)
{
	DataOption opts;
	string s;
	uint32_t  temp_32 = 0;
	uint16_t  temp_16 = 0;

	//Construct message
	s.append(auth.mac_, MAC_STR_LEN + 1);//mac

	temp_16 = htons(auth.attr_);
	s.append(reinterpret_cast<char*>(&temp_16), sizeof(uint16_t));//attr

	temp_32 = htonl(gid);
	s.append(reinterpret_cast<char*>(&temp_32), sizeof(uint32_t));//gid

	temp_32 = htonl(auth.duration_);
	s.append(reinterpret_cast<char*>(&temp_32), sizeof(uint32_t));//duration_

	opts.insert(make_pair(CLIENT_AUTH, s));

	return construct_sync_msg(CLI_AUTH_RES, opts, raw_data);
}


bool validate_sync_msg_header(const SyncMsgHeader &header)
{
	if (header.version_ != SYNC_MSG_VER1) {
		return false;
	}
	if (header.type_ == MSG_INVALID_TYPE || header.type_ >= MSG_TYPE_NR) {
		return false;
	}

	return true;
}

bool parse_tlv_data(const uint8_t *data, uint32_t data_len, DataOption &opts)
{
	const uint8_t *end = data+data_len;
	
	while (data < end) {
		uint16_t type = *reinterpret_cast<uint16_t*>(const_cast<uint8_t*>(data));
		data += 2;
		type = ntohs(type);

		if (type == 0 || type >= DATA_TYPE_NR) {
			cerr << "Invalid Data type(" << type << ")" << endl;
			return false;
		}
		
		uint16_t len = *reinterpret_cast<uint16_t*>(const_cast<uint8_t*>(data));
		data += 2;
		len = ntohs(len);
		if (data + len > end) {
			cerr << "Invalid data length (" << len <<") for type(" << type << ")" << endl;
			return false;
		}

		string value((char*)data, len);
		opts.insert(make_pair(type, value));

		cout << "Find Data type(" << type << ")" << endl;
		data += len;
	}

	return true;
}

bool validate_chap_str(const string &res, const string &req, const string &pwd)
{
	string comp = req+pwd;
	cppbase::MD5 md5;
	uint8_t ret[16];

	if (res.size() != 16) {
		return false;
	}

	md5.md5_once(const_cast<char*>(comp.data()), comp.size(), ret);

	return (0 == memcmp(res.data(), ret, 16));
}

static uint32_t construct_sync_msg(uint8_t msg_type, DataOption &opts, RawData &raw_data)
{
	SyncMsgHeader *header = &raw_data.header_;
	uint8_t *data = reinterpret_cast<uint8_t*>(header+1);
	uint16_t data_len = 0;

	memset(header, 0, sizeof(*header));
	header->version_ = SYNC_MSG_VER1;
	header->type_ = msg_type;

	for (auto it = opts.begin(); it != opts.end(); ++it) {
		uint16_t *ptype;
		uint16_t *plen;
		string value;

		//type
		ptype = reinterpret_cast<uint16_t*>(data);
		*ptype = htons(it->first);
		data += sizeof(*ptype);
		data_len += sizeof(*ptype);

		// len
		plen = reinterpret_cast<uint16_t*>(data);
		value = it->second;
 		*plen = htons(value.size());
 		data += sizeof(*plen);
		data_len += sizeof(*plen);

		// value
		if (value.size()) {
			memcpy(data, value.data(), value.size());
			data += value.size();
			data_len += value.size();
		}
	}

	header->len_ = htons(data_len);

	return sizeof(SyncMsgHeader)+data_len;
}



int ik_create_dhcp_fd()
{
	int option_fd = -1;
	struct sockaddr_un addr;
	int addr_len = sizeof(struct sockaddr_un);

	if ((option_fd = socket(AF_LOCAL, SOCK_DGRAM, 0)) <0) {
		cout << "socket option fd fealed!" << endl;
		return -1;
	}
	unlink(DHCP_OPTION_AUTH_PATH);
	memset(&addr, 0, addr_len);
	addr.sun_family = AF_LOCAL;
	strncpy(addr.sun_path, DHCP_OPTION_AUTH_PATH, addr_len);
	if (bind(option_fd, (struct sockaddr *)&addr, addr_len) < 0) {
		cout <<  "bind failed option fd!" <<  endl;
		goto ret;
	}

	return option_fd;

ret:
	close(option_fd);
	option_fd = -1;
	return -1;
}


