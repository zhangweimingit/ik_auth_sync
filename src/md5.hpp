#ifndef MD5_HPP_
#define MD5_HPP_

#include <openssl/md5.h>
#include <string>

class MD5 {
public:
	MD5();
	void append(void *data, uint32_t size);
	void append(std::string str);
	void reset(void);
	void md5_once(void *data, uint32_t size, uint8_t md5[16]);
	void final(uint8_t md5[16]);
private:
	MD5_CTX ctx;
};

#endif

