#include "md5.hpp"

MD5::MD5()
{
	reset();
	MD5_Init(&ctx);
}

void MD5::append(void *data, uint32_t size)
{
	MD5_Update(&ctx, data, size);
}

void MD5::append(std::string str)
{
	append(&str[0], str.size());
}

void MD5::reset(void)
{
	MD5_Init(&ctx);
}

void MD5::md5_once(void *data, uint32_t size, uint8_t md5[16])
{
	reset();
	append(data, size);
	final(md5);
}

void MD5::final(uint8_t md5[16])
{
	MD5_Final(md5, &ctx);
}