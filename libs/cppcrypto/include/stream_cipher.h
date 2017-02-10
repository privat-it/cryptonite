/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#ifndef CPPCRYPTO_STREAM_CIPHER_H
#define CPPCRYPTO_STREAM_CIPHER_H

#include <stdint.h>
#include <string>

namespace cppcrypto
{

	class stream_cipher
	{
	public:
		stream_cipher() {}
		virtual ~stream_cipher() {}

		virtual size_t keysize() const = 0;
		virtual size_t ivsize() const = 0;
		virtual stream_cipher* clone() const = 0;
		virtual void clear() = 0;

		virtual void init(const uint8_t* key, size_t keylen, const uint8_t* iv, size_t ivlen) = 0;
		virtual void encrypt(const uint8_t* in, size_t len, uint8_t* out) = 0;
		virtual void decrypt(const uint8_t* in, size_t len, uint8_t* out) = 0;

	private:
		stream_cipher(const stream_cipher&) = delete;
		void operator=(const stream_cipher&) = delete;
	};

}

#endif
