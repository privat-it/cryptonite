/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#ifndef CPPCRYPTO_BLOCK_CIPHER_H
#define CPPCRYPTO_BLOCK_CIPHER_H

#include <stdint.h>
#include <string>

namespace cppcrypto
{

	class block_cipher
	{
	public:
		enum direction { encryption, decryption };

		block_cipher() {}
		virtual ~block_cipher();

		virtual size_t blocksize() const = 0;
		virtual size_t keysize() const = 0;
		virtual block_cipher* clone() const = 0;
		virtual void clear() = 0;

		virtual bool init(const uint8_t* key, block_cipher::direction direction) = 0;
		virtual void encrypt_block(const uint8_t* in, uint8_t* out) = 0;
		virtual void decrypt_block(const uint8_t* in, uint8_t* out) = 0;

		virtual void encrypt_blocks(const uint8_t* in, uint8_t* out, size_t n);
		virtual void decrypt_blocks(const uint8_t* in, uint8_t* out, size_t n);

	private:
		block_cipher(const block_cipher&) = delete;
		void operator=(const block_cipher&) = delete;
	};

}

#endif
