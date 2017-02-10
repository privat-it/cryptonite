/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#ifndef CPPCRYPTO_CTR_H
#define CPPCRYPTO_CTR_H

#include <stdint.h>
#include "block_cipher.h"
#include "stream_cipher.h"
#include <memory>
#include <vector>
#include <ostream>

namespace cppcrypto
{
	class ctr : public stream_cipher
	{
	public:
		ctr(const block_cipher& cipher);
		virtual ~ctr();

		void clear();

		void init(const uint8_t* key, size_t keylen, const uint8_t* iv, size_t ivlen);
		void encrypt(const uint8_t* in, size_t len, uint8_t* out);
		void decrypt(const uint8_t* in, size_t len, uint8_t* out);

		size_t keysize() const { return cipher_->keysize(); }
		size_t ivsize() const { return cipher_->blocksize(); }
		stream_cipher* clone() const { return new ctr(*cipher_); }
	private:
		ctr(const ctr&) = delete;
		void operator=(const ctr&) = delete;

		uint8_t* block_;
		uint8_t* iv_;
		size_t pos;
		size_t nb_;
		std::unique_ptr<block_cipher> cipher_;
	};
}

#endif
