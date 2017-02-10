/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#ifndef CPPCRYPTO_KALYNA_H
#define CPPCRYPTO_KALYNA_H

#include <stdint.h>
#include "block_cipher.h"

namespace cppcrypto
{

	class kalyna512_512 : public block_cipher
	{
	public:
		~kalyna512_512();

		size_t blocksize() const override { return 512; }
		size_t keysize() const override { return 512; }
		kalyna512_512* clone() const override { return new kalyna512_512; }
		void clear() override;

		bool init(const uint8_t* key, block_cipher::direction direction) override;
		void encrypt_block(const uint8_t* in, uint8_t* out) override;
		void decrypt_block(const uint8_t* in, uint8_t* out) override;

	private:
		uint64_t rk[19 * 8];
	};

	class kalyna256_512 : public block_cipher
	{
	public:
		~kalyna256_512();

		size_t blocksize() const override { return 256; }
		size_t keysize() const override { return 512; }
		kalyna256_512* clone() const override { return new kalyna256_512; }
		void clear() override;

		bool init(const uint8_t* key, block_cipher::direction direction) override;
		void encrypt_block(const uint8_t* in, uint8_t* out) override;
		void decrypt_block(const uint8_t* in, uint8_t* out) override;

	private:
		uint64_t rk[19 * 4];
	};

	class kalyna256_256 : public block_cipher
	{
	public:
		~kalyna256_256();

		size_t blocksize() const override { return 256; }
		size_t keysize() const override { return 256; }
		kalyna256_256* clone() const override { return new kalyna256_256; }
		void clear() override;

		bool init(const uint8_t* key, block_cipher::direction direction) override;
		void encrypt_block(const uint8_t* in, uint8_t* out) override;
		void decrypt_block(const uint8_t* in, uint8_t* out) override;

	private:
		uint64_t rk[15 * 4];
	};

	class kalyna128_256 : public block_cipher
	{
	public:
		~kalyna128_256();

		size_t blocksize() const override { return 128; }
		size_t keysize() const override { return 256; }
		kalyna128_256* clone() const override { return new kalyna128_256; }
		void clear() override;

		bool init(const uint8_t* key, block_cipher::direction direction) override;
		void encrypt_block(const uint8_t* in, uint8_t* out) override;
		void decrypt_block(const uint8_t* in, uint8_t* out) override;

	private:
		uint64_t rk[15 * 2];
	};

	class kalyna128_128 : public block_cipher
	{
	public:
		~kalyna128_128();

		size_t blocksize() const override { return 128; }
		size_t keysize() const override { return 128; }
		kalyna128_128* clone() const override { return new kalyna128_128; }
		void clear() override;

		bool init(const uint8_t* key, block_cipher::direction direction) override;
		void encrypt_block(const uint8_t* in, uint8_t* out) override;
		void decrypt_block(const uint8_t* in, uint8_t* out) override;

	private:
		uint64_t rk[11 * 2];
	};


}

#endif

