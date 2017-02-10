/*
This code is written by kerukuro for cppcrypto library (http://cppcrypto.sourceforge.net/)
and released into public domain.
*/

#ifndef CPPCRYPTO_KUPYNA_H
#define CPPCRYPTO_KUPYNA_H

#include "crypto_hash.h"
#include "alignedarray.h"
#include <functional>
#include <memory>

namespace cppcrypto
{

	class kupyna256 : public crypto_hash
	{
	public:
		kupyna256();
		~kupyna256();

		void init() override;
		void update(const uint8_t* data, size_t len) override;
		void final(uint8_t* hash) override;

		size_t hashsize() const override { return 256; }
		size_t blocksize() const override { return 512; }
		kupyna256* clone() const override { return new kupyna256; }
		void clear() override;

	private:
		void transform();
		void outputTransform();

		aligned_pod_array<uint64_t, 8, 32> h;
		aligned_pod_array<uint8_t, 64, 32> m;
		size_t pos;
		uint64_t total;
	};

	class kupyna512 : public crypto_hash
	{
	public:
		kupyna512();
		~kupyna512();

		void init() override;
		void update(const uint8_t* data, size_t len) override;
		void final(uint8_t* hash) override;

		size_t hashsize() const override { return 512; }
		size_t blocksize() const override { return 1024; }
		kupyna512* clone() const override { return new kupyna512; }
		void clear() override;

	private:
		void transform();
		void outputTransform();

		aligned_pod_array<uint64_t, 16, 32> h;
		aligned_pod_array<uint8_t, 128, 32> m;
		size_t pos;
		uint64_t total;
	};

}

#endif
