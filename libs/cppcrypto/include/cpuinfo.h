/******************************************************************************
This code is released under Simplified BSD License (see license.txt).
******************************************************************************/
#ifndef CPPCRYPTO_CPUINFO_H
#define CPPCRYPTO_CPUINFO_H

#include <vector>
#include <bitset>
#include <array>
#include <string>

namespace cppcrypto
{

class cpu_info
{
	class cpu_info_impl;
public:
	static bool sse2() { return impl_.edx1_[26]; }
	static bool sse41() { return impl_.ecx1_[19]; }
	static bool avx() { return impl_.ecx1_[28]; }
	static bool avx2() { return impl_.ebx7_[5]; }
	static bool bmi2() { return impl_.ebx7_[8]; }
	static bool ssse3() { return impl_.ecx1_[9]; }
	static bool aesni() { return impl_.ecx1_[25]; }
	static bool mmx() { return impl_.edx1_[23]; }



private:
	class cpu_info_impl
	{
	public:
		cpu_info_impl();

		std::bitset<32> ecx1_;
		std::bitset<32> edx1_;
		std::bitset<32> ebx7_;
		std::bitset<32> ecx7_;
		std::bitset<32> ecx81_;
		std::bitset<32> edx81_;

	};

	static const cpu_info_impl impl_;
};

}

#endif
