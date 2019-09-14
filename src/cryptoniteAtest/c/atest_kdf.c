#include "atest.h"
#include "kdf.h"

typedef struct {
	int id;
	char* pass;
	char* salt;
	unsigned long iterations;
	int dkLen;
	char dk[1024];
} KdfHelper;

static KdfHelper pbkdf2_data[] = {
	/*
	Input:
	    P = "password" (8 octets)
	    S = "salt" (4 octets)
	    c = 1
	    dkLen = 20

	Output:
	    DK = 0c 60 c8 0f 96 1f 0e 71
		 	f3 a9 b5 24 af 60 12 06
			2f e0 37 a6             (20 octets)
	*/
	{
		PBKDF2_SHA1_HMAC_ID,
		"password",
		"salt",
		1,
		20,
		{
			0x0c, 0x60, 0xc8, 0x0f, 0x96, 0x1f, 0x0e, 0x71,
			0xf3, 0xa9, 0xb5, 0x24, 0xaf, 0x60, 0x12, 0x06,
			0x2f, 0xe0, 0x37, 0xa6
		}
	},
	/*
	Input:
	   P = "passwordPASSWORDpassword" (24 octets)
	   S = "saltSALTsaltSALTsaltSALTsaltSALTsalt" (36 octets)
	   c = 4096
	   dkLen = 25

	Output :
	   DK = 3d 2e ec 4f e4 1c 84 9b
			80 c8 d8 36 62 c0 e4 4a
			8b 29 1a 96 4c f2 f0 70
			38                      (25 octets)
	*/
	{
		PBKDF2_SHA1_HMAC_ID,
		"passwordPASSWORDpassword",
		"saltSALTsaltSALTsaltSALTsaltSALTsalt",
		4096,
		25,
		{
			0x3d, 0x2e, 0xec, 0x4f, 0xe4, 0x1c, 0x84, 0x9b,
			0x80, 0xc8, 0xd8, 0x36, 0x62, 0xc0, 0xe4, 0x4a,
			0x8b, 0x29, 0x1a, 0x96, 0x4c, 0xf2, 0xf0, 0x70,
			0x38
		},
	},
	/*
	Input:
	   P = "passwordPASSWORDpassword" (24 octets)
	   S = "saltSALTsaltSALTsaltSALTsaltSALTsalt" (36 octets)
	   c = 4096
	   dkLen = 40

	Output:
	   DK = 34 8c 89 db cb d3 2b 2f
		    32 d8 14 b8 11 6e 84 cf
		    2b 17 34 7e bc 18 00 18
		    1c 4e 2a 1f b8 dd 53 e1
		    c6 35 51 8c 7d ac 47 e9 (40 octets)
	*/
	{
		PBKDF2_SHA256_HMAC_ID,
		"passwordPASSWORDpassword",
		"saltSALTsaltSALTsaltSALTsaltSALTsalt",
		4096,
		40,
		{
			0x34, 0x8C, 0x89, 0xDB, 0xCB, 0xD3, 0x2B, 0x2F,
			0x32, 0xD8, 0x14, 0xB8, 0x11, 0x6E, 0x84, 0xCF,
			0x2B, 0x17, 0x34, 0x7E, 0xBC, 0x18, 0x00, 0x18,
			0x1C, 0x4E, 0x2A, 0x1F, 0xb8, 0xDD, 0x53, 0xE1,
			0xC6, 0x35, 0x51, 0x8C, 0x7D, 0xAC, 0x47, 0xE9
		}
	},
	/*
		PBKDF = PBKDF2
		PRF = HMAC_GOST34311
		sBox = SBOX-1
		P = “password”
		S = “salt”
		C = 1
		dkLen = 32
		DK = 39 46 85 33 E7 8B 12 34 32 0F 2B F9 76 C4 E1 4B 10 B0 2C 70 86 10 07 79 50 4C 1C 07 2F B5 D7 3E
	*/
	{
		PBKDF2_GOST_HMAC_ID,
		"password",
		"salt",
		1,
		32,
		{
				0x39, 0x46, 0x85, 0x33, 0xE7, 0x8B, 0x12, 0x34, 0x32, 0x0F, 0x2B, 
				0xF9, 0x76, 0xC4, 0xE1, 0x4B, 0x10, 0xB0, 0x2C, 0x70, 0x86, 0x10, 
				0x07, 0x79, 0x50, 0x4C, 0x1C, 0x07, 0x2F, 0xB5, 0xD7, 0x3E
		}
	},
	/*
		PBKDF = PBKDF2
		PRF = HMAC_GOST34311
		sBox = SBOX-1
		P = “passwordPASSWORDpassword”
		S = “saltSALTsaltSALTsaltSALTsaltSALTsalt”
		c = 4096
		dkLen = 32
		DK = B0 62 4C FD BE A4 89 0E 16 3E CC 24 98 81 65 42 4C B3 8F 9C F2 F3 E6 B9 B7 1E D3 47 34 8E 29 8A
	*/
	{
		PBKDF2_GOST_HMAC_ID,
		"passwordPASSWORDpassword",
		"saltSALTsaltSALTsaltSALTsaltSALTsalt",
		4096,
		32,
		{
			0xB0, 0x62, 0x4C, 0xFD, 0xBE, 0xA4, 0x89, 0x0E, 0x16, 0x3E, 0xCC,
			0x24, 0x98, 0x81, 0x65, 0x42, 0x4C, 0xB3, 0x8F, 0x9C, 0xF2, 0xF3,
			0xE6, 0xB9, 0xB7, 0x1E, 0xD3, 0x47, 0x34, 0x8E, 0x29, 0x8A
		}
	},
};


void test_kdf_pbkdf2(KdfHelper* td)
{
	ByteArray* dk = NULL;
	ByteArray* salt = ba_alloc_from_str(td->salt);
	ByteArray* data = ba_alloc_by_len(td->dkLen);
	ba_from_uint8(td->dk, td->dkLen, data);

	ASSERT_RET_OK(kdf_pbkdf2(td->pass, salt, td->iterations, td->dkLen, td->id, &dk));	
	CHECK_EQUALS_BA(data, dk);

cleanup:

	BA_FREE(data, dk, salt);
}


void atest_kdf(void)
{
	size_t err_count = error_count;

	ATEST_CORE(pbkdf2_data, test_kdf_pbkdf2, sizeof(KdfHelper));

	if (err_count == error_count) {
		msg_print_atest("KDF", "[pbkdf2]", "OK");
	}
	else {
		msg_print_atest("KDF", "", "FAILED");
	}
}
