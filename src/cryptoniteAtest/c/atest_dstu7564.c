/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "atest.h"
#include "dstu7564.h"


typedef struct {
    char *data;
    char *exp;
    size_t hash_len;
} Dstu7564HashHelper;

typedef struct {
    char *key;
    char *data;
    char *exp;
    size_t hash_len;
} Dstu7564HmacHelper;

static Dstu7564HashHelper hash_data[] = {
    {
        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F",
        "08F4EE6F1BE6903B324C4E27990CB24EF69DD58DBE84813EE0A52F6631239875",
        32
    },
    {
        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F"\
        "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F",
        "0A9474E645A7D25E255E9E89FFF42EC7EB31349007059284F0B182E452BDA882",
        32
    },
    {
        "FF",
        "EA7677CA4526555680441C117982EA14059EA6D0D7124D6ECDB3DEEC49E890F4",
        32
    },
    {
        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F"\
        "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E",
        "1075C8B0CB910F116BDA5FA1F19C29CF8ECC75CAFF7208BA2994B68FC56E8D16",
        32
    },
    {
        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F",
        "2F6631239875",
        6
    },
    {
        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F",
        "3813E2109118CDFB5A6D5E72F7208DCCC80A2DFB3AFDFB02F46992B5EDBE536B3560DD1D7E29C6F53978AF58B444E37BA685C0DD910533BA5D78EFFFC13DE62A",
        64
    },
    {
        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F"\
        "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F",
        "76ED1AC28B1D0143013FFA87213B4090B356441263C13E03FA060A8CADA32B979635657F256B15D5FCA4A174DE029F0B1B4387C878FCC1C00E8705D783FD7FFE",
        64
    },
    {
        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F"\
        "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F"\
        "808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF"\
        "C0C1C2C3C4C5C6C7C8C9CACBCCCDCECFD0D1D2D3D4D5D6D7D8D9DADBDCDDDEDFE0E1E2E3E4E5E6E7E8E9EAEBECEDEEEFF0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF",
        "0DD03D7350C409CB3C29C25893A0724F6B133FA8B9EB90A64D1A8FA93B56556611EB187D715A956B107E3BFC76482298133A9CE8CBC0BD5E1436A5B197284F7E",
        64
    },
    {
        "FF",
        "871B18CF754B72740307A97B449ABEB32B64444CC0D5A4D65830AE5456837A72D8458F12C8F06C98C616ABE11897F86263B5CB77C420FB375374BEC52B6D0292",
        64
    },
    {
        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F"\
        "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F"\
        "808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF",
        "B189BFE987F682F5F167F0D7FA565330E126B6E592B1C55D44299064EF95B1A57F3C2D0ECF17869D1D199EBBD02E8857FB8ADD67A8C31F56CD82C016CF743121",
        64
    },
    {
        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F"\
        "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F",
        "0A8CADA32B979635657F256B15D5FCA4A174DE029F0B1B4387C878FCC1C00E8705D783FD7FFE",
        38
    },
    {
        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F"\
        "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E",
        "D9021692D84E5175735654846BA751E6D0ED0FAC36DFBC0841287DCB0B5584C75016C3DECC2A6E47C50B2F3811E351B8",
        48
    }
};

static Dstu7564HmacHelper kmac_data[] = {
    {
        "1F1E1D1C1B1A191817161514131211100F0E0D0C0B0A09080706050403020100",
        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E",
        "B60594D56FA79BA210314C72C2495087CCD0A99FC04ACFE2A39EF669925D98EE",
        32
    },
    {
        "2F2E2D2C2B2A292827262524232221201F1E1D1C1B1A191817161514131211100F0E0D0C0B0A09080706050403020100",
        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E",
        "BEBFD8D730336F043ABACB41829E79A4D320AEDDD8D14024D5B805DA70C396FA295C281A38B30AE728A304B3F5AE490E",
        48
    },
    {
        "3F3E3D3C3B3A393837363534333231302F2E2D2C2B2A292827262524232221201F1E1D1C1B1A191817161514131211100F0E0D0C0B0A09080706050403020100",
        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E",
        "F270043C06A5C37E65D9D791C5FBFB966E5EE709F8F54019C9A55B76CA40B70100579F269CEC24E347A9D864614CF3ABBF6610742E4DB3BD2ABC000387C49D24",
        64
    }
};

static void test_dstu7564_kmac_loop(Dstu7564HmacHelper *data)
{
    ByteArray *data_ba = ba_alloc_from_le_hex_string(data->data);
    ByteArray *key_ba = ba_alloc_from_le_hex_string(data->key);
    ByteArray *expected_ba = ba_alloc_from_le_hex_string(data->exp);
    ByteArray *actual_ba = NULL;
    Dstu7564Ctx *ctx = NULL;
    size_t hash_len = data->hash_len;
    size_t count = error_count;

    ASSERT_NOT_NULL(ctx = dstu7564_alloc(DSTU7564_SBOX_1));
    ASSERT_RET_OK(dstu7564_init_kmac(ctx, key_ba, hash_len));
    ASSERT_RET_OK(dstu7564_update_kmac(ctx, data_ba));
    ASSERT_RET_OK(dstu7564_final_kmac(ctx, &actual_ba));

    CHECK_EQUALS_BA(expected_ba, actual_ba);

cleanup:

    PRINT_ERROR(print_hmac_error("DSTU 7564 KMAC", key_ba, data_ba), count);

    BA_FREE(key_ba, data_ba, expected_ba, actual_ba);
    dstu7564_free(ctx);
}

static void test_dstu7564_hash_loop(Dstu7564HashHelper *data)
{
    ByteArray *data_ba = ba_alloc_from_le_hex_string(data->data);
    ByteArray *expected_ba = ba_alloc_from_le_hex_string(data->exp);
    ByteArray *actual_ba = NULL;
    Dstu7564Ctx *ctx = NULL;
    size_t hash_len = data->hash_len;
    size_t count = error_count;

    ASSERT_NOT_NULL(ctx = dstu7564_alloc(DSTU7564_SBOX_1));
    ASSERT_RET_OK(dstu7564_init(ctx, hash_len));
    ASSERT_RET_OK(dstu7564_update(ctx, data_ba));
    ASSERT_RET_OK(dstu7564_final(ctx, &actual_ba));

    CHECK_EQUALS_BA(expected_ba, actual_ba);

cleanup:

    PRINT_ERROR(print_hash_error("DSTU 7564 HASH", data_ba), count);

    BA_FREE(data_ba, expected_ba, actual_ba);
    dstu7564_free(ctx);
}

void atest_dstu7564(void)
{
    size_t err_count = error_count;

    ATEST_CORE(hash_data, test_dstu7564_hash_loop, sizeof(Dstu7564HashHelper));
    ATEST_CORE(kmac_data, test_dstu7564_kmac_loop, sizeof(Dstu7564HmacHelper));

    if (err_count == error_count) {
        msg_print_atest("DSTU7564", "[hash, kmac]", "OK");
        return;
    } else {
        msg_print_atest("DSTU7564", "", "FAILED");
    }

}