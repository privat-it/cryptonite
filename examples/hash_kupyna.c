/*
 * Приклад: хешування за ДСТУ 7564:2014 («Купина»).
 *
 * Демонструє обчислення хешів різної довжини (256/384/512 біт)
 * та потокову обробку даних кількома викликами update.
 */

#include <stdio.h>

#include "byte_array.h"
#include "cryptonite_errors.h"
#include "dstu7564.h"

#define CHECK(func)                                                     \
    if ((ret = (func)) != RET_OK) {                                     \
        printf("Помилка %d у рядку %d\n", ret, __LINE__);               \
        goto cleanup;                                                   \
    }

static void print_hex(const char *title, const ByteArray *ba)
{
    printf("%s: ", title);
    ba_print(stdout, ba);
}

int main(void)
{
    int ret = RET_OK;
    ByteArray *part1 = ba_alloc_from_str("Перша частина повідомлення. ");
    ByteArray *part2 = ba_alloc_from_str("Друга частина повідомлення.");
    ByteArray *hash256 = NULL;
    ByteArray *hash512 = NULL;
    Dstu7564Ctx *ctx = NULL;

    ctx = dstu7564_alloc(DSTU7564_SBOX_1);
    if (ctx == NULL) {
        printf("Не вдалося створити контекст\n");
        return 1;
    }

    /* Купина-256: довжина хешу задається в init (у байтах). */
    CHECK(dstu7564_init(ctx, 32));
    CHECK(dstu7564_update(ctx, part1));
    CHECK(dstu7564_update(ctx, part2));   /* дані можна подавати частинами */
    CHECK(dstu7564_final(ctx, &hash256));
    print_hex("Купина-256", hash256);

    /* Той самий контекст можна ініціалізувати повторно — Купина-512. */
    CHECK(dstu7564_init(ctx, 64));
    CHECK(dstu7564_update(ctx, part1));
    CHECK(dstu7564_update(ctx, part2));
    CHECK(dstu7564_final(ctx, &hash512));
    print_hex("Купина-512", hash512);

cleanup:
    dstu7564_free(ctx);
    ba_free(part1);
    ba_free(part2);
    ba_free(hash256);
    ba_free(hash512);
    return (ret == RET_OK) ? 0 : 1;
}
