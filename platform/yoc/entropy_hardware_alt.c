/*
 *  Platform-specific and custom entropy polling functions
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include "common.h"

#if defined(MBEDTLS_ENTROPY_C) && defined(MBEDTLS_ENTROPY_HARDWARE_ALT)
#include <stdlib.h>
#include <string.h>
#include "mbedtls/entropy.h"
#include "entropy_poll.h"
#include "mbedtls/error.h"

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdlib.h>
#define mbedtls_calloc    calloc
#define mbedtls_free      free
#define mbedtls_time      time
#define mbedtls_time_t    time_t
#endif

#if defined(CONFIG_MBEDTLS_ENTROPY_USE_TRNG)
#include <drv/rng.h>
#endif


#define BLOCK_INT_SIZE 128
#define BLOCK_SIZE (BLOCK_INT_SIZE * sizeof(uint32_t))

static void _get_random(unsigned char *output, uint32_t output_len)
{
#if defined(CONFIG_MBEDTLS_ENTROPY_USE_TRNG)
    uint32_t buf[BLOCK_INT_SIZE];
    uint32_t size_i = output_len / BLOCK_SIZE;
    int i = 0;
    for (; i < size_i; i++) {
        csi_rng_get_multi_word(buf, BLOCK_INT_SIZE);
        memcpy(output, buf, BLOCK_SIZE);
    }
    if (output_len % BLOCK_SIZE) {
        csi_rng_get_multi_word(buf, BLOCK_INT_SIZE);
        memcpy(output + (size_i * BLOCK_SIZE), buf, output_len % BLOCK_SIZE);
    }
#else
    int i;
    uint32_t random;
    int mod = output_len % 4;
    int count = 0;
    uint32_t rnd = 0x12345678;
    for (i = 0; i < output_len / 4; i++) {
        random = rnd * 0xFFFF777;
        rnd = random;
        output[count++] = (random >> 24) & 0xFF;
        output[count++] = (random >> 16) & 0xFF;
        output[count++] = (random >> 8) & 0xFF;
        output[count++] = (random) & 0xFF;
    }
    random = rnd * 0xFFFF777;
    rnd = random;
    for (i = 0; i < mod; i++) {
        output[i + count] = (random >> 8 * i) & 0xFF;
    }
#endif
}

int mbedtls_hardware_poll(void *data, unsigned char *output, size_t len, size_t *olen) {
    unsigned char buf[MBEDTLS_ENTROPY_BLOCK_SIZE];
    size_t use_len = MBEDTLS_ENTROPY_BLOCK_SIZE;
    ((void) data);

    memset(buf, 0, MBEDTLS_ENTROPY_BLOCK_SIZE);

    _get_random(buf, MBEDTLS_ENTROPY_BLOCK_SIZE);
    // if (_get_random(buf, MBEDTLS_ENTROPY_BLOCK_SIZE) < 0) {
    //     return MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
    // }

    if (len < use_len) {
        use_len = len;
    }

    memcpy(output, buf, use_len);
    *olen = use_len;

    return 0;
}

#if 0

#include <aos/cli.h>
#include <aos/kernel.h>

// configure log
#define CONFIG_LANGO_DBG_LEVEL LANGO_DBG_LOG
#define LANGO_DBG_TAG "DRBG"
#include "lango_log.h"
// ------------------

static void gen_random(int argc, char *argv[]) {
    if (argc < 2) {
        LANGO_LOG_ERR("Usage: %s length(1-1024\n", argv[0]);
        return;
    }
    int length = atoi(argv[1]);
    if (length > 0 && length <= 1024) {
        unsigned char *buf = aos_malloc(length);
        _get_random(buf, length);
        LANGO_LOG_INFO_DUMP_HEX("random: ", buf, length);
        if (buf) {
            aos_free(buf);
        }
    } else {
        LANGO_LOG_ERR("Usage: %s length(1-1024\n", argv[0]);
    }
}
ALIOS_CLI_CMD_REGISTER(gen_random, gen_random, gen_random);
#endif //TEST

#endif /* MBEDTLS_ENTROPY_C && MBEDTLS_ENTROPY_HARDWARE_ALT */
