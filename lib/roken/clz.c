/*
 * Copyright (C) 2015 THL A29 Limited, a Tencent company, and Milo Yip.
 * All rights reserved.
 *
 * Licensed under the MIT License (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://opensource.org/licenses/MIT
 *
 * Unless required by applicable law or agreed to in writing, software distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */

#include <config.h>
#include <assert.h>

#include "roken.h"

#if defined(_MSC_VER)
#include <intrin.h>
#if defined(_WIN64)
#pragma intrinsic(_BitScanReverse64)
#else
#pragma intrinsic(_BitScanReverse)
#endif
#endif

ROKEN_LIB_FUNCTION int ROKEN_LIB_CALL
rk_clzll(uint64_t x)
{
#if defined(_MSC_VER)
    unsigned long r = 0;
#elif !(defined(__GNUC__) && __GNUC__ >= 4)
    int r = 0;
#endif

    assert(x != 0);

#if defined(_MSC_VER)
# if defined(_WIN64)
    _BitScanReverse64(&r, x);
# else
    if (_BitScanReverse(&r, (uint32_t)(x >> 32)))
        return 63 - (r + 32);
    _BitScanReverse(&r, (uint32_t)(x & 0xFFFFFFFF));
# endif

    return 63 - r;
#elif (defined(__GNUC__) && __GNUC__ >= 4)
    return __builtin_clzll(x);
#else
    while (!(x & ((uint64_t)1 << 63))) {
        x <<= 1;
        ++r;
    }

    return r;
#endif /* _MSC_VER || __GNUC__ */
}
