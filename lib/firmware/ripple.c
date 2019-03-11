/*
 * This file is part of the KeepKey project.
 *
 * Copyright (C) 2019 ShapeShift
 *
 * This library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "keepkey/firmware/ripple.h"

#include "trezor/crypto/base58.h"

// https://developers.ripple.com/base58-encodings.html
static const char *ripple_b58digits = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz";

bool ripple_getAddress(const HDNode *node, char address[MAX_ADDR_SIZE])
{
    uint8_t buff[64];
    memset(buff, 0, sizeof(buff));

    Hasher hasher;
    hasher_Init(&hasher, HASHER_SHA2_RIPEMD);
    hasher_Update(&hasher, node->public_key, 33);
    hasher_Final(&hasher, buff + 1);

    if (!base58_encode_check(buff, 21, HASHER_SHA2D,
                             address, MAX_ADDR_SIZE, ripple_b58digits))
        return false;

    return true;
}
