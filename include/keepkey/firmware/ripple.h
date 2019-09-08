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

#ifndef KEEPKEY_FIRMWARE_RIPPLE_H
#define KEEPKEY_FIRMWARE_RIPPLE_H

#include "trezor/crypto/bip32.h"

#include "messages-ripple.pb.h"

#define RIPPLE_MIN_FEE    10
#define RIPPLE_MAX_FEE 10000

#define RIPPLE_DECIMALS 6

bool ripple_getAddress(const HDNode *node, char address[MAX_ADDR_SIZE]);

void ripple_formatAmount(char *buf, size_t len, uint64_t amount);

void ripple_signTx(const HDNode *node, const RippleSignTx *tx,
                   RippleSignedTx *resp);

#endif
