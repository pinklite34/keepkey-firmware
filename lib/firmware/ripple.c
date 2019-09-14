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
#include "trezor/crypto/secp256k1.h"

#include <assert.h>

typedef enum {
    FT_INT16 = 1,
    FT_INT32 = 2,
    FT_AMOUNT = 6,
    FT_VL = 7,
    FT_ACCOUNT = 8,
} FieldType;

typedef struct _FieldMapping {
    FieldType type;
    int key;
} FieldMapping;

static const FieldMapping FM_account =            { .type = FT_ACCOUNT, .key = 1 };
static const FieldMapping FM_amount  =            { .type = FT_AMOUNT,  .key = 1 };
static const FieldMapping FM_destination =        { .type = FT_ACCOUNT, .key = 3 };
static const FieldMapping FM_fee =                { .type = FT_AMOUNT,  .key  = 8 };
static const FieldMapping FM_sequence =           { .type = FT_INT32,   .key = 4 };
static const FieldMapping FM_type =               { .type = FT_INT16,   .key = 2 };
static const FieldMapping FM_signingPubKey =      { .type = FT_VL,      .key = 3 };
static const FieldMapping FM_flags =              { .type = FT_INT32,   .key = 2 };
static const FieldMapping FM_txnSignature =       { .type = FT_VL,      .key = 4 };
static const FieldMapping FM_lastLedgerSequence = { .type = FT_INT32,   .key = 27 };
static const FieldMapping FM_destinationTag =     { .type = FT_INT32,   .key = 14 };


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

void ripple_formatAmount(char *buf, size_t len, uint64_t amount)
{
    bignum256 val;
    bn_read_uint64(amount, &val);
    bn_format(&val, NULL, " XRP", RIPPLE_DECIMALS, 0, false, buf, len);
}
void ripple_serializeType(uint8_t **buf, const uint8_t *end, const FieldMapping *m)
{
    if (m->key <= 0xf) {
        assert(*buf + 1 < end && "buffer not long enough");
        (*buf)[0] = m->type << 4 | m->key;
        *buf += 1;
    } else {
        assert(*buf + 2 < end && "buffer not long enough");
        (*buf)[0] = m->type << 4;
        (*buf)[1] = m->key;
        *buf += 2;
    }
}

void ripple_serializeInt16(uint8_t **buf, const uint8_t *end,
                           const FieldMapping *m, int16_t val)
{
    ripple_serializeType(buf, end, m);
    assert(m->type == FT_INT16 && "wrong type?");
    assert(*buf + 2 < end && "buffer not long enough");
    (*buf)[0] = (val >> 8) & 0xff;
    (*buf)[1] = val & 0xff;
    *buf += 2;
}

void ripple_serializeInt32(uint8_t **buf, const uint8_t *end,
                           const FieldMapping *m, int32_t val)
{
    assert(m->type == FT_INT32 && "wrong type?");
    assert(*buf + 4 < end && "buffer not long enough");
    ripple_serializeType(buf, end, m);
    (*buf)[0] = (val >> 24) & 0xff;
    (*buf)[1] = (val >> 16) & 0xff;
    (*buf)[2] = (val >>  8) & 0xff;
    (*buf)[3] = val & 0xff;
    *buf += 4;
}

void ripple_serializeAmount(uint8_t **buf, const uint8_t *end,
                            const FieldMapping *m, int64_t amount)
{
    ripple_serializeType(buf, end, m);
    assert(amount >= 0 && "amounts cannot be negative");
    assert(amount <= 100000000000 && "larger amounts not supported");
    assert(*buf + 8 < end && "buffer not long enough");
    (*buf)[0] = (amount >> (7 * 8)) & 0xff;
    (*buf)[1] = (amount >> (6 * 8)) & 0xff;
    (*buf)[2] = (amount >> (5 * 8)) & 0xff;
    (*buf)[3] = (amount >> (4 * 8)) & 0xff;
    (*buf)[4] = (amount >> (3 * 8)) & 0xff;
    (*buf)[5] = (amount >> (2 * 8)) & 0xff;
    (*buf)[6] = (amount >> (1 * 8)) & 0xff;
    (*buf)[7] = amount & 0xff;
    (*buf)[0] &= 0x7f; // Clear first bit, indicating XRP
    (*buf)[0] |= 0x40; // Clear second bit, indicating value is positive
    *buf += 8;
}

void ripple_serializeVarint(uint8_t **buf, const uint8_t *end, int val)
{
    if (val < 0)
        return;

    if (val < 192) {
        assert(*buf < end && "buffer not long enough");
        (*buf)[0] = val;
        *buf += 1;
        return;
    }

    if (val <= 12480) {
        assert(*buf + 2 < end && "buffer not long enough");
        val -= 193;
        (*buf)[0] = 193 + (val >> 8);
        (*buf)[1] = val & 0xff;
        *buf += 2;
        return;
    }

    if (val < 918744) {
        assert(*buf + 3 < end && "buffer not long enough");
        val -= 12481;
        (*buf)[0] = 241 + (val >> 16);
        (*buf)[1] = (val >> 8) & 0xff;
        (*buf)[2] = val & 0xff;
        *buf += 3;
        return;
    }

    assert(false && "value too large");
}

void ripple_serializeBytes(uint8_t **buf, const uint8_t *end,
                           const uint8_t *bytes, size_t count)
{
    ripple_serializeVarint(buf, end, count);
    assert(*buf + count < end && "buffer not long enough");
    memcpy(*buf, bytes, count);
    *buf += count;
}

void ripple_serializeAddress(uint8_t **buf, const uint8_t *end,
                             const FieldMapping *m, const char *address)
{
    const curve_info *curve = get_curve_by_name("secp256k1");
    if (!curve) return;

    uint8_t addr_raw[MAX_ADDR_RAW_SIZE];
    uint32_t addr_raw_len = base58_decode_check(address, curve->hasher_base58,
                                                addr_raw, MAX_ADDR_RAW_SIZE,
                                                ripple_b58digits);

    if (addr_raw_len != 20) {
        assert(false && "TODO: error handling");
        return;
    }

    ripple_serializeBytes(buf, end, addr_raw + 1, addr_raw_len - 1);
}

void ripple_serializeVL(uint8_t **buf, const uint8_t *end, const FieldMapping *m,
                        const uint8_t *bytes, size_t count)
{
    ripple_serializeType(buf, end, m);
    ripple_serializeBytes(buf, end, bytes, count);
}

void ripple_serialize(uint8_t **buf, const uint8_t *end, const RippleSignTx *tx,
                      const char *source_address,
                      const uint8_t *pubkey, const uint8_t *sig)
{
    ripple_serializeInt16(buf, end, &FM_type, /*Payment*/0);
    if (tx->has_flags)
        ripple_serializeInt32(buf, end, &FM_flags, tx->flags);
    if (tx->has_sequence)
        ripple_serializeInt32(buf, end, &FM_sequence, tx->sequence);
    if (tx->payment.has_destination_tag)
        ripple_serializeInt32(buf, end, &FM_destinationTag, tx->payment.destination_tag);
    if (tx->has_last_ledger_sequence)
        ripple_serializeInt32(buf, end, &FM_lastLedgerSequence, tx->last_ledger_sequence);
    if (tx->payment.has_amount)
        ripple_serializeAmount(buf, end, &FM_amount, tx->payment.amount);
    if (tx->has_fee)
        ripple_serializeAmount(buf, end, &FM_amount, tx->fee);
    if (pubkey)
        ripple_serializeVL(buf, end, &FM_signingPubKey, pubkey, 33);
    if (sig)
        ripple_serializeVL(buf, end, &FM_txnSignature, sig, 64);
    if (source_address)
        ripple_serializeAddress(buf, end, &FM_account, source_address);
    if (tx->payment.has_destination)
        ripple_serializeAddress(buf, end, &FM_destination, tx->payment.destination);
}

void ripple_signTx(const HDNode *node, RippleSignTx *tx,
                   RippleSignedTx *resp) {
    const curve_info *curve = get_curve_by_name("secp256k1");
    if (!curve) return;

    // Set canonical flag, since trezor-crypto ECDSA implementation returns
    // fully-canonical signatures, thereby enforcing it in the transaction
    // using the designated flag.
    // See: https://github.com/trezor/trezor-crypto/blob/3e8974ff8871263a70b7fbb9a27a1da5b0d810f7/ecdsa.c#L791
    if (!tx->has_flags) {
        tx->flags = 0;
        tx->has_flags = true;
    }
    tx->flags |= RIPPLE_FLAG_FULLY_CANONICAL;

    memset(resp->serialized_tx.bytes, 0, sizeof(resp->serialized_tx.bytes));

    // 'STX'
    memcpy(resp->serialized_tx.bytes, "\x53\x54\x58\x00", 4);

    char source_address[MAX_ADDR_SIZE];
    if (!ripple_getAddress(node, source_address))
        return;

    uint8_t *buf = resp->serialized_tx.bytes;
    size_t len = sizeof(resp->serialized_tx.bytes) - 4;
    ripple_serialize(&buf, buf + len, tx, source_address, node->public_key, NULL);

    // Ripple uses the first half of SHA512
    uint8_t hash[64];
    sha512_Raw(resp->serialized_tx.bytes, buf - resp->serialized_tx.bytes, hash);

    uint8_t sig[64];
    if (ecdsa_sign_digest(&secp256k1, node->private_key, hash, sig, NULL, NULL) != 0) {
        // Failure
    }

    resp->signature.size = ecdsa_sig_to_der(sig, resp->signature.bytes);
    resp->has_signature = true;

    memset(resp->serialized_tx.bytes, 0, sizeof(resp->serialized_tx.bytes));

    buf = resp->serialized_tx.bytes;
    len = sizeof(resp->serialized_tx);
    ripple_serialize(&buf, buf + len, tx, source_address, node->public_key, resp->signature.bytes);
    resp->has_serialized_tx = true;
    resp->serialized_tx.size = buf - resp->serialized_tx.bytes;
}