// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_CONSENSUS_H
#define BITCOIN_CONSENSUS_CONSENSUS_H

#include <stdint.h>

/** The maximum allowed size for a serialized block, in bytes (only for buffer size limits) */
static const unsigned int MAX_BLOCK_SERIALIZED_SIZE = 4000000;
/** The maximum allowed weight for a block, see BIP 141 (network rule) */
static const unsigned int MAX_BLOCK_WEIGHT = 4000000;
/** The maximum allowed size for a block excluding witness data, in bytes (network rule) */
static const unsigned int MAX_BLOCK_BASE_SIZE = 1000000;
/** The maximum allowed number of signature check operations in a block (network rule) */
static const int64_t MAX_BLOCK_SIGOPS_COST = 80000;
/** Coinbase transaction outputs can only be spent after this number of new blocks (network rule) */
static const int COINBASE_MATURITY = 100;
/** Initial max hardfork block weight (network rule) */
static const unsigned int MAX_INITIAL_BLOCK_WEIGHT = 5000000;
/** Final max hardfork block weight (network rule) */
static const unsigned int MAX_TARGET_BLOCK_WEIGHT = 16000000;
/** Growth rate of maximum hardfork block weight (1 weight by every 2^4 = 16 seconds; network rule) */
static const unsigned int MAX_BLOCK_WEIGHT_GROWTH_FACTOR = 4;
/** SigOp cost scaling factor (network rule) */
static const unsigned int SIGOP_COST_SCALE_FACTOR = 50;
/** Sighash cost scaling factor (network rule) */
static const unsigned int SIGHASH_COST_SCALE_FACTOR = 90;
/** Post-hardfork maximum miner space in miner header fields */
static const unsigned int MAX_MINER_SPACE_SIZE = 252;

/** Flags for nSequence and nLockTime locks */
enum {
    /* Interpret sequence numbers as relative lock-time constraints. */
    LOCKTIME_VERIFY_SEQUENCE = (1 << 0),

    /* Use GetMedianTimePast() instead of nTime for end point timestamp. */
    LOCKTIME_MEDIAN_TIME_PAST = (1 << 1),
};

#endif // BITCOIN_CONSENSUS_CONSENSUS_H
