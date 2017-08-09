// Copyright (c) 2017-2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "tx_verify.h"

#include "consensus.h"
#include "primitives/transaction.h"
#include "script/interpreter.h"
#include "validation.h"

// TODO remove the following dependencies
#include "chain.h"
#include "coins.h"
#include "utilmoneystr.h"
 
bool IsFinalTx(const CTransaction &tx, int nBlockHeight, int64_t nBlockTime)
{
    if (tx.nLockTime == 0)
        return true;
    if ((int64_t)tx.nLockTime < ((int64_t)tx.nLockTime < LOCKTIME_THRESHOLD ? (int64_t)nBlockHeight : nBlockTime))
        return true;
    for (const auto& txin : tx.vin) {
        if (!(txin.nSequence == CTxIn::SEQUENCE_FINAL))
            return false;
    }
    return true;
}

std::pair<int, int64_t> CalculateSequenceLocks(const CTransaction &tx, int flags, std::vector<int>* prevHeights, const CBlockIndex& block)
{
    assert(prevHeights->size() == tx.vin.size());

    // Will be set to the equivalent height- and time-based nLockTime
    // values that would be necessary to satisfy all relative lock-
    // time constraints given our view of block chain history.
    // The semantics of nLockTime are the last invalid height/time, so
    // use -1 to have the effect of any height or time being valid.
    int nMinHeight = -1;
    int64_t nMinTime = -1;

    // tx.nVersion is signed integer so requires cast to unsigned otherwise
    // we would be doing a signed comparison and half the range of nVersion
    // wouldn't support BIP 68.
    bool fEnforceBIP68 = static_cast<uint32_t>(tx.nVersion) >= 2
                      && flags & LOCKTIME_VERIFY_SEQUENCE;

    // Do not enforce sequence numbers as a relative lock time
    // unless we have been instructed to
    if (!fEnforceBIP68) {
        return std::make_pair(nMinHeight, nMinTime);
    }

    for (size_t txinIndex = 0; txinIndex < tx.vin.size(); txinIndex++) {
        const CTxIn& txin = tx.vin[txinIndex];

        // Sequence numbers with the most significant bit set are not
        // treated as relative lock-times, nor are they given any
        // consensus-enforced meaning at this point.
        if (txin.nSequence & CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG) {
            // The height of this input is not relevant for sequence locks
            (*prevHeights)[txinIndex] = 0;
            continue;
        }

        int nCoinHeight = (*prevHeights)[txinIndex];

        if (txin.nSequence & CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG) {
            int64_t nCoinTime = block.GetAncestor(std::max(nCoinHeight-1, 0))->GetMedianTimePast();
            // NOTE: Subtract 1 to maintain nLockTime semantics
            // BIP 68 relative lock times have the semantics of calculating
            // the first block or time at which the transaction would be
            // valid. When calculating the effective block time or height
            // for the entire transaction, we switch to using the
            // semantics of nLockTime which is the last invalid block
            // time or height.  Thus we subtract 1 from the calculated
            // time or height.

            // Time-based relative lock-times are measured from the
            // smallest allowed timestamp of the block containing the
            // txout being spent, which is the median time past of the
            // block prior.
            nMinTime = std::max(nMinTime, nCoinTime + (int64_t)((txin.nSequence & CTxIn::SEQUENCE_LOCKTIME_MASK) << CTxIn::SEQUENCE_LOCKTIME_GRANULARITY) - 1);
        } else {
            nMinHeight = std::max(nMinHeight, nCoinHeight + (int)(txin.nSequence & CTxIn::SEQUENCE_LOCKTIME_MASK) - 1);
        }
    }

    return std::make_pair(nMinHeight, nMinTime);
}

bool EvaluateSequenceLocks(const CBlockIndex& block, std::pair<int, int64_t> lockPair)
{
    assert(block.pprev);
    int64_t nBlockTime = block.pprev->GetMedianTimePast();
    if (lockPair.first >= block.nHeight || lockPair.second >= nBlockTime)
        return false;

    return true;
}

bool SequenceLocks(const CTransaction &tx, int flags, std::vector<int>* prevHeights, const CBlockIndex& block)
{
    return EvaluateSequenceLocks(block, CalculateSequenceLocks(tx, flags, prevHeights, block));
}

unsigned int GetLegacySigOpCount(const CTransaction& tx)
{
    unsigned int nSigOps = 0;
    for (const auto& txin : tx.vin)
    {
        nSigOps += txin.scriptSig.GetSigOpCount(false);
    }
    for (const auto& txout : tx.vout)
    {
        nSigOps += txout.scriptPubKey.GetSigOpCount(false);
    }
    return nSigOps;
}

unsigned int GetP2SHSigOpCount(const CTransaction& tx, const CCoinsViewCache& inputs)
{
    if (tx.IsCoinBase())
        return 0;

    unsigned int nSigOps = 0;
    for (unsigned int i = 0; i < tx.vin.size(); i++)
    {
        const Coin& coin = inputs.AccessCoin(tx.vin[i].prevout);
        assert(!coin.IsSpent());
        const CTxOut &prevout = coin.out;
        if (prevout.scriptPubKey.IsPayToScriptHash())
            nSigOps += prevout.scriptPubKey.GetSigOpCount(tx.vin[i].scriptSig);
    }
    return nSigOps;
}

int64_t GetTransactionSigOpCost(const CTransaction& tx, const CCoinsViewCache& inputs, int flags)
{
    int64_t nSigOps = GetLegacySigOpCount(tx) * WITNESS_SCALE_FACTOR;

    if (tx.IsCoinBase())
        return nSigOps;

    if (flags & SCRIPT_VERIFY_P2SH) {
        nSigOps += GetP2SHSigOpCount(tx, inputs) * WITNESS_SCALE_FACTOR;
    }

    for (unsigned int i = 0; i < tx.vin.size(); i++)
    {
        const Coin& coin = inputs.AccessCoin(tx.vin[i].prevout);
        assert(!coin.IsSpent());
        const CTxOut &prevout = coin.out;
        nSigOps += CountWitnessSigOps(tx.vin[i].scriptSig, prevout.scriptPubKey, &tx.vin[i].scriptWitness, flags);
    }
    return nSigOps;
}

bool CheckTransaction(const CTransaction& tx, CValidationState &state, bool fCheckDuplicateInputs)
{
    // Basic checks that don't depend on any context
    if (tx.vin.empty())
        return state.DoS(10, false, REJECT_INVALID, "bad-txns-vin-empty");
    if (tx.vout.empty())
        return state.DoS(10, false, REJECT_INVALID, "bad-txns-vout-empty");
    // Size limits (this doesn't take the witness into account, as that hasn't been checked for malleability)
    if (::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS) * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT)
        return state.DoS(100, false, REJECT_INVALID, "bad-txns-oversize");

    // Check for negative or overflow output values
    CAmount nValueOut = 0;
    for (const auto& txout : tx.vout)
    {
        if (txout.nValue < 0)
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-vout-negative");
        if (txout.nValue > MAX_MONEY)
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-vout-toolarge");
        nValueOut += txout.nValue;
        if (!MoneyRange(nValueOut))
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-txouttotal-toolarge");
    }

    // Check for duplicate inputs - note that this check is slow so we skip it in CheckBlock
    if (fCheckDuplicateInputs) {
        std::set<COutPoint> vInOutPoints;
        for (const auto& txin : tx.vin)
        {
            if (!vInOutPoints.insert(txin.prevout).second)
                return state.DoS(100, false, REJECT_INVALID, "bad-txns-inputs-duplicate");
        }
    }

    if (tx.IsCoinBase())
    {
        if (tx.vin[0].scriptSig.size() < 2 || tx.vin[0].scriptSig.size() > 100)
            return state.DoS(100, false, REJECT_INVALID, "bad-cb-length");
    }
    else
    {
        for (const auto& txin : tx.vin)
            if (txin.prevout.IsNull())
                return state.DoS(10, false, REJECT_INVALID, "bad-txns-prevout-null");
    }

    return true;
}

bool Consensus::CheckTxInputs(const CTransaction& tx, CValidationState& state, const CCoinsViewCache& inputs, int nSpendHeight)
{
        // This doesn't trigger the DoS code on purpose; if it did, it would make it easier
        // for an attacker to attempt to split the network.
        if (!inputs.HaveInputs(tx))
            return state.Invalid(false, 0, "", "Inputs unavailable");

        CAmount nValueIn = 0;
        CAmount nFees = 0;
        for (unsigned int i = 0; i < tx.vin.size(); i++)
        {
            const COutPoint &prevout = tx.vin[i].prevout;
            const Coin& coin = inputs.AccessCoin(prevout);
            assert(!coin.IsSpent());

            // If prev is coinbase, check that it's matured
            if (coin.IsCoinBase()) {
                if (nSpendHeight - coin.nHeight < COINBASE_MATURITY)
                    return state.Invalid(false,
                        REJECT_INVALID, "bad-txns-premature-spend-of-coinbase",
                        strprintf("tried to spend coinbase at depth %d", nSpendHeight - coin.nHeight));
            }

            // Check for negative or overflow input values
            nValueIn += coin.out.nValue;
            if (!MoneyRange(coin.out.nValue) || !MoneyRange(nValueIn))
                return state.DoS(100, false, REJECT_INVALID, "bad-txns-inputvalues-outofrange");

        }

        if (nValueIn < tx.GetValueOut())
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-in-belowout", false,
                strprintf("value in (%s) < value out (%s)", FormatMoney(nValueIn), FormatMoney(tx.GetValueOut())));

        // Tally transaction fees
        CAmount nTxFee = nValueIn - tx.GetValueOut();
        if (nTxFee < 0)
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-fee-negative");
        nFees += nTxFee;
        if (!MoneyRange(nFees))
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-fee-outofrange");
    return true;
}

bool Consensus::CheckColor(const CTransaction& tx, CValidationState& state, const CCoinsViewCache& inputs)
{
    typedef std::map<uint256, CAmount> maptype;
    maptype mapcolor;
    std::vector<bool> vfHasColor(tx.vout.size(), false);
    for (auto &txout : tx.vout) {
        const CScript &scriptPubKey = txout.scriptPubKey;
        if (scriptPubKey.IsColorCommitment()) {
            // If the size is exactly 36, this color commitment is redundant
            // If the last byte is 0, it refers to no output so must be redundant
            if (scriptPubKey.size() == 36 || scriptPubKey.back() == 0)
                return state.DoS(0, false, REJECT_INVALID, "bad-txns-color-committment");

            // Color pattern output must be null color
            if (txout.HasColor())
                return state.DoS(0, false, REJECT_INVALID, "bad-txns-color-selfassign");

            // Null color commitment is redundant as any output not covered by a color commitment has null color
            for (size_t i = 4; i < 36; i++) {
                if (scriptPubKey[i])
                    break;
                if (i == 35)
                    return state.DoS(0, false, REJECT_INVALID, "bad-txns-color-null");
            }

            // Check for out-of-range color assignment
            for (size_t i = 0; i < scriptPubKey.size() - 36; i++) {
                if (i * 8 >= tx.vout.size())
                    return state.DoS(0, false, REJECT_INVALID, "bad-txns-color-outofrange");
                for (size_t j = 0; j < 8; j++) {
                    if (scriptPubKey[i + 36] & (1U << j)) {
                        const size_t nOut = i * 8 + j;
                        if (nOut >= tx.vout.size())
                            return state.DoS(0, false, REJECT_INVALID, "bad-txns-color-outofrange");
                        // Each output may be assigned color at most once. However, it is valid to have multiple
                        // commitments for the same color, as long as the assignments do not repeat
                        if (vfHasColor[nOut])
                            return state.DoS(0, false, REJECT_INVALID, "bad-txns-color-multiple");
                        vfHasColor[nOut] = true;
                    }
                }
            }
        }
        else if (txout.HasColor()) {
            // Making 0-value output with color is invalid
            if (txout.nValue == 0)
                return state.DoS(0, false, REJECT_INVALID, "bad-txns-color-zero-value");
            std::pair<maptype::iterator, bool> ret = mapcolor.emplace(txout.color, txout.nValue);
            if (!ret.second)
                ret.first->second += txout.nValue;
        }
    }

    for (auto &txin : tx.vin)
    {
        const CTxOut& prev = inputs.AccessCoin(txin.prevout).out;

        const uint32_t nColorType = (txin.nSequence & CTxIn::SEQUENCE_COLOR_MASK);

        // If the nColorType bits are not set, color of the input (if any) is irrecoverably discarded.
        // The coins are transferred as null-color bitcoin.
        if (nColorType) {
            maptype::iterator it;
            // Null-color inputs cannot use SEQUENCE_COLOR_TRANSFER. For simple value transfer they should unset the
            // nColorType bits. For color genesis they may use SEQUENCE_COLOR_SCRIPT or SEQUENCE_COLOR_PREVOUT
            if (nColorType == CTxIn::SEQUENCE_COLOR_TRANSFER) {
                if (!prev.HasColor())
                    return state.DoS(0, false, REJECT_INVALID, "bad-txns-color-sequence");
                it = mapcolor.find(prev.color);
            }

            // When SEQUENCE_COLOR_PREVOUT or SEQUENCE_COLOR_SCRIPT is used, the input must originally have null color.
            // SEQUENCE_COLOR_PREVOUT color genesis is guaranteed to be an one-off event for a given color (with BIP30)
            // SEQUENCE_COLOR_SCRIPT color genesis could be repeated by spending UTXOs with the same scriptPubKey.
            // A future scripting system might optionally impose restrictions on this ability.
            else {
                if (prev.HasColor())
                    return state.DoS(0, false, REJECT_INVALID, "bad-txns-color-sequence");
                CHashWriter ss(SER_GETHASH, 0);
                ss << nColorType;
                if (nColorType == CTxIn::SEQUENCE_COLOR_SCRIPT)
                    ss << prev.scriptPubKey;
                else // SEQUENCE_COLOR_PREVOUT
                    ss << txin.prevout;
                it = mapcolor.find(ss.GetHash());
            }

            // Remove colors from mapcolor that are known to have total input value not lower than total output value
            // This speeds up the remaining tests
            if (it != mapcolor.end() && (it->second -= prev.nValue) <= 0)
                mapcolor.erase(it);
        }
        else if (prev.HasColor())
            return state.DoS(0, false, REJECT_INVALID, "bad-txns-color-sequence");
    }

    // A valid transaction should have an empty mapcolor at this point
    if (!mapcolor.empty())
        return state.DoS(0, false, REJECT_INVALID, "bad-txns-color-in-belowout");
    return true;
}
