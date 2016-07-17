// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PRIMITIVES_BLOCK_H
#define BITCOIN_PRIMITIVES_BLOCK_H

#include "primitives/transaction.h"
#include "serialize.h"
#include "uint256.h"

static const uint32_t HARDFORK_HEIGHT = 4194304;  // 2088 Q1
static const int SERIALIZE_BLOCK_LEGACY = 0x04000000;

int64_t GetBlockTime(uint32_t nBlockTTime, int64_t nPrevBlockTime);

/** Nodes collect new transactions into a block, hash them into a hash tree,
 * and scan through nonce values to make the block's hash satisfy proof-of-work
 * requirements.  When they solve the proof-of-work, they broadcast the block
 * to everyone and the block is added to the block chain.  The first transaction
 * in the block is a special one that creates a new coin owned by the creator
 * of the block.
 */
class CBlockHeader
{
public:
    // header
    uint32_t nHeight;
    uint32_t nDeploymentSoft;
    uint32_t nDeploymentHard;
    uint256 hashPrevBlock;
    uint32_t nTTime;
    uint32_t nBits;
    uint32_t nNonce;
    uint32_t nNonceC2;
    std::vector<uint8_t> vchNonceC3;

    // info about transactions
    uint256 hashMerkleRoot;
    uint256 hashMerkleRootWitnesses;
    uint64_t nTxsBytes;
    uint64_t nTxsCost;
    uint64_t nTxsSigops;
    uint32_t nTxsCount;

    // branches in commitment merkle tree
    std::vector<uint256> vhashCMTBranches;

    CBlockHeader()
    {
        SetNull();
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        int nVersion = s.GetVersion();
        if (nVersion & SERIALIZE_BLOCK_LEGACY) {
            if (ser_action.ForRead()) {
                SetNull();
            }
            READWRITE(nDeploymentSoft);
            READWRITE(hashPrevBlock);
            READWRITE(hashMerkleRoot);
            READWRITE(nTTime);
            READWRITE(nBits);
            READWRITE(nNonce);
        } else {
            READWRITE(nHeight);
            READWRITE(nDeploymentSoft);
            READWRITE(nDeploymentHard);
            READWRITE(hashPrevBlock);
            READWRITE(nTTime);
            READWRITE(nBits);
            READWRITE(nNonce);
            READWRITE(nNonceC2);
            READWRITE(vchNonceC3);
            if (vchNonceC3.size() < 4 && nHeight >= HARDFORK_HEIGHT) {
                throw std::ios_base::failure("CBlockHeader::SerializationOp: short class 3 nonce");
            }

            READWRITE(hashMerkleRoot);
            READWRITE(hashMerkleRootWitnesses);
            READWRITE(nTxsBytes);
            READWRITE(nTxsCost);
            READWRITE(nTxsSigops);
            READWRITE(nTxsCount);

            READWRITE(vhashCMTBranches);
        }
    }

    void SetNull()
    {
        nHeight = 0;
        nDeploymentSoft = 0;
        nDeploymentHard = 0;
        hashPrevBlock.SetNull();
        hashMerkleRoot.SetNull();
        hashMerkleRootWitnesses.SetNull();
        nTTime = 0;
        nBits = 0;
        nNonce = 0;
        nNonceC2 = 0;
        nTxsBytes = 0;
        nTxsCost = 0;
        nTxsSigops = 0;
        nTxsCount = 0;
        vhashCMTBranches.clear();
    }

    bool IsNull() const
    {
        return (nBits == 0);
    }

    uint256 GetHash() const;

    int64_t GetBlockTime(int64_t nPrevBlockTime) const
    {
        return ::GetBlockTime(nTTime, nPrevBlockTime);
    }
};


class CBlock : public CBlockHeader
{
public:
    // network and disk
    std::vector<CTransactionRef> vtx;

    // memory only
    mutable bool fChecked;

    CBlock()
    {
        SetNull();
    }

    CBlock(const CBlockHeader &header)
    {
        SetNull();
        *((CBlockHeader*)this) = header;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(*(CBlockHeader*)this);
        READWRITE(vtx);
    }

    void SetNull()
    {
        CBlockHeader::SetNull();
        vtx.clear();
        fChecked = false;
    }

    CBlockHeader GetBlockHeader() const
    {
        CBlockHeader block;
        block.nDeploymentSoft = nDeploymentSoft;
        block.hashPrevBlock  = hashPrevBlock;
        block.hashMerkleRoot = hashMerkleRoot;
        block.nTTime         = nTTime;
        block.nBits          = nBits;
        block.nNonce         = nNonce;
        return block;
    }

    std::string ToString() const;
};

/** Describes a place in the block chain to another node such that if the
 * other node doesn't have the same branch, it can find a recent common trunk.
 * The further back it is, the further before the fork it may be.
 */
struct CBlockLocator
{
    std::vector<uint256> vHave;

    CBlockLocator() {}

    CBlockLocator(const std::vector<uint256>& vHaveIn)
    {
        vHave = vHaveIn;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        int nVersion = s.GetVersion();
        if (!(s.GetType() & SER_GETHASH))
            READWRITE(nVersion);
        READWRITE(vHave);
    }

    void SetNull()
    {
        vHave.clear();
    }

    bool IsNull() const
    {
        return vHave.empty();
    }
};

/** Compute the consensus-critical block weight (see BIP 141). */
int64_t GetBlockWeight(const CBlock& tx);

#endif // BITCOIN_PRIMITIVES_BLOCK_H
