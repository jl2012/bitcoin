// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PRIMITIVES_BLOCK_H
#define BITCOIN_PRIMITIVES_BLOCK_H

#include "primitives/transaction.h"
#include "serialize.h"
#include "uint256.h"

static const uint32_t HARDFORK_HEIGHT = 200;  // 2088 Q1
static const int SERIALIZE_BLOCK_LEGACY = 0x04000000;
static const int SERIALIZE_BLOCK_DUMMY = 0x02000000;

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
    uint16_t nDeploymentHard;
    uint256 hashPrevBlock;
    uint32_t nTTime;
    uint32_t nBits;
    uint32_t nNonce;
    uint32_t nNonceC2;
    std::vector<uint8_t> vchNonceC3;

    // info about transactions
    uint256 hashMerkleRoot;
    uint256 hashMerkleRootWitnesses;
    uint256 hashMerkleSumRoot;
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
                SetNewHeaderNull();
            }
            READWRITE(nDeploymentSoft);
            READWRITE(hashPrevBlock);
            READWRITE(hashMerkleRoot);
            READWRITE(nTTime);
            READWRITE(nBits);
            READWRITE(nNonce);
        }
        else if (nVersion & SERIALIZE_BLOCK_DUMMY) {
            uint256 hashHB;
            if (ser_action.ForRead())
                SetNull();
            else
                hashHB = GetHashHB();
            READWRITE(nNonceC2);
            READWRITE(hashPrevBlock);
            READWRITE(hashHB);
            READWRITE(nTTime);
            READWRITE(nBits);
            READWRITE(nNonce);
        }
        else {
            if (!ser_action.ForRead()) {
                if (nHeight < HARDFORK_HEIGHT)
                   SetNewHeaderNull();
                assert(vhashCMTBranches.size() <= 32);
            }
            READWRITE(nHeight);
            READWRITE(nDeploymentSoft);
            READWRITE(nDeploymentHard);
            READWRITE(hashMerkleRoot);
            READWRITE(hashMerkleRootWitnesses);
            READWRITE(hashMerkleSumRoot);
            READWRITE(nTxsCount);
            READWRITE(hashPrevBlock);
            READWRITE(nTTime);
            READWRITE(nBits);
            READWRITE(nNonce);
            READWRITE(nNonceC2);
            READWRITE(vchNonceC3);
            READWRITE(vhashCMTBranches);
            if (ser_action.ForRead()) {
                if (nHeight < HARDFORK_HEIGHT)
                    SetNewHeaderNull();
                if (vhashCMTBranches.size() > 32)
                    vhashCMTBranches.resize(32);
            }
        }
    }

    void SetNewHeaderNull()
    {
        nHeight = 0;
        nDeploymentHard = 0;
        nNonceC2 = 0;
        vchNonceC3.clear();
        hashMerkleRootWitnesses.SetNull();
        hashMerkleSumRoot.SetNull();
        nTxsCount = 0;
        vhashCMTBranches.clear();
    }

    void SetNull()
    {
        nDeploymentSoft = 0;
        hashPrevBlock.SetNull();
        hashMerkleRoot.SetNull();
        nTTime = 0;
        nBits = 0;
        nNonce = 0;
        SetNewHeaderNull();
    }

    bool IsNull() const
    {
        return (nBits == 0);
    }

    uint256 GetHashCMR() const;
    uint256 GetHashHB() const;
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
        int nVersion = s.GetVersion();
        READWRITE(*(CBlockHeader*)this);
        if (nVersion & SERIALIZE_BLOCK_DUMMY) {
            assert(!ser_action.ForRead());
            std::vector<unsigned char> coinbaseDummy;
            const CScript serHeight = CScript() << nHeight;
            const uint8_t nLenToken = (serHeight.size() + 33 + vchNonceC3.size());
            const uint256 hashCMR = GetHashCMR();
            coinbaseDummy.resize(nLenToken + 1);
            memcpy(&coinbaseDummy[0], &serHeight[0], serHeight.size());
            coinbaseDummy[serHeight.size()] = (nDeploymentHard >> 8);
            memcpy(&coinbaseDummy[serHeight.size() + 1], &hashCMR, 32);
            memcpy(&coinbaseDummy[serHeight.size() + 33], &vchNonceC3[0], vchNonceC3.size());
            coinbaseDummy.back() = nLenToken;
            CMutableTransaction coinbaseTxDummy;
            coinbaseTxDummy.nVersion = 0x77777777;
            coinbaseTxDummy.vin.resize(1);
            coinbaseTxDummy.vin[0].prevout.SetNull();
            coinbaseTxDummy.vin[0].nSequence = 0;
            for (int i = 3; i >= 0; i--) {
                coinbaseTxDummy.vin[0].nSequence |= (uint32_t(coinbaseDummy.back()) << (i * 8));
                coinbaseDummy.pop_back();
            }
            coinbaseTxDummy.vin[0].scriptSig = CScript(coinbaseDummy.begin(), coinbaseDummy.end());
            coinbaseTxDummy.vout.resize(1);
            coinbaseTxDummy.vout[0].scriptPubKey = CScript();
            coinbaseTxDummy.vout[0].nValue = 0;
            coinbaseTxDummy.nLockTime = 0;
            vtx.resize(1);
            vtx[0] = MakeTransactionRef(std::move(coinbaseTxDummy));
        }
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
        block.nHeight        = nHeight;
        block.nDeploymentSoft = nDeploymentSoft;
        block.nDeploymentHard = nDeploymentHard;
        block.hashPrevBlock  = hashPrevBlock;
        block.nTTime         = nTTime;
        block.nBits          = nBits;
        block.nNonce         = nNonce;
        block.nNonceC2       = nNonceC2;
        block.vchNonceC3     = vchNonceC3;
        block.hashMerkleRoot = hashMerkleRoot;
        block.hashMerkleRootWitnesses = hashMerkleRootWitnesses;
        block.hashMerkleSumRoot = hashMerkleSumRoot;
        block.nTxsCount = nTxsCount;
        block.vhashCMTBranches = vhashCMTBranches;
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
