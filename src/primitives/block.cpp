// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "primitives/block.h"

#include "hash.h"
#include "tinyformat.h"
#include "utilstrencodings.h"
#include "consensus/merkle.h"
#include "crypto/common.h"

int64_t GetBlockTime(uint32_t nTTime, int64_t nPrevBlockTime)
{
    const int32_t nPrevBlockHTime = (nPrevBlockTime >> 32);
    const uint32_t nPrevBlockTTime = (nPrevBlockTime & 0xffffffff);
    int32_t nHTime;
    if (nPrevBlockTTime >= 0xe0000000 && nTTime < 0x20000000) {
        // ~388 days allowed before and after the overflow point
        nHTime = nPrevBlockHTime + 1;
    } else if (nPrevBlockTTime < 0x20000000 && nTTime >= 0xe0000000 && nPrevBlockHTime > 0) {
        nHTime = nPrevBlockHTime - 1;
    } else {
        nHTime = nPrevBlockHTime;
    }
    return (int64_t(nHTime) << 32) | nTTime;
}

namespace {

    uint32_t lrot(uint32_t x, uint32_t n) {
        return (x << n) | (x >> (32 - n));
    }

    uint32_t vector_position_for_hc(uint32_t nonce, uint32_t vector_size) {
        const uint32_t chain_id = 0x62697463;  // "bitc"
        uint32_t a, b, c;
        a = (0xb14c0121 ^ chain_id) - lrot(chain_id, 14);
        b = (nonce ^ a) - lrot(a, 11);
        c = (chain_id ^ b) - lrot(b, 25);
        a = (a ^ c) - lrot(c, 16);
        b = (b ^ a) - lrot(a, 4);
        c = (c ^ b) - lrot(b, 14);
        a = (a ^ c) - lrot(c, 24);
        return a % vector_size;
    }

    template<typename Stream, typename T> void add_to_hash(Stream& s, const T& obj) {
        ::Serialize(s, obj);
    }
}

uint256 CBlockHeader::GetHashCMR() const
{
    CHashWriter writer(SER_GETHASH, 0);
    add_to_hash(writer, nTxsBytes);
    add_to_hash(writer, nTxsWeight);
    add_to_hash(writer, nTxsSigops);
    add_to_hash(writer, nTxsCount);
    add_to_hash(writer, nDeploymentHard & 0x00ffffff);
    add_to_hash(writer, nDeploymentSoft);
    add_to_hash(writer, hashMerkleRoot);
    add_to_hash(writer, hashMerkleRootWitnesses);

    const uint256 hashHC = writer.GetHash();

    std::vector<uint8_t> vchNonceC3Copy = vchNonceC3;
    if (vchNonceC3Copy.size() < 4)
        vchNonceC3Copy.resize(4, 0x00);

    const uint32_t pos_nonce = (uint32_t(vchNonceC3Copy[0]) << 0x18)
                             | (uint32_t(vchNonceC3Copy[1]) << 0x10)
                             | (uint32_t(vchNonceC3Copy[2]) <<    8)
                             | (uint32_t(vchNonceC3Copy[3])        );
    const uint32_t pos = vector_position_for_hc(pos_nonce, 1 << vhashCMTBranches.size());
    return ComputeMerkleRootFromBranch(hashHC, vhashCMTBranches, pos);
}

uint256 CBlockHeader::GetHashHB() const
{
    CHashWriter writer(SER_GETHASH, 0);
    writer.write("\x77\x77\x77\x77\x01\0\0\0" "\0\0\0\0\0\0\0\0", 0x10);
    writer.write("\0\0\0\0\0\0\0\0" "\0\0\0\0\0\0\0\0", 0x10);
    writer.write("\0\0\0\0\0\xff\xff\xff" "\xff", 9);
    const CScript serHeight = CScript() << nHeight;
    const uint8_t nLenToken = (serHeight.size() + 33 + vchNonceC3.size());
    ser_writedata8(writer, nLenToken - 3);
    add_to_hash(writer, CFlatData(serHeight));
    ser_writedata8(writer, nDeploymentHard >> 24);
    add_to_hash(writer, GetHashCMR());
    add_to_hash(writer, CFlatData(vchNonceC3));
    add_to_hash(writer, nLenToken);
    writer.write("\x01\0\0\0\0\0\0\0" "\0\0\0\0\0\0", 0xE);
    return writer.GetHash();
}

uint256 CBlockHeader::GetHash() const
{
    CHashWriter writer(SER_GETHASH, 0);
    if (nHeight >= HARDFORK_HEIGHT) {
        add_to_hash(writer, nNonceC2);
        add_to_hash(writer, hashPrevBlock);
        add_to_hash(writer, GetHashHB());
    }
    else {
        add_to_hash(writer, nDeploymentSoft);
        add_to_hash(writer, hashPrevBlock);
        add_to_hash(writer, hashMerkleRoot);
    }
    add_to_hash(writer, nTTime);
    add_to_hash(writer, nBits);
    add_to_hash(writer, nNonce);
    return writer.GetHash();
}

std::string CBlock::ToString() const
{
    std::stringstream s;
    s << strprintf("CBlock(hash=%s, height=%u, deploySoft=0x%08x, deployHard=0x%06x, hashPrevBlock=%s, hashMerkleRoot=%s, hashMerkleRootWitness=%s, nTime=%u, nBits=%08x, nNonce=%u:%u:%s, vtx=%u, vbranches)\n",
        GetHash().ToString(),
        nHeight,
        nDeploymentSoft,
        nDeploymentHard,
        hashPrevBlock.ToString(),
        hashMerkleRoot.ToString(),
        hashMerkleRootWitnesses.ToString(),
        nTTime, nBits, nNonce,
        nNonceC2, HexStr(vchNonceC3),
        vtx.size(),
        vhashCMTBranches.size());
    for (unsigned int i = 0; i < vtx.size(); i++)
    {
        s << "  " << vtx[i]->ToString() << "\n";
    }
    return s.str();
}

int64_t GetBlockWeight(const CBlock& block)
{
    // This implements the weight = (stripped_size * 4) + witness_size formula,
    // using only serialization with and without witness data. As witness_size
    // is equal to total_size - stripped_size, this formula is identical to:
    // weight = (stripped_size * 3) + total_size.
    return ::GetSerializeSize(block, SER_NETWORK, PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS) * (WITNESS_SCALE_FACTOR - 1) + ::GetSerializeSize(block, SER_NETWORK, PROTOCOL_VERSION);
}