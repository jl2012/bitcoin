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

uint256 CBlockHeader::GetHash() const
{
    CHashWriter writer(SER_GETHASH, 0);
    if (nHeight >= HARDFORK_HEIGHT) {
        CHashWriter writer1(SER_GETHASH, 0);
        CHashWriter writer2(SER_GETHASH, 0);
        add_to_hash(writer1, nTxsBytes);
        add_to_hash(writer1, nTxsCost);
        add_to_hash(writer1, nTxsSigops);
        add_to_hash(writer1, nTxsCount);
        {
            const uint16_t nDeploymentHardWithinMM = nDeploymentHard;
            add_to_hash(writer1, nDeploymentHardWithinMM);
        }
        add_to_hash(writer1, nDeploymentSoft);
        add_to_hash(writer1, hashMerkleRoot);
        add_to_hash(writer1, hashMerkleRootWitnesses);

        const uint256 hashHC = writer1.GetHash();

        assert(vchNonceC3.size() >= 4);
        const uint32_t pos_nonce = (uint32_t(vchNonceC3[0]) << 0x18)
                                 | (uint32_t(vchNonceC3[1]) << 0x10)
                                 | (uint32_t(vchNonceC3[2]) <<    8)
                                 | (uint32_t(vchNonceC3[3])        );
        const uint32_t pos = vector_position_for_hc(pos_nonce, 1 << vhashCMTBranches.size());
        const uint256 hashCMR = ComputeMerkleRootFromBranch(hashHC, vhashCMTBranches, pos);

        writer2.write("\x77\x77\x77\x77\x01\0\0\0" "\0\0\0\0\0\0\0\0", 0x10);
        writer2.write("\0\0\0\0\0\0\0\0" "\0\0\0\0\0\0\0\0", 0x10);
        writer2.write("\0\0\0\0\0\xff\xff\xff" "\xff", 9);
        const CScript serHeight = CScript() << nHeight;
        const uint8_t nLenToken = (serHeight.size() + sizeof(hashCMR) + vchNonceC3.size());
        ser_writedata8(writer2, nLenToken - 3);
        add_to_hash(writer2, nLenToken);
        add_to_hash(writer2, CFlatData(serHeight));
        {
            const uint8_t nDeploymentMMHard = nDeploymentHard >> 16;
            add_to_hash(writer2, nDeploymentMMHard);
        }
        add_to_hash(writer2, hashCMR);
        add_to_hash(writer2, vchNonceC3);
        add_to_hash(writer2, CFlatData(vchNonceC3));
        add_to_hash(writer2, nLenToken);
        writer2.write("\x01\0\0\0\0\0\0\0" "\0\0\0\0\0\0", 0xE);

        const uint256 hashHB = writer2.GetHash();

        assert(nNonceC2 >> 0x18);
        ser_writedata24(writer, nNonceC2);
        writer.write("\x60", 1);
        add_to_hash(writer, hashPrevBlock);
        add_to_hash(writer, hashHB);
        add_to_hash(writer, nTTime);
        add_to_hash(writer, nBits);
        add_to_hash(writer, nNonce);
    } else {
        add_to_hash(writer, nDeploymentSoft);
        add_to_hash(writer, hashPrevBlock);
        add_to_hash(writer, hashMerkleRoot);
        add_to_hash(writer, nTTime);
        add_to_hash(writer, nBits);
        add_to_hash(writer, nNonce);
    }
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
