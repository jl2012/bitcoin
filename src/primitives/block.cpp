// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "primitives/block.h"

#include "hash.h"
#include "tinyformat.h"
#include "utilstrencodings.h"
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

uint256 CBlockHeader::GetHash() const
{
    return SerializeHash(*this);
}

std::string CBlock::ToString() const
{
    std::stringstream s;
    s << strprintf("CBlock(hash=%s, deploySoft=0x%08x, hashPrevBlock=%s, hashMerkleRoot=%s, nTime=%u, nBits=%08x, nNonce=%u, vtx=%u)\n",
        GetHash().ToString(),
        nDeploymentSoft,
        hashPrevBlock.ToString(),
        hashMerkleRoot.ToString(),
        nTTime, nBits, nNonce,
        vtx.size());
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
