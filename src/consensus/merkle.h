// Copyright (c) 2015-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_MERKLE_H
#define BITCOIN_CONSENSUS_MERKLE_H

#include <stdint.h>
#include <vector>

#include <primitives/transaction.h>
#include <primitives/block.h>
#include <uint256.h>

uint256 ComputeMerkleRoot(std::vector<uint256> hashes, bool* mutated = nullptr);

/*
 * Compute the Merkle root of the transactions in a block.
 * *mutated is set to true if a duplicated subtree was found.
 */
uint256 BlockMerkleRoot(const CBlock& block, bool* mutated = nullptr);

/*
 * Compute the Merkle root of the witness transactions in a block.
 * *mutated is set to true if a duplicated subtree was found.
 */
uint256 BlockWitnessMerkleRoot(const CBlock& block, bool* mutated = nullptr);

/*
 * Compute the Merkle root with a leaf and a branch.
 * At every level, the two hashes from lower level are compared lexicographically (first byte being most significant).
 * Merkle hash is the single SHA256 of the two hashes serialed, the smaller first.
 * If the branch is empty, root hash is the leaf hash.
 */
uint256 ComputeOrderedMerkleRootFromBranch(const uint256& leaf, const std::vector<uint256>& merkle_branch);

#endif // BITCOIN_CONSENSUS_MERKLE_H
