#!/usr/bin/env python3
# Copyright (c) 2019 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
# Test taproot softfork.

from test_framework.blocktools import create_coinbase, create_block, create_transaction, add_witness_commitment
from test_framework.messages import CTransaction, CTxIn, CTxOut, COutPoint
from test_framework.script import CScript, TaprootSignatureHash, OP_10, Taproot
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error
from test_framework.key import CECKey, CPubKey
from test_framework.address import program_to_witness
from binascii import hexlify
from hashlib import sha256
from secrets import token_bytes

UNKNOWNWITNESS_ERROR = "non-mandatory-script-verify-flag (Witness version reserved for soft-fork upgrades) (code 64)"

class TAPROOTTest(BitcoinTestFramework):

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-whitelist=127.0.0.1", "-acceptnonstdtxn=0", "-vbparams=segwit:0:999999999999"]]

    def run_test(self):
        bare_taproot = Taproot(token_bytes(32))

        blockhash = self.nodes[0].generate(250)
        self.coinbase = []
        for i in blockhash:
            self.coinbase.append(self.nodes[0].getblock(i)['tx'][0])

        self.lastblockhash = self.nodes[0].getbestblockhash()
        self.tip = int("0x" + self.lastblockhash, 0)
        block = self.nodes[0].getblock(self.lastblockhash)
        self.lastblockheight = block['height']
        self.lastblocktime = block['time']

        self.log.info("Test 1: Pre-activation sending to native taproot is accepted to mempool")
        txid = []
        txid.append(self.send_with_coinbase(49, bare_taproot.get_bech32()))
        txid.append(self.send_with_coinbase(49, bare_taproot.get_p2sh()))
        hash = self.nodes[0].generate(1)
        block = self.nodes[0].getblock(hash[0])
        for i in txid:
            assert i in block['tx']

        self.log.info("Test 2: Pre-activation spending of taproot is not accepted to mempool")
        tx = self.create_tx(txid[0], 0, 48, bare_taproot.get_spk())
        assert_raises_rpc_error(-26, UNKNOWNWITNESS_ERROR, self.nodes[0].sendrawtransaction, tx.serialize_with_witness().hex(), 0)
        tx = self.create_tx(txid[1], 0, 48, bare_taproot.get_spk())
        tx.vin[0].scriptSig = CScript([bare_taproot.get_spk()])
        assert_raises_rpc_error(-26, UNKNOWNWITNESS_ERROR, self.nodes[0].sendrawtransaction, tx.serialize_with_witness().hex(), 0)

    def send_with_coinbase(self, value, address):
        tx = create_transaction(self.nodes[0], self.coinbase[0], address, amount = value)
        txid = self.nodes[0].sendrawtransaction(tx.serialize_with_witness().hex(), 0)
        self.coinbase = self.coinbase[1:]
        return txid

    def create_tx(self, txid, n, value, spk):
        tx = CTransaction()
        tx.vin.append(CTxIn(COutPoint(int(txid, 16), n)))
        tx.vout.append(CTxOut(int(value * 100000000), spk))
        tx.rehash()
        return tx


    def block_submit(self, node, txs, witness=False, accept=False):
        block = create_block(self.tip, create_coinbase(self.lastblockheight + 1), self.lastblocktime + 1)
        block.nVersion = 4
        for tx in txs:
            tx.rehash()
            block.vtx.append(tx)
        block.hashMerkleRoot = block.calc_merkle_root()
        witness and add_witness_commitment(block)
        block.rehash()
        block.solve()
        node.submitblock(block.serialize(True).hex())
        if (accept):
            assert_equal(node.getbestblockhash(), block.hash)
            self.tip = block.sha256
            self.lastblockhash = block.hash
            self.lastblocktime += 1
            self.lastblockheight += 1
        else:
            assert_equal(node.getbestblockhash(), self.lastblockhash)


if __name__ == '__main__':
    TAPROOTTest().main()
