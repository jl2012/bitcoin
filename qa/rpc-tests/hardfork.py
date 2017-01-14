#!/usr/bin/env python3
# Copyright (c) 2016 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *
from test_framework.mininode import CTransaction, hash256
from io import BytesIO

class ForceNetTest(BitcoinTestFramework):

    def __init__(self):
        super().__init__()
        self.num_nodes = 2
        self.setup_clean_chain = True

    def setup_network(self):
        self.nodes = []
        self.nodes.append(start_node(0, self.options.tmpdir, ["-debug", "-logtimemicros=1"]))
        self.nodes.append(start_node(1, self.options.tmpdir, ["-debug", "-logtimemicros=1"]))
        connect_nodes(self.nodes[0], 1)

    def run_test(self):
        self.address = self.nodes[0].getnewaddress()
        self.wit_address = self.nodes[0].addwitnessaddress(self.address)

        self.coinbase_blocks = self.nodes[0].generate(150) # Block 150
        sync_blocks(self.nodes)
        coinbase_txid = []
        for i in self.coinbase_blocks:
            coinbase_txid.append(self.nodes[0].getblock(i)['tx'][0])
            legacyheader = self.nodes[0].getlegacyblockheader(i)
            headerhash = self.reverse_hash(hash256(hex_str_to_bytes(legacyheader)))
            assert (i == headerhash)

        tx = self.create_transaction(self.nodes[0], coinbase_txid[0], self.wit_address, 49)
        txid = self.tx_submit(self.nodes[0], tx)
        tx = self.create_transaction(self.nodes[0], txid, self.wit_address, 48)
        self.tx_submit(self.nodes[0], tx)

        sync_mempools(self.nodes)
        assert_equal(len(self.nodes[0].getrawmempool()), 2)
        hash = self.nodes[1].generate(1)[0]
        sync_mempools(self.nodes)
        assert_equal(len(self.nodes[0].getblock(hash)['tx']), 3)
        assert_equal(len(self.nodes[0].getrawmempool()), 0)

        self.coinbase_blocks = self.nodes[0].generate(150) # Block 301

        sync_blocks(self.nodes)

        for i in self.coinbase_blocks:
            coinbase_txid.append(self.nodes[0].getblock(i)['tx'][0])
            legacyheader = self.nodes[0].getlegacyblockheader(i)
            headerhash = self.reverse_hash(hash256(hex_str_to_bytes(legacyheader)))
            assert (i == headerhash)

        tx = self.create_transaction(self.nodes[0], coinbase_txid[1], self.wit_address, 49)
        txid = self.tx_submit(self.nodes[0], tx)
        tx = self.create_transaction(self.nodes[0], txid, self.wit_address, 48)
        self.tx_submit(self.nodes[0], tx)

        sync_mempools(self.nodes)
        assert_equal(len(self.nodes[0].getrawmempool()), 2)
        hash = self.nodes[1].generate(1)[0]
        sync_mempools(self.nodes)
        assert_equal(len(self.nodes[0].getblock(hash)['tx']), 3)
        assert_equal(len(self.nodes[0].getrawmempool()), 0)
        legacyblock = self.nodes[1].getlegacyblock(hash)
        dummymerkleroot = bytes_to_hex_str(hash256(hex_str_to_bytes(legacyblock[162:])))
        assert_equal(dummymerkleroot, legacyblock[72:136])
        sync_blocks(self.nodes)

    def reverse_hash(self, hash):
        return (bytes_to_hex_str(hash[::-1]))

    def create_transaction(self, node, txid, to_address, amount):
        inputs = [{ "txid" : txid, "vout" : 0}]
        outputs = { to_address : amount }
        rawtx = node.createrawtransaction(inputs, outputs)
        signresult = node.signrawtransaction(rawtx)
        tx = CTransaction()
        f = BytesIO(hex_str_to_bytes(signresult['hex']))
        tx.deserialize(f)
        return tx

    def tx_submit(self, node, tx, msg = ""):
        tx.rehash()
        try:
            node.sendrawtransaction(bytes_to_hex_str(tx.serialize_with_witness()), True)
        except JSONRPCException as exp:
            assert_equal(exp.error["message"], msg)
        else:
            assert_equal('', msg)
        return tx.hash

if __name__ == '__main__':
    ForceNetTest().main()
