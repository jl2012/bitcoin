#!/usr/bin/env python3
# Copyright (c) 2017 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *
from test_framework.mininode import CTransaction, NetworkThread, CTxIn, CTxOut, COutPoint
from test_framework.blocktools import create_coinbase, create_block
from test_framework.script import CScript, OP_TRUE, OP_HASH160, OP_EQUAL, hash160, hash256
from io import BytesIO
import time


class ColorCoinTest(BitcoinTestFramework):

    def __init__(self):
        super().__init__()
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [['-whitelist=127.0.0.1', '-acceptnonstdtxn=0']]

    def run_test(self):
        NetworkThread().start() # Start up network handling in another thread
        self.lastblockhash = self.nodes[0].getbestblockhash()
        self.tip = int("0x" + self.lastblockhash, 0)
        self.lastblockheight = 0
        self.lastblocktime = int(time.time())

        vout = []
        for i in range(0x51, 0x56):
            vout.append(CTxOut(10000000, CScript([OP_HASH160, hash160(bytes([i])), OP_EQUAL])))
        vout.append(CTxOut(0, hex_str_to_bytes("6a4d85ad00112233445566778899aabbccddeeff0123456789abcdef0123456789abcdef01")))

        self.block_submit(self.nodes[0], 143, 4, [], vout) # block 143
        txid = int("0x" + self.nodes[0].getblock(self.lastblockhash)['tx'][0], 0)
        self.block_submit(self.nodes[0], 288, 0x20000040, []) # block 431

        vout = []
        vout.append(CTxOut(1000000, hex_str_to_bytes("a914da1745e9b549bd0bfa1a569971c77eba30cd5a4b87")))
        vout.append(CTxOut(1000000, hex_str_to_bytes("a914da1745e9b549bd0bfa1a569971c77eba30cd5a4b87")))
        vout.append(CTxOut(0, hex_str_to_bytes("6a4d85ad00112233445566778899aabbccddeeff0123456789abcdef0123456789abcdef01")))
        tx = self.create_transaction(self.nodes[0], 2, txid, vout)
        tx.vin[0].scriptSig = hex_str_to_bytes("0151")
        self.tx_submit(tx, "scriptpubkey")
        tx.nVersion = 3
        self.tx_submit(tx, "bad-txns-color-in-belowout")
        tx.vout.append(CTxOut(0, hex_str_to_bytes("6a4d85ad00112233445566778899aabbccddeeff0123456789abcdef0123456789abcdef02")))
        self.tx_submit(tx, "bad-txns-color-in-belowout")
        tx.vout.append(CTxOut(0, hex_str_to_bytes("6a4d85ad00112233445566778899aabbccddeeff0123456789abcdef0123456789abcdef02")))
        self.tx_submit(tx, "bad-txns-color-multiple")
        tx.vout.append(CTxOut(0, hex_str_to_bytes("6a4d85ad00112233445566778899aabbccddeeff0123456789abcdef0123456789abcdee02")))
        self.tx_submit(tx, "bad-txns-color-multiple")
        tx.vout[4] = CTxOut(0, hex_str_to_bytes("6a4d85ad00112233445566778899aabbccddeeff0123456789abcdef0123456789abcdef04"))
        self.tx_submit(tx, "bad-txns-color-selfassign")
        tx.vout[4] = CTxOut(0, hex_str_to_bytes("6a4d85ad00112233445566778899aabbccddeeff0123456789abcdef0123456789abcdef80"))
        self.tx_submit(tx, "bad-txns-color-outofrange")
        tx.vout.pop()
        tx.vout.pop()
        tx.vout.pop()

        tx.vin[0].nSequence = (1 << 23)
        color = bytes_to_hex_str(hash256(hex_str_to_bytes("0000800017a914da1745e9b549bd0bfa1a569971c77eba30cd5a4b87")))
        tx.vout[2] = CTxOut(0, hex_str_to_bytes("6a4d85ad" + color + "03"))
        self.tx_submit(tx)

        self.block_submit(self.nodes[0], 1, 4, [tx])  # block 431
        vout = []
        vout.append(CTxOut(400000, hex_str_to_bytes("a914da1745e9b549bd0bfa1a569971c77eba30cd5a4b87")))
        vout.append(CTxOut(410000, hex_str_to_bytes("a914da1745e9b549bd0bfa1a569971c77eba30cd5a4b87")))
        vout.append(CTxOut(0, hex_str_to_bytes("6a4d85ad" + color + "01")))
        txid = tx.sha256
        tx = self.create_transaction(self.nodes[0], 3, txid, vout)
        tx.vin[0].scriptSig = hex_str_to_bytes("0151")
        self.tx_submit(tx, "bad-txns-color-sequence")
        tx.vin[0].nSequence = (1 << 23 | 1 << 24)
        self.tx_submit(tx)

    def create_transaction(self, node, nVersion, txid, vout):
        tx = CTransaction()
        tx.nVersion = nVersion
        tx.vin.append(CTxIn(COutPoint(txid,0)))
        tx.vout = vout
        tx.rehash()
        return tx

    def tx_submit(self, tx, error=""):
        if (error):
            assert_raises_jsonrpc(-26, error, self.nodes[0].sendrawtransaction, bytes_to_hex_str(tx.serialize()), True)
        else:
            self.nodes[0].sendrawtransaction(bytes_to_hex_str(tx.serialize()))

    def block_submit(self, node, count, nVersion, txs, vout = [CTxOut(100000000, hex_str_to_bytes("a914da1745e9b549bd0bfa1a569971c77eba30cd5a4b87"))], error = ""):
        for i in range(count):
            coinbase = create_coinbase(self.lastblockheight + 1)
            coinbase.nVersion = 3
            coinbase.vout = vout
            coinbase.rehash()
            block = create_block(self.tip, coinbase, self.lastblocktime + 1)
            block.nVersion = nVersion
            for tx in txs:
                tx.rehash()
                block.vtx.append(tx)
            block.hashMerkleRoot = block.calc_merkle_root()
            block.rehash()
            block.solve()
            ret = node.submitblock(bytes_to_hex_str(block.serialize(True)))
            if (not(error)):
                assert_equal(node.getbestblockhash(), block.hash)
                self.tip = block.sha256
                self.lastblockhash = block.hash
                self.lastblocktime += 1
                self.lastblockheight += 1
            else:
                assert_equal(node.getbestblockhash(), self.lastblockhash)
                assert_equal(ret, error)

if __name__ == '__main__':
    ColorCoinTest().main()
