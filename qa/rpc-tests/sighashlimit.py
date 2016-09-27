#!/usr/bin/env python3
# Copyright (c) 2016 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from test_framework.test_framework import BitcoinTestFramework
from test_framework.mininode import CTransaction, CTxOut, CTxIn, COutPoint, CTxInWitness
from test_framework.util import *
from test_framework.key import CECKey, CPubKey
from test_framework.script import CScript, OP_0, OP_1, OP_3, OP_12, OP_14, OP_CHECKSIG, OP_CHECKMULTISIG, OP_CODESEPARATOR, OP_CHECKMULTISIGVERIFY, OP_CHECKSIGVERIFY, OP_HASH160, OP_EQUAL, SignatureHash, SIGHASH_ALL, hash160, sha256, SegwitVersion1SignatureHash
import time
from random import randint

'''
This is to test the correctness and performance of 2 types of sighash caches:
#8524: Intra/inter-input sighash midstate cache for segwit (BIP143)
#8654: Intra-input sighash reuse
'''

dummykey = hex_str_to_bytes("0300112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")

# By default, we generate a transaction with 38 inputs and 38 outputs. Each input contains 14 sigOPs.
# scriptPubKey size for each output is 24684 bytes. The total uncached hashing size for SIGHASH_ALL is:
# 38 * 38 * 14 * (24684 + 32 + 4 + 4 + 8) = about 500MB

# Set 2 to reduce the testing time if we just want to test for correctness. Set to 1 for more accurate benchmarking
speedup = 2

default_nIn = 38 // speedup
default_nOut = default_nIn
default_outputsize = 24684 // speedup
default_amount = 200000
null = hex_str_to_bytes("")
time_assertion = False # compare validation time with benchmarking test
verbose = True # print validation details

class SigHashCacheTest(BitcoinTestFramework):

    def __init__(self):
        super().__init__()
        self.setup_clean_chain = True

    def setup_network(self):
        # Switch off STRICTENC so we could test strange nHashType
        self.nodes = [start_node(0, self.options.tmpdir, ["-promiscuousmempoolflags=8181", "-acceptnonstdtxn=0", "-blockmaxweight=4000000"])]
        self.nodes.append(start_node(1, self.options.tmpdir, ["-promiscuousmempoolflags=8181", "-blockmaxweight=4000000"]))
        connect_nodes(self.nodes[0], 1)

    def generate_txpair(self, offset, witoffset = 500, nIn = default_nIn, nOut = default_nOut, outputsize = default_outputsize):
        # Generate a pair of transactions: non-segwit and segwit
        txpair = [CTransaction(), CTransaction()]
        for i in range(nIn):
            txpair[0].vin.append(CTxIn(COutPoint(self.txid,i+offset),nSequence=4294967295))
            txpair[1].vin.append(CTxIn(COutPoint(self.txid,i+offset+witoffset),nSequence=4294967295))
            txpair[1].wit.vtxinwit.append(CTxInWitness())
        for i in range(nOut):
            txpair[0].vout.append(CTxOut(1, hex_str_to_bytes("00" * outputsize)))
            txpair[1].vout.append(CTxOut(1, hex_str_to_bytes("00" * outputsize)))
        return txpair

    def validation_time(self, txpair):
        # sendrawtransaction and timing
        [tx, wtx] = txpair
        start = time.time()
        self.nodes[0].sendrawtransaction(bytes_to_hex_str(tx.serialize_with_witness()), True)
        t = time.time() - start
        self.nodes[0].generate(1)
        start = time.time()
        self.nodes[0].sendrawtransaction(bytes_to_hex_str(wtx.serialize_with_witness()), True)
        wt = time.time() - start
        if (verbose):
            print ("**Non-witness**")
            print ("Transaction weight : " + str(len(tx.serialize_without_witness()) * 3 + len(tx.serialize_with_witness())))
            print ("Validation time    : " + str(t))
            print ("**Witness**")
            print ("Transaction weight : " + str(len(wtx.serialize_without_witness()) * 3 + len(wtx.serialize_with_witness())))
            print ("Validation time    : " + str(wt))
        self.nodes[0].generate(1)
        return [t, wt]

    def test_preparation(self):
        self.coinbase_blocks = self.nodes[1].generate(1)
        coinbase_txid = int("0x" + self.nodes[1].getblock(self.coinbase_blocks[0])['tx'][0], 0)
        self.nodes[1].generate(100)

        tx = CTransaction()
        tx.vin.append(CTxIn(COutPoint(coinbase_txid)))

        self.script = CScript([OP_0, OP_0, OP_0, OP_1, OP_CHECKMULTISIG])
        self.p2sh = CScript([OP_HASH160, hash160(self.script), OP_EQUAL])
        self.p2wsh = CScript([OP_0, sha256(self.script)])
        for i in range(1000):
            tx.vout.append(CTxOut(3800000, self.p2sh))
        for i in range(300):
            tx.vout.append(CTxOut(3800000, self.p2wsh))

        tx.rehash()
        signresults = self.nodes[1].signrawtransaction(bytes_to_hex_str(tx.serialize_with_witness()))['hex']
        self.txid = int("0x" + self.nodes[1].sendrawtransaction(signresults, True), 0)
        self.nodes[1].generate(1)
        sync_blocks(self.nodes)

        self.p2shcount = 0
        self.p2wshcount = 1000

    def non_segwit_test(self):
        bigtx = CTransaction()
        smalltx = CTransaction()
        for i in range(121):
            bigtx.vin.append(CTxIn(COutPoint(self.txid,self.p2shcount),CScript([self.script])))
            smalltx.vin.append(CTxIn(COutPoint(self.txid,self.p2shcount + 1),CScript([self.script])))
            self.p2shcount += 2
        for i in range(2567):
            bigtx.vout.append(CTxOut(1000, self.p2sh))
            smalltx.vout.append(CTxOut(1000, self.p2sh))
        bigtx.vout.append(CTxOut(1000, self.p2sh))
        bigtx.rehash()
        smalltx.rehash()

        try:
            self.nodes[0].sendrawtransaction(bytes_to_hex_str(bigtx.serialize_without_witness()), True)
        except JSONRPCException as exp:
            assert_equal(exp.error["message"], "64: bad-txns-nonstandard-too-much-sighashing")
        assert_equal(len(self.nodes[0].getrawmempool()), 0)
        self.nodes[1].sendrawtransaction(bytes_to_hex_str(bigtx.serialize_without_witness()), True)
        self.nodes[0].sendrawtransaction(bytes_to_hex_str(smalltx.serialize_without_witness()), True)
        self.nodes[1].sendrawtransaction(bytes_to_hex_str(smalltx.serialize_without_witness()), True)
        self.nodes[1].generate(1)
        sync_blocks(self.nodes)
        assert_equal(len(self.nodes[0].getrawmempool()), 0)
        assert_equal(len(self.nodes[1].getrawmempool()), 0)

    def non_segwit_test2(self):
        bigtx = CTransaction()
        smalltx = CTransaction()
        for i in range(121):
            bigtx.vin.append(CTxIn(COutPoint(self.txid,self.p2shcount),CScript([self.script])))
            smalltx.vin.append(CTxIn(COutPoint(self.txid,self.p2shcount + 1),CScript([self.script])))
            self.p2shcount += 2
        for i in range(2567):
            bigtx.vout.append(CTxOut(1000, self.p2sh))
            smalltx.vout.append(CTxOut(1000, self.p2sh))
        bigtx.vout.append(CTxOut(1000, self.p2sh))
        bigtx.rehash()
        smalltx.rehash()

        try:
            self.nodes[0].sendrawtransaction(bytes_to_hex_str(bigtx.serialize_without_witness()), True)
        except JSONRPCException as exp:
            assert_equal(exp.error["message"], "64: bad-txns-nonstandard-too-much-sighashing")
        assert_equal(len(self.nodes[0].getrawmempool()), 0)
        #self.nodes[1].sendrawtransaction(bytes_to_hex_str(bigtx.serialize_without_witness()), True)
        #self.nodes[0].sendrawtransaction(bytes_to_hex_str(smalltx.serialize_without_witness()), True)
        self.nodes[1].sendrawtransaction(bytes_to_hex_str(smalltx.serialize_without_witness()), True)
        #self.nodes[1].generate(400)
        #sync_blocks(self.nodes)
        #self.nodes[1].generate(1000)
        #sync_blocks(self.nodes)
        #assert_equal(len(self.nodes[0].getrawmempool()), 0)
        #assert_equal(len(self.nodes[1].getrawmempool()), 0)
        for i in range(400):
            self.nodes[1].generate(1)
            #print (i)
            print (self.nodes[1].getrawmempool())


    def segwit_test(self):
        bigtx = CTransaction()
        smalltx = CTransaction()
        for i in range(121):
            bigtx.vin.append(CTxIn(COutPoint(self.txid,self.p2wshcount)))
            bigtx.wit.vtxinwit.append(CTxInWitness())
            bigtx.wit.vtxinwit[i].scriptWitness.stack = [self.script]
            smalltx.vin.append(CTxIn(COutPoint(self.txid,self.p2wshcount + 1)))
            smalltx.wit.vtxinwit.append(CTxInWitness())
            smalltx.wit.vtxinwit[i].scriptWitness.stack = [self.script]
            self.p2wshcount += 2
        for i in range(121):
            bigtx.vin.append(CTxIn(COutPoint(self.txid,self.p2shcount),CScript([self.script])))
            smalltx.vin.append(CTxIn(COutPoint(self.txid,self.p2shcount + 1),CScript([self.script])))
            self.p2shcount += 2
        for i in range(2000):
            bigtx.vout.append(CTxOut(1000, self.p2sh))
            smalltx.vout.append(CTxOut(1000, self.p2sh))
        bigtx.vout.append(CTxOut(1000, self.p2sh))
        bigtx.rehash()
        smalltx.rehash()
        print ("Transaction weight : " + str(len(bigtx.serialize_without_witness()) * 3 + len(bigtx.serialize_with_witness())))


        try:
            self.nodes[0].sendrawtransaction(bytes_to_hex_str(bigtx.serialize_with_witness()), True)
        except JSONRPCException as exp:
            assert_equal(exp.error["message"], "64: bad-txns-nonstandard-too-much-sighashing")
        #assert_equal(len(self.nodes[0].getrawmempool()), 0)
        self.nodes[1].sendrawtransaction(bytes_to_hex_str(bigtx.serialize_with_witness()), True)
        self.nodes[0].sendrawtransaction(bytes_to_hex_str(smalltx.serialize_with_witness()), True)
        self.nodes[1].sendrawtransaction(bytes_to_hex_str(smalltx.serialize_with_witness()), True)
        self.nodes[1].generate(1)
        sync_blocks(self.nodes)


# def signtx(self, scripts, txpair, nIn, flags):
    #     sig = []
    #     wsig = []
    #     for i in (range(len(scripts))):
    #         sighash = SignatureHash(scripts[i], txpair[0], nIn, flags[i])[0]
    #         sig.append(self.key.sign(sighash) + chr(flags[i]).encode('latin-1'))
    #         wsighash = SegwitVersion1SignatureHash(scripts[i], txpair[1], nIn, flags[i], default_amount)
    #         wsig.append(self.key.sign(wsighash) + chr(flags[i]).encode('latin-1'))
    #     return [sig, wsig]

    def MS_14_of_14_different_ALL(self):
        print ("Test: 14-of-14 CHECKMULTISIG P2SH/P2WSH inputs with different variations of SIGHASH_ALL")
        script = self.script[1]
        txpair = self.generate_txpair(1000)
        for i in range(default_nIn):
            [sig, wsig] = self.signtx([script] * 14, txpair, i, range(4,18))
            txpair[0].vin[i].scriptSig = CScript([OP_0] + sig + [script])
            txpair[1].wit.vtxinwit[i].scriptWitness.stack = [null] + wsig + [script]
        [t, wt] = self.validation_time(txpair)
        self.banchmark = t # For non-segwit this is equivalent to no cache
        if (time_assertion):
            assert(self.banchmark / wt > 4)


    def run_test(self):
        self.test_preparation()
        self.non_segwit_test()
        self.nodes[0].generate(400)
        self.non_segwit_test2()
        #self.segwit_test()

if __name__ == '__main__':
    SigHashCacheTest().main()