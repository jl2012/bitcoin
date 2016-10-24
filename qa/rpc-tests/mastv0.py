#!/usr/bin/env python3
# Copyright (c) 2016 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from test_framework.mininode import hex_str_to_bytes, bytes_to_hex_str, CTxIn, CTxInWitness
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import start_node, connect_nodes, sync_blocks, JSONRPCException, assert_equal
from test_framework.script import *
from test_framework.key import CECKey, CPubKey
from math import log, ceil
from io import BytesIO


CHECKSIGFAIL = "64: non-mandatory-script-verify-flag (Signature must be zero for failed CHECK(MULTI)SIG operation)"
CHECKMULTISIGFAIL = "64: non-mandatory-script-verify-flag (Script failed an OP_CHECKMULTISIGVERIFY operation)"
NULLFAIL = "64: non-mandatory-script-verify-flag (Signature must be zero for failed CHECK(MULTI)SIG operation)"
FLAGSFAIL = "64: non-mandatory-script-verify-flag (Invalid signature flags for OP_CHECKMULTISIG(VERIFY))"
SIGCODEFAIL = "64: non-mandatory-script-verify-flag (sigScriptCode is not committed to by signature)"
UNKNOWNWITNESS = "64: non-mandatory-script-verify-flag (Witness version reserved for soft-fork upgrades)"

def find_unspent(node, min_value):
    for utxo in node.listunspent():
        if utxo['amount'] >= min_value:
            return utxo

def get_keyscripthash(branch):
    assert (len(branch) > 0)
    sh = chr(len(branch)).encode('latin-1')
    for i in branch:
        sh += hash256(i)
    return hash256(sh)

def get_hash_list(scripts):
    depth = ceil(log(len(scripts), 2))
    assert (depth <= 32)
    hash = []
    for i in scripts:
        hash.append(get_keyscripthash(i))
    for i in range(len(scripts), 2 ** depth):
        hash.append(hash256(CScript([OP_RETURN])))
    return hash

def get_higher_hash(hash):
    for i in range(0, len(hash), 2):
        cat = hash[i] + hash[i+1]
        hash[i//2] = hash256(cat)
    return hash[:-len(hash)//2]

def get_mast_spk(scripts):
    hash = get_hash_list(scripts)
    while (len(hash) > 1):
        hash = get_higher_hash(hash)
    root = hex_str_to_bytes("00000000") + hash[0]
    return CScript([OP_1, hash256(root)])

def get_mast_stack(scripts, pos, sigscript = []):
    hash = get_hash_list(scripts)
    poscopy = int(pos)
    path = b''
    while (len(hash) > 1):
        if (poscopy % 2):
            path += hash[poscopy - 1]
        else:
            path += hash[poscopy + 1]
        poscopy //= 2
        hash = get_higher_hash(hash)

    stack = []
    assert (len(sigscript) <= 6)
    for i in sigscript:
        stack.append(i)
    if len(sigscript):
        assert (len(sigscript[0]))
        stack.append(chr(len(sigscript)).encode('latin-1'))
    else:
        stack.append(b'')
    for i in scripts[pos]:
        stack.append(i)
    if (pos > 0):
        stack.append(chr(pos).encode('latin-1'))
    else:
        stack.append(b'')
    stack.append(path)
    stack.append(chr(len(scripts[pos])).encode('latin-1'))
    return stack

def get_sighash(pubkey, mast, pos, tx, nIn, nOut, hashtype, amount, fee, sigScriptCode = [CScript()] * 6):
    sighash = MASTVersion0SignatureHash(pubkey, get_mast_spk(mast), get_keyscripthash(mast[pos]), sigScriptCode, tx, nIn, nOut, hashtype, amount, fee)
    return sighash

def sign_mast(key, mast, pos, tx, nIn, nOut, hashtype, amount, fee, sigScriptCode = []):
    assert (nOut < 65536)
    assert (hashtype < 65536)
    pubkey = CPubKey(key.get_pubkey())
    while (len(sigScriptCode) < 6):
        sigScriptCode = [CScript()] + sigScriptCode
    sighash = MASTVersion0SignatureHash(pubkey, get_mast_spk(mast), get_keyscripthash(mast[pos]), sigScriptCode, tx, nIn, nOut, hashtype, amount, fee)
    sig = key.sign(sighash, mast = True)
    if hashtype == 0:
        return sig
    sig += chr(hashtype & 0xff).encode('latin-1')
    if hashtype < 256:
        return sig
    sig += chr(hashtype >> 8).encode('latin-1')
    if (nOut > 0) and (((hashtype & 0xc000) == SIGHASHV2_DUALOUTPUT) or ((hashtype & 0xc000) == SIGHASHV2_SINGLEOUTPUT)):
        sig += chr(nOut & 0xff).encode('latin-1')
        if nOut >= 256:
            sig += chr(nOut >> 8).encode('latin-1')
    return sig

class SegWitTest(BitcoinTestFramework):

    def __init__(self):
        super().__init__()
        self.setup_clean_chain = True
        self.num_nodes = 2

    def setup_network(self):
        self.nodes = []
        self.nodes.append(start_node(0, self.options.tmpdir, ["-logtimemicros", "-blockversion=536870915", "-debug"]))
        self.nodes.append(start_node(1, self.options.tmpdir, ["-logtimemicros", "-blockversion=536870916", "-debug", "-acceptnonstdtxn=0"]))
        connect_nodes(self.nodes[1], 0)
        self.is_network_split = False
        self.sync_all()

    def mine_and_clear_mempool(self, node, blocks = 1):
        self.nodes[node].generate(blocks)
        sync_blocks(self.nodes)
        assert_equal(len(self.nodes[node].getrawmempool()), 0)

    def run_test(self):
        key1 = CECKey()
        key1.set_secretbytes(b"1")
        key1.set_compressed(True)
        pubkey1 = CPubKey(key1.get_pubkey())
        key2 = CECKey()
        key2.set_secretbytes(b"2")
        key2.set_compressed(True)
        pubkey2 = CPubKey(key2.get_pubkey())

        mast1 = []
        mast1.append([CScript([pubkey1, OP_CHECKSIGVERIFY])])
        mast1.append([CScript([OP_1, OP_EQUALVERIFY])])
        mast1.append([CScript([pubkey1, OP_CHECKSIGVERIFY]), CScript([pubkey2, OP_CHECKSIGVERIFY])])
        mast1.append([CScript([OP_2, pubkey1, pubkey2, OP_2, OP_CHECKMULTISIGVERIFY])])
        mast1.append([CScript([OP_1, pubkey1, pubkey2, OP_2, OP_CHECKMULTISIGVERIFY])])

        mast2 = []
        mast2.append([CScript([pubkey1, OP_CHECKSIGVERIFY]), CScript([pubkey2, OP_CHECKSIGVERIFY])])
        mast2.append([CScript([pubkey1, OP_CHECKSIGVERIFY])])
        mast2.append([CScript([OP_1, OP_EQUALVERIFY])])

        self.mine_and_clear_mempool(0, 432) # block 432: activate segwit

        utxo = find_unspent(self.nodes[0], 50)
        tx = CTransaction()
        tx.vin.append(CTxIn(COutPoint(int('0x'+utxo['txid'],0), utxo['vout'])))
        tx.vout.append(CTxOut(4990 * 1000 * 1000, get_mast_spk(mast1)))
        signresults = self.nodes[0].signrawtransaction(bytes_to_hex_str(tx.serialize_without_witness()))['hex']
        tx.deserialize(BytesIO(hex_str_to_bytes(signresults)))
        txid = self.tx_submit(0, tx)
        self.tx_submit(1, tx, "64: scriptpubkey")
        self.mine_and_clear_mempool(0)

        tx = CTransaction()
        tx.vin.append(CTxIn(COutPoint(txid, 0)))
        tx.wit.vtxinwit.append(CTxInWitness())
        tx.vout.append(CTxOut(4980 * 1000 * 1000, CScript([OP_DUP, OP_HASH160, hash160(pubkey1), OP_EQUALVERIFY, OP_CHECKSIG])))
        tx.wit.vtxinwit[0].scriptWitness.stack = [b'\x01'] + get_mast_stack(mast1, 1)
        self.tx_submit(0, tx, UNKNOWNWITNESS)
        self.tx_submit(1, tx, UNKNOWNWITNESS)

        self.mine_and_clear_mempool(1, 285) # Last block without MAST
        self.tx_submit(0, tx, UNKNOWNWITNESS)
        self.tx_submit(1, tx, UNKNOWNWITNESS)

        self.mine_and_clear_mempool(0) # First block with MAST
        self.tx_submit(0, tx)
        self.tx_submit(1, tx)

        amount = [830 * 1000 * 1000, 830 * 1000 * 1000, 840 * 1000 * 1000, 820 * 1000 * 1000, 810 * 1000 * 1000, 830 * 1000 * 1000]

        utxo = find_unspent(self.nodes[0], 50)
        tx = CTransaction()
        tx.vin.append(CTxIn(COutPoint(int('0x'+utxo['txid'],0), utxo['vout'])))
        for i in range(4):
            tx.vout.append(CTxOut(amount[i], get_mast_spk(mast1)))
        tx.vout.append(CTxOut(amount[4], get_mast_spk(mast2)))
        tx.vout.append(CTxOut(amount[5], get_mast_spk(mast2)))
        signresults = self.nodes[0].signrawtransaction(bytes_to_hex_str(tx.serialize_without_witness()))['hex']
        tx.deserialize(BytesIO(hex_str_to_bytes(signresults)))
        txid = self.tx_submit(0, tx)
        self.mine_and_clear_mempool(0)

        self.tx = CTransaction()
        self.fee = 0
        for i in range(6):
            self.tx.vin.append(CTxIn(COutPoint(txid, i)))
            self.tx.wit.vtxinwit.append(CTxInWitness())
            self.fee += amount[i]
        pay = 540 * 1000 * 1000
        for i in range(10):
            self.fee -= pay
            self.tx.vout.append(CTxOut(pay, CScript([chr(i).encode('latin-1')])))
            pay -= 10 * 1000 * 1000
        for i in range(250):
            self.tx.vout.append(CTxOut(0, CScript([chr(i).encode('latin-1')])))

        signone1 = sign_mast(key1, mast1, 0, self.tx, 0, 0, SIGHASHV2_NONE, amount[0], self.fee)
        signone2 = sign_mast(key2, mast1, 0, self.tx, 0, 0, SIGHASHV2_NONE, amount[0], self.fee)
        self.tx.wit.vtxinwit[0].scriptWitness.stack = [signone1] + get_mast_stack(mast1, 0)
        self.tx.wit.vtxinwit[1].scriptWitness.stack = [b'\x01'] + get_mast_stack(mast1, 1)
        self.tx.wit.vtxinwit[2].scriptWitness.stack = [signone2, signone1] + get_mast_stack(mast1, 2)
        # The witness of 3rd input is not changed throughout the test, showing that SIGHASHV2_NONE commit to nothing
        self.tx.wit.vtxinwit[3].scriptWitness.stack = [signone1] + get_mast_stack(mast1, 0)
        self.tx.wit.vtxinwit[4].scriptWitness.stack = [signone1] + get_mast_stack(mast2, 1)
        self.tx.wit.vtxinwit[5].scriptWitness.stack = [b'\x01'] + get_mast_stack(mast2, 2)
        self.tx_submit(0, self.tx)

        print ("Testing SIGHASHV2_VERSION")
        # Replace a signature with SIGHASHV2_VERSION with a wrong nVersion should fail
        self.rbf()
        sig = sign_mast(key1, mast1, 0, self.tx, 0, 0, SIGHASHV2_VERSION, amount[0], self.fee)
        self.tx.nVersion += 1
        self.tx.wit.vtxinwit[0].scriptWitness.stack = [sig] + get_mast_stack(mast1, 0)
        self.tx_submit(0, self.tx, CHECKSIGFAIL)
        # Revert nVersion should pass
        self.tx.nVersion -= 1
        self.tx_submit(0, self.tx)

        print ("Testing SIGHASHV2_KEYSCRIPTHASH")
        self.rbf()
        sig1 = sign_mast(key1, mast1, 0, self.tx, 0, 0, SIGHASHV2_KEYSCRIPTHASH, amount[0], self.fee)
        sig2 = sign_mast(key1, mast1, 2, self.tx, 0, 0, SIGHASHV2_KEYSCRIPTHASH, amount[0], self.fee)
        self.tx.wit.vtxinwit[0].scriptWitness.stack = [sig1] + get_mast_stack(mast1, 0)
        self.tx.wit.vtxinwit[2].scriptWitness.stack = [signone2, sig1] + get_mast_stack(mast1, 2)
        self.tx_submit(0, self.tx, CHECKSIGFAIL)
        self.tx.wit.vtxinwit[0].scriptWitness.stack = [sig2] + get_mast_stack(mast1, 0)
        self.tx_submit(0, self.tx, CHECKSIGFAIL)
        self.tx.wit.vtxinwit[2].scriptWitness.stack = [signone2, sig2] + get_mast_stack(mast1, 2)
        self.tx_submit(0, self.tx, CHECKSIGFAIL)
        self.tx.wit.vtxinwit[0].scriptWitness.stack = [sig1] + get_mast_stack(mast1, 0)
        self.tx_submit(0, self.tx)
        self.rbf()
        self.tx.wit.vtxinwit[4].scriptWitness.stack = [sig2] + get_mast_stack(mast2, 1)
        self.tx_submit(0, self.tx, CHECKSIGFAIL)
        self.tx.wit.vtxinwit[4].scriptWitness.stack = [sig1] + get_mast_stack(mast2, 1)
        self.tx_submit(0, self.tx)
        self.rbf()
        self.tx.wit.vtxinwit[1].scriptWitness.stack = [sig1] + get_mast_stack(mast1, 0)
        self.tx_submit(0, self.tx)

        print ("Testing SIGHASHV2_FEE")
        self.rbf()
        sig = sign_mast(key1, mast1, 0, self.tx, 0, 0, SIGHASHV2_FEE, amount[0], self.fee)
        self.tx.vout[3].nValue += 1 # Change the value of only one vout should fail
        self.tx.wit.vtxinwit[0].scriptWitness.stack = [sig] + get_mast_stack(mast1, 0)
        self.tx_submit(0, self.tx, CHECKSIGFAIL)
        self.tx.vout[4].nValue -= 1 # Revert to the original fee by changing another vout should pass
        self.tx_submit(0, self.tx)

        print ("Testing SIGHASHV2_LOCKTIME")
        self.rbf()
        sig = sign_mast(key1, mast1, 0, self.tx, 0, 0, SIGHASHV2_LOCKTIME, amount[0], self.fee)
        self.tx.nLockTime += 1
        self.tx.wit.vtxinwit[0].scriptWitness.stack = [sig] + get_mast_stack(mast1, 0)
        self.tx_submit(0, self.tx, CHECKSIGFAIL)
        self.tx.nLockTime -= 1
        self.tx_submit(0, self.tx)

        print ("Testing SIGHASHV2_PROGRAM")
        self.rbf()
        sig1 = sign_mast(key1, mast1, 0, self.tx, 0, 0, SIGHASHV2_PROGRAM, amount[0], self.fee)
        sig2 = sign_mast(key1, mast2, 1, self.tx, 0, 0, SIGHASHV2_PROGRAM, amount[0], self.fee)
        self.tx.wit.vtxinwit[0].scriptWitness.stack = [sig1] + get_mast_stack(mast1, 0)
        self.tx.wit.vtxinwit[4].scriptWitness.stack = [sig1] + get_mast_stack(mast2, 1)
        self.tx_submit(0, self.tx, CHECKSIGFAIL)
        self.tx.wit.vtxinwit[2].scriptWitness.stack = [signone2, sig1] + get_mast_stack(mast1, 2)
        self.tx_submit(0, self.tx, CHECKSIGFAIL)
        self.tx.wit.vtxinwit[4].scriptWitness.stack = [sig2] + get_mast_stack(mast2, 1)
        self.tx_submit(0, self.tx)

        print ("Testing SIGHASHV2_THISSEQUENCE")
        self.rbf()
        sig = sign_mast(key1, mast1, 0, self.tx, 0, 0, SIGHASHV2_THISSEQUENCE, amount[0], self.fee)
        self.tx.vin[0].nSequence += 1
        self.tx.wit.vtxinwit[0].scriptWitness.stack = [sig] + get_mast_stack(mast1, 0)
        self.tx_submit(0, self.tx, CHECKSIGFAIL)
        self.tx.vin[0].nSequence -= 1
        self.tx_submit(0, self.tx)
        self.rbf()
        self.tx.vin[3].nSequence += 1
        self.tx_submit(0, self.tx)

        print ("Testing SIGHASHV2_AMOUNT")
        self.rbf()
        sig1 = sign_mast(key1, mast1, 0, self.tx, 0, 0, SIGHASHV2_AMOUNT, amount[0], self.fee)
        sig2 = sign_mast(key1, mast1, 0, self.tx, 0, 0, SIGHASHV2_AMOUNT, amount[3], self.fee)
        self.tx.wit.vtxinwit[0].scriptWitness.stack = [sig2] + get_mast_stack(mast1, 0)
        self.tx_submit(0, self.tx, CHECKSIGFAIL)
        self.tx.wit.vtxinwit[0].scriptWitness.stack = [sig1] + get_mast_stack(mast1, 0)
        self.tx_submit(0, self.tx)
        self.rbf()
        self.tx.wit.vtxinwit[1].scriptWitness.stack = [sig1] + get_mast_stack(mast1, 0)
        self.tx_submit(0, self.tx)
        self.rbf()
        self.tx.wit.vtxinwit[5].scriptWitness.stack = [sig1] + get_mast_stack(mast2, 1)
        self.tx_submit(0, self.tx)

        print ("Testing SIGHASHV2_THISINPUT")
        self.rbf()
        sig1 = sign_mast(key1, mast1, 0, self.tx, 0, 0, SIGHASHV2_THISINPUT, amount[0], self.fee) # Correct for input 0
        sig2 = sign_mast(key1, mast1, 0, self.tx, 1, 0, SIGHASHV2_THISINPUT, amount[0], self.fee) # Correct for input 1
        sig3 = sign_mast(key1, mast1, 0, self.tx, 0, 0, SIGHASHV2_THISINPUT, 0, self.fee) # Incorrect amount for input 0
        sig4 = sign_mast(key1, mast2, 1, self.tx, 0, 0, SIGHASHV2_THISINPUT, amount[0], self.fee) # Incorrect program for input 0

        self.tx.wit.vtxinwit[0].scriptWitness.stack = [sig2] + get_mast_stack(mast1, 0)
        self.tx_submit(0, self.tx, CHECKSIGFAIL)
        self.tx.wit.vtxinwit[0].scriptWitness.stack = [sig3] + get_mast_stack(mast1, 0)
        self.tx_submit(0, self.tx, CHECKSIGFAIL)
        self.tx.wit.vtxinwit[0].scriptWitness.stack = [sig4] + get_mast_stack(mast1, 0)
        self.tx_submit(0, self.tx, CHECKSIGFAIL)
        self.tx.wit.vtxinwit[0].scriptWitness.stack = [sig1] + get_mast_stack(mast1, 0)
        self.tx_submit(0, self.tx)
        self.rbf()
        self.tx.wit.vtxinwit[1].scriptWitness.stack = [sig2] + get_mast_stack(mast1, 0)
        self.tx_submit(0, self.tx)
        self.rbf()
        self.tx.vin[0].nSequence += 1
        self.tx.vin[3].nSequence += 1
        self.tx_submit(0, self.tx) # SIGHASHV2_THISINPUT does not cover nSequence

        # SIGHASHV2_THISINPUT does not cover other inputs
        self.rbf()
        self.tx.vin[4], self.tx.vin[5] = self.tx.vin[5], self.tx.vin[4]
        self.tx.wit.vtxinwit[4], self.tx.wit.vtxinwit[5] = self.tx.wit.vtxinwit[5], self.tx.wit.vtxinwit[4]
        self.tx_submit(0, self.tx)
        self.tx.vin[4], self.tx.vin[5] = self.tx.vin[5], self.tx.vin[4]
        self.tx.wit.vtxinwit[4], self.tx.wit.vtxinwit[5] = self.tx.wit.vtxinwit[5], self.tx.wit.vtxinwit[4]

        print ("Testing SIGHASHV2_ALLINPUT")
        self.rbf()
        sig1 = sign_mast(key1, mast1, 0, self.tx, 0, 0, SIGHASHV2_ALLINPUT, amount[0], self.fee) # Correct for input 0
        sig2 = sign_mast(key1, mast1, 0, self.tx, 1, 0, SIGHASHV2_ALLINPUT, amount[0], self.fee) # Correct for input 1
        sig3 = sign_mast(key1, mast1, 0, self.tx, 0, 0, SIGHASHV2_ALLINPUT, 0, self.fee) # Incorrect amount for input 0
        sig4 = sign_mast(key1, mast2, 1, self.tx, 0, 0, SIGHASHV2_ALLINPUT, amount[0], self.fee) # Incorrect program for input 0

        self.tx.wit.vtxinwit[0].scriptWitness.stack = [sig2] + get_mast_stack(mast1, 0)
        self.tx_submit(0, self.tx, CHECKSIGFAIL)
        self.tx.wit.vtxinwit[0].scriptWitness.stack = [sig3] + get_mast_stack(mast1, 0)
        self.tx_submit(0, self.tx, CHECKSIGFAIL)
        self.tx.wit.vtxinwit[0].scriptWitness.stack = [sig4] + get_mast_stack(mast1, 0)
        self.tx_submit(0, self.tx, CHECKSIGFAIL)
        self.tx.wit.vtxinwit[0].scriptWitness.stack = [sig1] + get_mast_stack(mast1, 0)
        self.tx_submit(0, self.tx)
        self.rbf()
        self.tx.wit.vtxinwit[1].scriptWitness.stack = [sig2] + get_mast_stack(mast1, 0)
        self.tx_submit(0, self.tx)

        # SIGHASHV2_ALLINPUT covers other inputs
        self.rbf()
        self.tx.vin[4].prevout, self.tx.vin[5].prevout = self.tx.vin[5].prevout, self.tx.vin[4].prevout
        self.tx.wit.vtxinwit[4], self.tx.wit.vtxinwit[5] = self.tx.wit.vtxinwit[5], self.tx.wit.vtxinwit[4]
        self.tx_submit(0, self.tx, CHECKSIGFAIL)
        self.tx.vin[4].prevout, self.tx.vin[5].prevout = self.tx.vin[5].prevout, self.tx.vin[4].prevout
        self.tx.wit.vtxinwit[4], self.tx.wit.vtxinwit[5] = self.tx.wit.vtxinwit[5], self.tx.wit.vtxinwit[4]
        self.tx.vin[0].nSequence += 1
        self.tx.vin[3].nSequence += 1
        self.tx_submit(0, self.tx) # SIGHASHV2_THISINPUT does not cover nSequence

        print ("Testing SIGHASHV2_ALLINPUT_ALLSEQUENCE")
        self.rbf()
        sig1 = sign_mast(key1, mast1, 0, self.tx, 0, 0, SIGHASHV2_ALLINPUT_ALLSEQUENCE, amount[0], self.fee) # Correct for input 0
        sig2 = sign_mast(key1, mast1, 0, self.tx, 1, 0, SIGHASHV2_ALLINPUT_ALLSEQUENCE, amount[0], self.fee) # Correct for input 1
        sig3 = sign_mast(key1, mast1, 0, self.tx, 0, 0, SIGHASHV2_ALLINPUT_ALLSEQUENCE, 0, self.fee) # Incorrect amount for input 0
        sig4 = sign_mast(key1, mast2, 1, self.tx, 0, 0, SIGHASHV2_ALLINPUT_ALLSEQUENCE, amount[0], self.fee) # Incorrect program for input 0

        self.tx.wit.vtxinwit[0].scriptWitness.stack = [sig2] + get_mast_stack(mast1, 0)
        self.tx_submit(0, self.tx, CHECKSIGFAIL)
        self.tx.wit.vtxinwit[0].scriptWitness.stack = [sig3] + get_mast_stack(mast1, 0)
        self.tx_submit(0, self.tx, CHECKSIGFAIL)
        self.tx.wit.vtxinwit[0].scriptWitness.stack = [sig4] + get_mast_stack(mast1, 0)
        self.tx_submit(0, self.tx, CHECKSIGFAIL)
        self.tx.wit.vtxinwit[0].scriptWitness.stack = [sig1] + get_mast_stack(mast1, 0)
        self.tx_submit(0, self.tx)
        self.rbf()
        self.tx.wit.vtxinwit[1].scriptWitness.stack = [sig2] + get_mast_stack(mast1, 0)
        self.tx_submit(0, self.tx)

        # SIGHASHV2_ALLINPUT_ALLSEQUENCE covers all inputs and all sequence
        self.rbf()
        self.tx.vin[4].prevout, self.tx.vin[5].prevout = self.tx.vin[5].prevout, self.tx.vin[4].prevout
        self.tx.wit.vtxinwit[4], self.tx.wit.vtxinwit[5] = self.tx.wit.vtxinwit[5], self.tx.wit.vtxinwit[4]
        self.tx_submit(0, self.tx, CHECKSIGFAIL)
        self.tx.vin[4].prevout, self.tx.vin[5].prevout = self.tx.vin[5].prevout, self.tx.vin[4].prevout
        self.tx.wit.vtxinwit[4], self.tx.wit.vtxinwit[5] = self.tx.wit.vtxinwit[5], self.tx.wit.vtxinwit[4]
        self.tx.vin[0].nSequence += 1
        self.tx_submit(0, self.tx, CHECKSIGFAIL)
        self.tx.vin[0].nSequence -= 1
        self.tx.vin[3].nSequence += 1
        self.tx_submit(0, self.tx, CHECKSIGFAIL)
        self.tx.vin[3].nSequence -= 1
        self.tx_submit(0, self.tx)

        print ("Testing SIGHASHV2_ALLOUTPUT")
        self.rbf()
        sig = sign_mast(key1, mast1, 0, self.tx, 0, 0, SIGHASHV2_ALLOUTPUT, amount[0], self.fee)
        self.tx.wit.vtxinwit[0].scriptWitness.stack = [sig] + get_mast_stack(mast1, 0)
        self.tx.vout[7], self.tx.vout[8] = self.tx.vout[8], self.tx.vout[7]
        self.tx_submit(0, self.tx, CHECKSIGFAIL)
        self.tx.vout[7], self.tx.vout[8] = self.tx.vout[8], self.tx.vout[7]
        self.tx_submit(0, self.tx)

        print ("Testing SIGHASHV2_SINGLEOUTPUT")
        self.rbf()
        sig = sign_mast(key1, mast1, 0, self.tx, 0, 0, SIGHASHV2_SINGLEOUTPUT, amount[0], self.fee)
        self.tx.wit.vtxinwit[0].scriptWitness.stack = [sig] + get_mast_stack(mast1, 0)
        self.tx.vout[0], self.tx.vout[1] = self.tx.vout[1], self.tx.vout[0]
        self.tx_submit(0, self.tx, CHECKSIGFAIL)
        self.tx.vout[0], self.tx.vout[1] = self.tx.vout[1], self.tx.vout[0]
        self.tx_submit(0, self.tx)
        self.rbf()
        sig += b'\x01'
        self.tx.wit.vtxinwit[0].scriptWitness.stack = [sig] + get_mast_stack(mast1, 0)
        self.tx_submit(0, self.tx, CHECKSIGFAIL)
        self.tx.vout[0], self.tx.vout[1] = self.tx.vout[1], self.tx.vout[0]
        self.tx_submit(0, self.tx)
        self.rbf()
        sig += b'\x01'
        self.tx.wit.vtxinwit[0].scriptWitness.stack = [sig] + get_mast_stack(mast1, 0)
        self.tx_submit(0, self.tx, CHECKSIGFAIL)
        self.tx.vout[257], self.tx.vout[1] = self.tx.vout[1], self.tx.vout[257]
        self.tx_submit(0, self.tx)

        print ("Testing SIGHASHV2_DUALOUTPUT")
        self.rbf()
        sig = sign_mast(key1, mast1, 0, self.tx, 1, 0, SIGHASHV2_DUALOUTPUT, amount[0], self.fee)
        self.tx.wit.vtxinwit[1].scriptWitness.stack = [signone1] + get_mast_stack(mast1, 0)
        self.tx.wit.vtxinwit[1].scriptWitness.stack = [sig] + get_mast_stack(mast1, 0)
        self.tx.vout[0], self.tx.vout[1] = self.tx.vout[1], self.tx.vout[0]
        self.tx_submit(0, self.tx, CHECKSIGFAIL)
        self.tx.vout[0], self.tx.vout[1] = self.tx.vout[1], self.tx.vout[0]
        self.tx.vout[2], self.tx.vout[1] = self.tx.vout[1], self.tx.vout[2]
        self.tx_submit(0, self.tx, CHECKSIGFAIL)
        self.tx.vout[2], self.tx.vout[1] = self.tx.vout[1], self.tx.vout[2]
        self.tx.vout[0], self.tx.vout[2] = self.tx.vout[2], self.tx.vout[0]
        self.tx_submit(0, self.tx, CHECKSIGFAIL)
        self.tx.vout[0], self.tx.vout[2] = self.tx.vout[2], self.tx.vout[0]
        self.tx_submit(0, self.tx)
        self.rbf()
        sig += b'\x02'
        self.tx.wit.vtxinwit[1].scriptWitness.stack = [sig] + get_mast_stack(mast1, 0)
        self.tx_submit(0, self.tx, CHECKSIGFAIL)
        self.tx.vout[0], self.tx.vout[2] = self.tx.vout[2], self.tx.vout[0]
        self.tx_submit(0, self.tx)
        self.rbf()
        sig += b'\x01'
        self.tx.wit.vtxinwit[1].scriptWitness.stack = [sig] + get_mast_stack(mast1, 0)
        self.tx_submit(0, self.tx, CHECKSIGFAIL)
        self.tx.vout[258], self.tx.vout[2] = self.tx.vout[2], self.tx.vout[258]
        self.tx_submit(0, self.tx)

        print ("Testing sigScriptCode committment")
        self.rbf()
        sigcode1 = [CScript([OP_14, OP_EQUALVERIFY]),CScript(),CScript([OP_15, OP_EQUALVERIFY]),CScript(),CScript([OP_16, OP_EQUALVERIFY]),CScript()]
        self.tx.wit.vtxinwit[0].scriptWitness.stack = [signone1, b'\x10', b'\x0f', b'\x0e'] + get_mast_stack(mast1, 0, sigcode1)
        self.tx_submit(0, self.tx, SIGCODEFAIL)
        sig = sign_mast(key1, mast1, 0, self.tx, 1, 0, 0x0100, amount[0], self.fee, sigcode1)
        self.tx.wit.vtxinwit[0].scriptWitness.stack = [sig, b'\x10', b'\x0f', b'\x0e'] + get_mast_stack(mast1, 0, sigcode1)
        self.tx_submit(0, self.tx, SIGCODEFAIL)
        sig = sign_mast(key1, mast1, 0, self.tx, 1, 0, 0x0500, amount[0], self.fee, sigcode1)
        self.tx.wit.vtxinwit[0].scriptWitness.stack = [sig, b'\x10', b'\x0f', b'\x0e'] + get_mast_stack(mast1, 0, sigcode1)
        self.tx_submit(0, self.tx, SIGCODEFAIL)
        sig = sign_mast(key1, mast1, 0, self.tx, 1, 0, 0x1500, amount[0], self.fee, sigcode1)
        sigcode2 = [CScript([OP_15, OP_EQUALVERIFY]),CScript(),CScript([OP_15, OP_EQUALVERIFY]),CScript(),CScript([OP_16, OP_EQUALVERIFY]),CScript()]
        self.tx.wit.vtxinwit[0].scriptWitness.stack = [sig, b'\x10', b'\x0f', b'\x0f'] + get_mast_stack(mast1, 0, sigcode2)
        self.tx_submit(0, self.tx, CHECKSIGFAIL)
        self.tx.wit.vtxinwit[0].scriptWitness.stack = [sig, b'\x10', b'\x0f', b'\x0e'] + get_mast_stack(mast1, 0, sigcode1)
        self.tx_submit(0, self.tx)
        self.rbf()
        sig1 = sign_mast(key1, mast1, 0, self.tx, 1, 0, 0x3f00, amount[0], self.fee, sigcode1)
        sigcode3 = [CScript([OP_14, OP_EQUALVERIFY]),CScript([OP_13, OP_EQUALVERIFY]),CScript([OP_15, OP_EQUALVERIFY]),CScript(),CScript([OP_16, OP_EQUALVERIFY]),CScript()]
        self.tx.wit.vtxinwit[0].scriptWitness.stack = [sig1, b'\x10', b'\x0f', b'\x0d', b'\x0e'] + get_mast_stack(mast1, 0, sigcode3)
        self.tx_submit(0, self.tx, CHECKSIGFAIL)
        self.tx.wit.vtxinwit[0].scriptWitness.stack = [sig1, b'\x10', b'\x0f', b'\x0e'] + get_mast_stack(mast1, 0, sigcode1)
        self.tx_submit(0, self.tx)

        self.rbf()
        sig2 = sign_mast(key2, mast1, 2, self.tx, 1, 0, 0x1700, amount[0], self.fee, sigcode3)
        self.tx.wit.vtxinwit[0].scriptWitness.stack = [sig2, sig1, b'\x10', b'\x0f', b'\x0d', b'\x0e'] + get_mast_stack(mast1, 2, sigcode3)
        self.tx_submit(0, self.tx, CHECKSIGFAIL)
        self.tx.wit.vtxinwit[0].scriptWitness.stack = [sig2, sig, b'\x10', b'\x0f', b'\x0d', b'\x0e'] + get_mast_stack(mast1, 2, sigcode3)
        self.tx_submit(0, self.tx)

        self.rbf()
        self.tx.wit.vtxinwit[0].scriptWitness.stack = [b'\x03', sig1, sig2, b'\x10', b'\x0f', b'\x0d', b'\x0e'] + get_mast_stack(mast1, 3, sigcode3)
        self.tx_submit(0, self.tx, NULLFAIL)
        self.tx.wit.vtxinwit[0].scriptWitness.stack = [b'\x03', sig, sig2, b'\x10', b'\x0f', b'\x0d', b'\x0e'] + get_mast_stack(mast1, 3, sigcode3)
        self.tx_submit(0, self.tx)

        self.rbf(5 * 1000 * 1000)
        sigcode4 = [CScript([pubkey1, OP_CHECKSIGVERIFY])] * 6
        for i in range(0, 0x3f00, 0x100):
            sig = sign_mast(key1, mast1, 0, self.tx, 1, 0, i, amount[0], self.fee, sigcode4)
            self.tx.wit.vtxinwit[0].scriptWitness.stack = [sig, signone1, signone1, signone1, signone1, signone1, signone1] + get_mast_stack(mast1, 0, sigcode4)
            self.tx_submit(0, self.tx, SIGCODEFAIL)
        sig = sign_mast(key1, mast1, 0, self.tx, 1, 0, 0x3f00, amount[0], self.fee, sigcode4)
        self.tx.wit.vtxinwit[0].scriptWitness.stack = [sig, signone1, signone1, signone1, signone1, signone1, signone1] + get_mast_stack(mast1, 0, sigcode4)
        self.tx_submit(0, self.tx)

        self.rbf()
        sig1 = sign_mast(key1, mast1, 0, self.tx, 1, 0, 0x2000, amount[0], self.fee, sigcode4)
        sig2 = sign_mast(key1, mast1, 0, self.tx, 1, 0, 0x1f00, amount[0], self.fee, sigcode4)
        self.tx.wit.vtxinwit[0].scriptWitness.stack = [sig1, signone1, signone1, signone1, signone1, signone1, sig2] + get_mast_stack(mast1, 0, sigcode4)
        self.tx_submit(0, self.tx, SIGCODEFAIL)
        self.tx.wit.vtxinwit[0].scriptWitness.stack = [sig1, signone1, signone1, signone1, signone1, sig2, signone1] + get_mast_stack(mast1, 0, sigcode4)
        self.tx_submit(0, self.tx, SIGCODEFAIL)
        self.tx.wit.vtxinwit[0].scriptWitness.stack = [sig1, signone1, signone1, signone1, sig2, signone1, signone1] + get_mast_stack(mast1, 0, sigcode4)
        self.tx_submit(0, self.tx, SIGCODEFAIL)
        self.tx.wit.vtxinwit[0].scriptWitness.stack = [sig1, signone1, signone1, sig2, signone1, signone1, signone1] + get_mast_stack(mast1, 0, sigcode4)
        self.tx_submit(0, self.tx, SIGCODEFAIL)
        self.tx.wit.vtxinwit[0].scriptWitness.stack = [sig1, signone1, sig2, signone1, signone1, signone1, signone1] + get_mast_stack(mast1, 0, sigcode4)
        self.tx_submit(0, self.tx, SIGCODEFAIL)
        self.tx.wit.vtxinwit[0].scriptWitness.stack = [sig1, sig2, signone1, signone1, signone1, signone1, signone1] + get_mast_stack(mast1, 0, sigcode4)
        self.tx_submit(0, self.tx)

        self.rbf()
        sig1 = sign_mast(key1, mast1, 0, self.tx, 1, 0, 0x2000, amount[0], self.fee, sigcode4)
        sig2 = sign_mast(key1, mast1, 0, self.tx, 1, 0, 0x1000, amount[0], self.fee, sigcode4)
        sig3 = sign_mast(key1, mast1, 0, self.tx, 1, 0, 0x0800, amount[0], self.fee, sigcode4)
        sig4 = sign_mast(key1, mast1, 0, self.tx, 1, 0, 0x0400, amount[0], self.fee, sigcode4)
        sig5 = sign_mast(key1, mast1, 0, self.tx, 1, 0, 0x0200, amount[0], self.fee, sigcode4)
        sig6 = sign_mast(key1, mast1, 0, self.tx, 1, 0, 0x0100, amount[0], self.fee, sigcode4)
        self.tx.wit.vtxinwit[0].scriptWitness.stack = [sig1, sig1, sig2, sig3, sig4, sig5, sig6] + get_mast_stack(mast1, 0, sigcode4)
        self.tx_submit(0, self.tx, SIGCODEFAIL)
        self.tx.wit.vtxinwit[0].scriptWitness.stack = [sig1, sig2, sig3, sig4, sig5, sig6, signone1] + get_mast_stack(mast1, 0, sigcode4)
        self.tx_submit(0, self.tx)

        self.rbf()
        sig1 = sign_mast(key1, mast1, 2, self.tx, 1, 0, 0x2000, amount[0], self.fee, sigcode4)
        sig2 = sign_mast(key2, mast1, 2, self.tx, 1, 0, 0x1000, amount[0], self.fee, sigcode4)
        sig3 = sign_mast(key1, mast1, 2, self.tx, 1, 0, 0x0c00, amount[0], self.fee, sigcode4)
        sig4 = sign_mast(key1, mast1, 2, self.tx, 1, 0, 0x0300, amount[0], self.fee, sigcode4)
        self.tx.wit.vtxinwit[0].scriptWitness.stack = [sig2, sig1, sig3, sig4, signone1, signone1, signone1, signone1] + get_mast_stack(mast1, 2, sigcode4)
        self.tx_submit(0, self.tx)

        self.rbf()
        self.tx.wit.vtxinwit[0].scriptWitness.stack = [b'\x03', sig2, sig1, sig3, sig4, signone1, signone1, signone1, signone1] + get_mast_stack(mast1, 3, sigcode4)
        self.tx_submit(0, self.tx, NULLFAIL)
        self.tx.wit.vtxinwit[0].scriptWitness.stack = [b'\x01', sig2, sig1, sig3, sig4, signone1, signone1, signone1, signone1] + get_mast_stack(mast1, 3, sigcode4)
        self.tx_submit(0, self.tx, NULLFAIL)
        self.tx.wit.vtxinwit[0].scriptWitness.stack = [b'\x02', sig2, sig1, sig3, sig4, signone1, signone1, signone1, signone1] + get_mast_stack(mast1, 3, sigcode4)
        self.tx_submit(0, self.tx, FLAGSFAIL)
        self.tx.wit.vtxinwit[0].scriptWitness.stack = [b'\x06', sig2, sig1, sig3, sig4, signone1, signone1, signone1, signone1] + get_mast_stack(mast1, 3, sigcode4)
        self.tx_submit(0, self.tx, FLAGSFAIL)
        self.tx.wit.vtxinwit[0].scriptWitness.stack = [b'\x01', sig1, sig2, sig3, sig4, signone1, signone1, signone1, signone1] + get_mast_stack(mast1, 3, sigcode4)
        self.tx_submit(0, self.tx, FLAGSFAIL)
        self.tx.wit.vtxinwit[0].scriptWitness.stack = [b'\x05', sig1, sig2, sig3, sig4, signone1, signone1, signone1, signone1] + get_mast_stack(mast1, 3, sigcode4)
        self.tx_submit(0, self.tx, FLAGSFAIL)
        self.tx.wit.vtxinwit[0].scriptWitness.stack = [b'\x07', sig1, sig2, sig3, sig4, signone1, signone1, signone1, signone1] + get_mast_stack(mast1, 3, sigcode4)
        self.tx_submit(0, self.tx, FLAGSFAIL)
        self.tx.wit.vtxinwit[0].scriptWitness.stack = [b'\x0c', sig1, sig2, sig3, sig4, signone1, signone1, signone1, signone1] + get_mast_stack(mast1, 3, sigcode4)
        self.tx_submit(0, self.tx, FLAGSFAIL)
        self.tx.wit.vtxinwit[0].scriptWitness.stack = [b'\x03\x00', sig1, sig2, sig3, sig4, signone1, signone1, signone1, signone1] + get_mast_stack(mast1, 3, sigcode4)
        self.tx_submit(0, self.tx, "64: non-mandatory-script-verify-flag (unknown error)")
        self.tx.wit.vtxinwit[0].scriptWitness.stack = [b'\x03', sig1, signone2, sig3, sig4, signone1, signone1, signone1, signone1] + get_mast_stack(mast1, 3, sigcode4)
        self.tx_submit(0, self.tx, SIGCODEFAIL)
        self.tx.wit.vtxinwit[0].scriptWitness.stack = [b'\x03', signone1, sig2, sig3, sig4, signone1, signone1, signone1, signone1] + get_mast_stack(mast1, 3, sigcode4)
        self.tx_submit(0, self.tx, SIGCODEFAIL)
        self.tx.wit.vtxinwit[0].scriptWitness.stack = [b'\x03', sig1, sig2, sig3, sig4, signone1, signone1, signone1, signone1] + get_mast_stack(mast1, 3, sigcode4)
        self.tx_submit(0, self.tx)

        self.rbf()
        sig1 = sign_mast(key1, mast1, 2, self.tx, 1, 0, 0x3000, amount[0], self.fee, sigcode4)
        sig2 = sign_mast(key2, mast1, 2, self.tx, 1, 0, 0x3000, amount[0], self.fee, sigcode4)
        self.tx.wit.vtxinwit[0].scriptWitness.stack = [b'\x01', sig1, sig3, sig4, signone1, signone1, signone1, signone1] + get_mast_stack(mast1, 4, sigcode4)
        self.tx_submit(0, self.tx, NULLFAIL)
        self.tx.wit.vtxinwit[0].scriptWitness.stack = [b'\x02', sig1, sig3, sig4, signone1, signone1, signone1, signone1] + get_mast_stack(mast1, 4, sigcode4)
        self.tx_submit(0, self.tx)
        self.rbf()
        self.tx.wit.vtxinwit[0].scriptWitness.stack = [b'\x02', sig2, sig3, sig4, signone1, signone1, signone1, signone1] + get_mast_stack(mast1, 4, sigcode4)
        self.tx_submit(0, self.tx, NULLFAIL)
        self.tx.wit.vtxinwit[0].scriptWitness.stack = [b'\x01', sig2, sig3, sig4, signone1, signone1, signone1, signone1] + get_mast_stack(mast1, 4, sigcode4)
        self.tx_submit(0, self.tx)

        self.mine_and_clear_mempool(0)

    def rbf(self, fee = 3 * 1000 * 1000):
        self.fee += fee
        self.tx.vout[9].nValue -= fee

    def tx_submit(self, node, tx, msg = ""):
        tx.rehash()
        try:
            self.nodes[node].sendrawtransaction(bytes_to_hex_str(tx.serialize_with_witness()), True)
        except JSONRPCException as exp:
            assert_equal(exp.error["message"], msg)
        else:
            assert_equal('', msg)
        return tx.sha256

if __name__ == '__main__':
    SegWitTest().main()