#!/usr/bin/env python3
# Copyright (c) 2017 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from test_framework.mininode import hex_str_to_bytes, bytes_to_hex_str, CTxIn, CTxInWitness
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import sync_blocks, JSONRPCException, assert_equal
from test_framework.script import *
from test_framework.key import CECKey, CPubKey
from math import log, ceil
from io import BytesIO


CHECKSIGFAIL = "64: non-mandatory-script-verify-flag (Signature must be zero for failed CHECK(MULTI)SIG operation)"
CHECKMULTISIGFAIL = "64: non-mandatory-script-verify-flag (Script failed an OP_CHECKMULTISIGVERIFY operation)"
NULLFAIL = "64: non-mandatory-script-verify-flag (Signature must be zero for failed CHECK(MULTI)SIG operation)"
FLAGSFAIL = "64: non-mandatory-script-verify-flag (Invalid signature flags for OP_CHECKMULTISIG(VERIFY))"
WITCODEFAIL = "64: non-mandatory-script-verify-flag (scriptWitCode not covered by signature)"
EQUALFAIL = "64: non-mandatory-script-verify-flag (Script failed an OP_EQUALVERIFY operation)"
NUMEQUALFAIL = "64: non-mandatory-script-verify-flag (Script failed an OP_NUMEQUALVERIFY operation)"
UNKNOWNWITNESS = "64: non-mandatory-script-verify-flag (Witness version reserved for soft-fork upgrades)"
INVALIDSTACK = "64: non-mandatory-script-verify-flag (Operation not valid with the current stack size)"
HASHTYPEFAIL = "64: non-mandatory-script-verify-flag (Signature hash type missing or not understood)"
EVALFALSE = "64: non-mandatory-script-verify-flag (Script evaluated without error but finished with a false/empty top stack element)"
CSVFAIL = "64: non-mandatory-script-verify-flag (Locktime requirement not satisfied)"
BIP68FAIL = "64: non-BIP68-final"

def find_unspent(node, min_value):
    for utxo in node.listunspent():
        if utxo['amount'] >= min_value:
            return utxo

def int_to_chr(int):
    assert(int >= 0 and int < 256)
    return chr(int).encode('latin-1')

def get_hash_list(script_version_pairs):
    depth = ceil(log(len(script_version_pairs), 2))
    assert (depth <= 32)
    hashlist = []
    for i in script_version_pairs:
        hashlist.append(sha256(int_to_chr(i[1]) + i[0]))
    for i in range(len(script_version_pairs), 2 ** depth):
        hashlist.append(int_to_chr(i % 256) * 32)
    return hashlist

def get_higher_hash(hash):
    for i in range(0, len(hash), 2):
        cat = hash[i] + hash[i+1]
        hash[i//2] = hash256(cat)
    return hash[:-len(hash)//2]

def get_ms_spk(script_version_pairs):
    hash = get_hash_list(script_version_pairs)
    while (len(hash) > 1):
        hash = get_higher_hash(hash)
    return CScript([OP_1, hash[0]])

def get_ms_stack(script_version_pairs, pos, scriptsigcode = []):
    hash = get_hash_list(script_version_pairs)
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
    assert (len(scriptsigcode) <= 5)
    for i in reversed(scriptsigcode):
        stack.append(i)
    if len(scriptsigcode):
        assert (len(scriptsigcode[len(scriptsigcode) - 1]))
        stack.append(int_to_chr(len(scriptsigcode)))
    else:
        stack.append(b'')
    if (pos > 0):
        stack.append(int_to_chr(pos))
    else:
        stack.append(b'')
    stack.append(path)
    stack.append(int_to_chr(script_version_pairs[pos][1]) + script_version_pairs[pos][0])
    return stack

def get_sighash(script, tx, nIn, hashtype, amount, fee, vscriptSigCode = [CScript()] * MAX_MSV0_SCRIPTSIGCODE):
    assert (len(vscriptSigCode) <= MAX_MSV0_SCRIPTSIGCODE)
    while (len(vscriptSigCode) < MAX_MSV0_SCRIPTSIGCODE):
        vscriptSigCode = vscriptSigCode + [CScript()]
    sighash = MSV0SignatureHash(script, vscriptSigCode, tx, nIn, hashtype, amount, fee)
    return sighash

def sign_msv0(key, script, tx, nIn, hashtype, amount, fee, vscriptSigCode = [CScript()] * MAX_MSV0_SCRIPTSIGCODE):
    assert (hashtype < 65536)
    sighash = get_sighash(script, tx, nIn, hashtype, amount, fee, vscriptSigCode)
    sig = key.sign(sighash, msv0 = True)
    if hashtype == 0:
        return sig
    sig += int_to_chr(hashtype & 0xff)
    if hashtype < 256:
        return sig
    sig += int_to_chr(hashtype >> 8)
    return sig

class VaultDemo(BitcoinTestFramework):

    def __init__(self):
        super().__init__()
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.extra_args = [["-acceptnonstdtxn=0", "-debug"], ["-acceptnonstdtxn=0", "-debug"]]

    def mine_and_clear_mempool(self, node, blocks = 1):
        self.nodes[node].generate(blocks)
        sync_blocks(self.nodes)
        assert_equal(len(self.nodes[node].getrawmempool()), 0)

    def run_test(self):
        key = []
        pubkey = []
        for i in range(4):
            key.append(CECKey())
            key[i].set_secretbytes(int_to_chr(i))
            key[i].set_compressed(True)
            pubkey.append(CPubKey(key[i].get_pubkey()))


        recoverhash = sha256(int_to_chr(0) + CScript([OP_2, pubkey[1], pubkey[0], OP_2, OP_CHECKMULTISIG]))

        vault = []
        vault.append([CScript([OP_2, pubkey[1], pubkey[0], OP_2, OP_CHECKMULTISIG]),0])
        vault.append([CScript([OP_1, pubkey[1], pubkey[0], OP_2, OP_CHECKMULTISIGVERIFY, b'\x51\x20', b'\x00\x60\xb2', OP_ROT, OP_CAT, OP_SHA256, recoverhash, OP_CAT, OP_HASH256, OP_CAT, OP_1NEGATE, OP_16, OP_PUSHTXDATA, OP_ROT, OP_EQUALVERIFY, OP_3, OP_PUSHTXDATA, OP_SUB, b'\x40\x42\x8f', OP_GREATERTHANOREQUAL]),0])



        self.mine_and_clear_mempool(0, 432) # block 432: activate segwit

        utxo = find_unspent(self.nodes[0], 50)
        tx = CTransaction()
        inputvalue = 4999 * 1000 * 1000
        outputvalue = 4998 * 1000 * 1000
        tx.vin.append(CTxIn(COutPoint(int('0x'+utxo['txid'],0), utxo['vout'])))
        tx.vout.append(CTxOut(inputvalue, get_ms_spk(vault)))
        signresults = self.nodes[0].signrawtransaction(bytes_to_hex_str(tx.serialize_without_witness()))['hex']
        tx.deserialize(BytesIO(hex_str_to_bytes(signresults)))
        txid = self.tx_submit(0, tx)
        self.mine_and_clear_mempool(0)
        tx = CTransaction()
        tx.vin.append(CTxIn(COutPoint(txid, 0)))
        tx.wit.vtxinwit.append(CTxInWitness())
        tx.vout.append(CTxOut(outputvalue, CScript([pubkey[2], OP_CHECKSIG])))
        sigall0 = sign_msv0(key[0], vault[0][0], tx, 0, SIGHASH_MSV0_ALL, inputvalue, inputvalue - outputvalue)
        sigall1 = sign_msv0(key[1], vault[0][0], tx, 0, SIGHASH_MSV0_ALL, inputvalue, inputvalue - outputvalue)

        tx.wit.vtxinwit[0].scriptWitness.stack = [b'\x03', sigall1, sigall0] + get_ms_stack(vault, 0)

        self.tx_submit(0, tx)
        self.mine_and_clear_mempool(0)


        utxo = find_unspent(self.nodes[0], 50)
        tx = CTransaction()
        inputvalue = 4999 * 1000 * 1000
        tx.vin.append(CTxIn(COutPoint(int('0x'+utxo['txid'],0), utxo['vout'])))
        tx.vout.append(CTxOut(inputvalue, get_ms_spk(vault)))
        signresults = self.nodes[0].signrawtransaction(bytes_to_hex_str(tx.serialize_without_witness()))['hex']
        tx.deserialize(BytesIO(hex_str_to_bytes(signresults)))
        txid = self.tx_submit(0, tx)
        self.mine_and_clear_mempool(0)

        outputvalue = 4998 * 1000 * 1000
        intermediate = []
        intermediate.append([CScript([pubkey[3], OP_CHECKSIG]),0])
        intermediate.append([CScript([OP_2, pubkey[1], pubkey[0], OP_2, OP_CHECKMULTISIG]),0])
        tx = CTransaction()
        tx.vin.append(CTxIn(COutPoint(txid, 0)))
        tx.wit.vtxinwit.append(CTxInWitness())
        tx.vout.append(CTxOut(outputvalue, get_ms_spk(intermediate)))
        sigall0 = sign_msv0(key[0], vault[1][0], tx, 0, SIGHASH_MSV0_ALL, inputvalue, inputvalue - outputvalue)
        tx.wit.vtxinwit[0].scriptWitness.stack = [CScript([pubkey[3], OP_CHECKSIG]), b'\x01', sigall0] + get_ms_stack(vault, 1)
        self.tx_submit(0, tx, EQUALFAIL)

        outputvalue = 4998 * 1000 * 1000 - 1
        intermediate[0] = [CScript([OP_16, OP_CHECKSEQUENCEVERIFY, pubkey[3], OP_CHECKSIG]),0]
        tx.vout[0] = CTxOut(outputvalue, get_ms_spk(intermediate))
        sigall0 = sign_msv0(key[0], vault[1][0], tx, 0, SIGHASH_MSV0_ALL, inputvalue, inputvalue - outputvalue)
        tx.wit.vtxinwit[0].scriptWitness.stack = [CScript([pubkey[3], OP_CHECKSIG]), b'\x01', sigall0] + get_ms_stack(vault, 1)
        self.tx_submit(0, tx, EVALFALSE)

        outputvalue = 4998 * 1000 * 1000
        tx.vout[0] = CTxOut(outputvalue, get_ms_spk(intermediate))
        sigall0 = sign_msv0(key[0], vault[1][0], tx, 0, SIGHASH_MSV0_ALL, inputvalue, inputvalue - outputvalue)
        tx.wit.vtxinwit[0].scriptWitness.stack = [CScript([pubkey[3], OP_CHECKSIG]), b'\x01', sigall0] + get_ms_stack(vault, 1)
        txid = self.tx_submit(0, tx)
        self.mine_and_clear_mempool(0)

        tx = CTransaction()
        tx.vin.append(CTxIn(COutPoint(txid, 0)))
        tx.wit.vtxinwit.append(CTxInWitness())
        inputvalue = outputvalue
        outputvalue -= 1000 * 1000
        tx.vout.append(CTxOut(outputvalue, CScript([pubkey[3], OP_CHECKSIG])))
        sigall0 = sign_msv0(key[0], intermediate[1][0], tx, 0, SIGHASH_MSV0_ALL, inputvalue, inputvalue - outputvalue)
        sigall1 = sign_msv0(key[1], intermediate[1][0], tx, 0, SIGHASH_MSV0_ALL, inputvalue, inputvalue - outputvalue)
        tx.wit.vtxinwit[0].scriptWitness.stack = [b'\x03', sigall1, sigall0] + get_ms_stack(intermediate, 1)
        self.tx_submit(0, tx)

        #########

        utxo = find_unspent(self.nodes[0], 50)
        tx = CTransaction()
        inputvalue = 4999 * 1000 * 1000
        tx.vin.append(CTxIn(COutPoint(int('0x'+utxo['txid'],0), utxo['vout'])))
        tx.vout.append(CTxOut(inputvalue, get_ms_spk(vault)))
        signresults = self.nodes[0].signrawtransaction(bytes_to_hex_str(tx.serialize_without_witness()))['hex']
        tx.deserialize(BytesIO(hex_str_to_bytes(signresults)))
        txid = self.tx_submit(0, tx)
        self.mine_and_clear_mempool(0)

        outputvalue = 4998 * 1000 * 1000
        tx = CTransaction()
        tx.vin.append(CTxIn(COutPoint(txid, 0)))
        tx.wit.vtxinwit.append(CTxInWitness())
        tx.vout.append(CTxOut(outputvalue, get_ms_spk(intermediate)))
        sigall0 = sign_msv0(key[0], vault[1][0], tx, 0, SIGHASH_MSV0_ALL, inputvalue, inputvalue - outputvalue)
        tx.wit.vtxinwit[0].scriptWitness.stack = [CScript([pubkey[3], OP_CHECKSIG]), b'\x01', sigall0] + get_ms_stack(vault, 1)
        txid = self.tx_submit(0, tx)
        self.mine_and_clear_mempool(0)

        tx = CTransaction()
        tx.vin.append(CTxIn(COutPoint(txid, 0)))
        tx.wit.vtxinwit.append(CTxInWitness())
        inputvalue = outputvalue
        outputvalue -= 1000 * 1000
        tx.vout.append(CTxOut(outputvalue, CScript([pubkey[2], OP_CHECKSIG])))
        sigall2 = sign_msv0(key[0], intermediate[0][0], tx, 0, SIGHASH_MSV0_ALL, inputvalue, inputvalue - outputvalue)
        tx.wit.vtxinwit[0].scriptWitness.stack = [sigall2] + get_ms_stack(intermediate, 0)
        self.tx_submit(0, tx, CSVFAIL)

        tx.vin[0].nSequence = 0
        tx.nVersion = 2
        sigall3 = sign_msv0(key[3], intermediate[0][0], tx, 0, SIGHASH_MSV0_ALL, inputvalue, inputvalue - outputvalue)
        tx.wit.vtxinwit[0].scriptWitness.stack = [sigall3] + get_ms_stack(intermediate, 0)
        self.tx_submit(0, tx, CSVFAIL)

        self.mine_and_clear_mempool(0, 14)
        tx.vin[0].nSequence = 16
        sigall3 = sign_msv0(key[3], intermediate[0][0], tx, 0, SIGHASH_MSV0_ALL, inputvalue, inputvalue - outputvalue)
        tx.wit.vtxinwit[0].scriptWitness.stack = [sigall3] + get_ms_stack(intermediate, 0)
        self.tx_submit(0, tx, BIP68FAIL)

        self.mine_and_clear_mempool(0)
        self.tx_submit(0, tx)
        self.mine_and_clear_mempool(0)

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
    VaultDemo().main()