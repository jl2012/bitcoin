#!/usr/bin/env python3
# Copyright (c) 2016 The Bitcoin Core developers
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
    # for i in hashlist:
    #     print (bytes_to_hex_str(i))
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
    # for i in stack:
    #     print (bytes_to_hex_str(i))
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

class MSV0Test(BitcoinTestFramework):

    def __init__(self):
        super().__init__()
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.extra_args = [["-blockversion=536870915", "-debug"], ["-blockversion=536870944", "-debug", "-acceptnonstdtxn=0"]]

    def mine_and_clear_mempool(self, node, blocks = 1):
        self.nodes[node].generate(blocks)
        sync_blocks(self.nodes)
        assert_equal(len(self.nodes[node].getrawmempool()), 0)

    def run_test(self):
        key = []
        pubkey = []
        for i in range(3):
            key.append(CECKey())
            key[i].set_secretbytes(int_to_chr(i))
            key[i].set_compressed(True)
            pubkey.append(CPubKey(key[i].get_pubkey()))

        ms = []
        # ms.append([hex_str_to_bytes("1e00112233445566778899aabbccddeeff00112233445566778899aabbccdd87"),0])
        # ms.append([hex_str_to_bytes("1e0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab87"),0])
        ms.append([CScript([pubkey[0], OP_CHECKSIG]),0])
        ms.append([CScript([pubkey[1], OP_CHECKSIG]),0])
        ms.append([CScript([pubkey[2], OP_CHECKSIG]),0])
        ms.append([CScript([pubkey[0], OP_CHECKSIG, OP_NOP]),0])
        ms.append([CScript([OP_2, pubkey[2], pubkey[1], pubkey[0], OP_3, OP_CHECKMULTISIG]),0])
        ms.append([CScript([pubkey[1], OP_CHECKSIGVERIFY, OP_CODESEPARATOR, pubkey[0], OP_CHECKSIG]),0])
        ms.append([CScript([OP_1, OP_EQUAL] + [OP_NOP] * 31),0])
        ms.append([CScript([pubkey[0], OP_CHECKSIG]),1])

        self.mine_and_clear_mempool(0, 432) # block 432: activate segwit
        utxo = find_unspent(self.nodes[0], 50)
        tx = CTransaction()
        tx.vin.append(CTxIn(COutPoint(int('0x'+utxo['txid'],0), utxo['vout'])))
        tx.vout.append(CTxOut(4990 * 1000 * 1000, get_ms_spk(ms)))
        signresults = self.nodes[0].signrawtransaction(bytes_to_hex_str(tx.serialize_without_witness()))['hex']
        tx.deserialize(BytesIO(hex_str_to_bytes(signresults)))
        txid = self.tx_submit(0, tx)
        self.tx_submit(1, tx, "64: scriptpubkey")
        self.mine_and_clear_mempool(0)

        tx = CTransaction()
        tx.vin.append(CTxIn(COutPoint(txid, 0)))
        tx.wit.vtxinwit.append(CTxInWitness())
        tx.vout.append(CTxOut(4980 * 1000 * 1000, CScript([OP_DUP, OP_HASH160, hash160(pubkey[0]), OP_EQUALVERIFY, OP_CHECKSIG])))
        tx.wit.vtxinwit[0].scriptWitness.stack = [b'\x01'] + get_ms_stack(ms, 6)

        self.mine_and_clear_mempool(1, 285) # Last block without MAST
        self.tx_submit(0, tx, UNKNOWNWITNESS)
        self.tx_submit(1, tx, UNKNOWNWITNESS)

        self.mine_and_clear_mempool(0) # First block with MAST
        # self.tx_submit(0, tx)
        self.tx_submit(1, tx)

        amount = []
        for i in range(12):
            amount.append((4980 * 1000 * 1000 // 12) - (i * 1000 * 1000))

        utxo = find_unspent(self.nodes[0], 50)
        tx = CTransaction()
        tx.vin.append(CTxIn(COutPoint(int('0x'+utxo['txid'],0), utxo['vout'])))
        for i in range(3):
            tx.vout.append(CTxOut(amount[4 * i], get_ms_spk(ms)))
            tx.vout.append(CTxOut(amount[4 * i + 1], CScript([OP_HASH160, hash160(get_ms_spk(ms)), OP_EQUAL])))
            # print(bytes_to_hex_str(tx.vout[4 * i + 1].scriptPubKey))
            tx.vout.append(CTxOut(amount[4 * i + 2], CScript([OP_1, pubkey[i]])))
            tx.vout.append(CTxOut(amount[4 * i + 3], CScript([OP_HASH160, hash160(CScript([OP_1, pubkey[i]])), OP_EQUAL])))

    # tx.vout.append(CTxOut(amount[9], CScript([OP_1, pubkey[2]])))
        # print(bytes_to_hex_str(tx.vout[9].scriptPubKey))
        signresults = self.nodes[0].signrawtransaction(bytes_to_hex_str(tx.serialize_without_witness()))['hex']
        tx.deserialize(BytesIO(hex_str_to_bytes(signresults)))
        txid = self.tx_submit(0, tx)
        txhashrev = hex_str_to_bytes(tx.hash)[::-1]  # get the reversed txid
        self.mine_and_clear_mempool(0)

        self.tx = CTransaction()
        self.fee = 0
        for i in range(12):
            self.tx.vin.append(CTxIn(COutPoint(txid, i)))
            self.tx.wit.vtxinwit.append(CTxInWitness())
            self.fee += amount[i]
        pay = 600 * 1000 * 1000
        for i in range(8):
            self.fee -= pay
            self.tx.vout.append(CTxOut(pay, CScript([b'\x6a' + int_to_chr(i)])))
            pay -= 1 * 1000 * 1000

        signone = []
        signone.append(sign_msv0(key[0], CScript(), self.tx, 0, SIGHASH_MSV0_NONE, 0, self.fee))
        signone.append(sign_msv0(key[1], CScript(), self.tx, 0, SIGHASH_MSV0_NONE, 0, self.fee))
        signone.append(sign_msv0(key[2], CScript(), self.tx, 0, SIGHASH_MSV0_NONE, 0, self.fee))
        for i in range(3):
            self.tx.vin[4 * i + 1].scriptSig = CScript([get_ms_spk(ms)])
            self.tx.vin[4 * i + 3].scriptSig = CScript([CScript([OP_1, pubkey[i]])])
        self.tx.wit.vtxinwit[0].scriptWitness.stack = [signone[0]] + get_ms_stack(ms, 0)
        self.tx.wit.vtxinwit[1].scriptWitness.stack = [signone[1]] + get_ms_stack(ms, 1)
        self.tx.wit.vtxinwit[2].scriptWitness.stack = [signone[0], b'']
        self.tx.wit.vtxinwit[3].scriptWitness.stack = [signone[0], b'']
        self.tx.wit.vtxinwit[4].scriptWitness.stack = [signone[2]] + get_ms_stack(ms, 2)
        self.tx.wit.vtxinwit[5].scriptWitness.stack = [signone[0]] + get_ms_stack(ms, 3)
        self.tx.wit.vtxinwit[6].scriptWitness.stack = [signone[1], b'']
        self.tx.wit.vtxinwit[7].scriptWitness.stack = [signone[1], b'']
        self.tx.wit.vtxinwit[8].scriptWitness.stack = [b'\x05', signone[2], signone[0]] + get_ms_stack(ms, 4)
        self.tx.wit.vtxinwit[9].scriptWitness.stack = [signone[0], signone[1]] + get_ms_stack(ms, 5)
        self.tx.wit.vtxinwit[10].scriptWitness.stack = [signone[2], b'']
        self.tx.wit.vtxinwit[11].scriptWitness.stack = [signone[2], b'']

        self.tx_submit(0, self.tx)



        print ("Testing nVersion signing")
        # Replace a signature with SIGHASHV2_VERSION with a wrong nVersion should fail
        self.rbf()
        sig = sign_msv0(key[0], CScript(), self.tx, 0, SIGHASH_MSV0_NONE & ~SIGHASH_MSV0_NOVERSION, 0, self.fee)
        self.tx.nVersion += 1
        self.tx.wit.vtxinwit[0].scriptWitness.stack = [sig] + get_ms_stack(ms, 0)
        self.tx_submit(0, self.tx, CHECKSIGFAIL)
        # Revert nVersion should pass
        self.tx.nVersion -= 1
        self.tx_submit(0, self.tx)

        print ("Testing Input Index signing")
        self.rbf()
        sig = sign_msv0(key[1], CScript(), self.tx, 1, SIGHASH_MSV0_NONE & ~SIGHASH_MSV0_NOINPUTINDEX, 0, self.fee)
        self.tx.wit.vtxinwit[4].scriptWitness.stack = [sig] + get_ms_stack(ms, 1)
        self.tx_submit(0, self.tx, CHECKSIGFAIL)
        self.tx.wit.vtxinwit[1].scriptWitness.stack, self.tx.wit.vtxinwit[4].scriptWitness.stack = self.tx.wit.vtxinwit[4].scriptWitness.stack, self.tx.wit.vtxinwit[1].scriptWitness.stack
        self.tx_submit(0, self.tx)

        print ("Testing fees signing")
        self.rbf()
        sig = sign_msv0(key[1], CScript(), self.tx, 1, SIGHASH_MSV0_NONE & ~SIGHASH_MSV0_NOFEE, 0, self.fee)
        self.tx.vout[5].nValue += 1 # Change the value of only one vout should fail
        self.tx.wit.vtxinwit[6].scriptWitness.stack = [sig, b'']
        self.tx_submit(0, self.tx, CHECKSIGFAIL)
        self.tx.vout[7].nValue -= 1 # Revert to the original fee by changing another vout should pass
        self.tx_submit(0, self.tx)

        print ("Testing nLockTime signing")
        self.tx.wit.vtxinwit[6].scriptWitness.stack = [signone[1], b'']
        self.rbf()
        sig = sign_msv0(key[2], CScript(), self.tx, 1, SIGHASH_MSV0_NONE & ~SIGHASH_MSV0_NOLOCKTIME, 0, self.fee)
        self.tx.nLockTime += 1
        self.tx.wit.vtxinwit[10].scriptWitness.stack = [sig, b'']
        self.tx_submit(0, self.tx, CHECKSIGFAIL)
        self.tx.nLockTime -= 1
        self.tx_submit(0, self.tx)

        print ("Testing scriptCode signing")
        self.rbf()
        sig0a = sign_msv0(key[0], ms[0][0], self.tx, 1, SIGHASH_MSV0_NONE & ~SIGHASH_MSV0_NOSCRIPTCODE, 0, self.fee)
        sig0b = sign_msv0(key[0], ms[3][0], self.tx, 1, SIGHASH_MSV0_NONE & ~SIGHASH_MSV0_NOSCRIPTCODE, 0, self.fee)
        sig1a = sign_msv0(key[1], ms[5][0], self.tx, 1, SIGHASH_MSV0_NONE & ~SIGHASH_MSV0_NOSCRIPTCODE, 0, self.fee)
        sig1b = sign_msv0(key[1], ms[1][0], self.tx, 1, SIGHASH_MSV0_NONE & ~SIGHASH_MSV0_NOSCRIPTCODE, 0, self.fee)
        sig1c = sign_msv0(key[1], CScript([pubkey[1], OP_CHECKSIGVERIFY, pubkey[0], OP_CHECKSIG]), self.tx, 1, SIGHASH_MSV0_NONE & ~SIGHASH_MSV0_NOSCRIPTCODE, 0, self.fee)
        self.tx.wit.vtxinwit[0].scriptWitness.stack = [sig0a] + get_ms_stack(ms, 0)
        self.tx.wit.vtxinwit[1].scriptWitness.stack = [sig1b] + get_ms_stack(ms, 1)
        self.tx.wit.vtxinwit[2].scriptWitness.stack = [sig0a, b'']
        self.tx.wit.vtxinwit[5].scriptWitness.stack = [sig0b] + get_ms_stack(ms, 3)
        self.tx.wit.vtxinwit[6].scriptWitness.stack = [sig1b, b'']
        self.tx.wit.vtxinwit[9].scriptWitness.stack = [sig0a, sig1a] + get_ms_stack(ms, 5)
        self.tx_submit(0, self.tx)
        self.rbf()
        self.tx.wit.vtxinwit[0].scriptWitness.stack = [sig0b] + get_ms_stack(ms, 0)
        self.tx_submit(0, self.tx, CHECKSIGFAIL)
        self.tx.wit.vtxinwit[0].scriptWitness.stack = [sig0a] + get_ms_stack(ms, 0)
        self.tx.wit.vtxinwit[2].scriptWitness.stack = [sig0b, b'']
        self.tx_submit(0, self.tx, CHECKSIGFAIL)
        self.tx.wit.vtxinwit[2].scriptWitness.stack = [sig0a, b'']
        self.tx.wit.vtxinwit[5].scriptWitness.stack = [sig0a] + get_ms_stack(ms, 3)
        self.tx_submit(0, self.tx, CHECKSIGFAIL)
        self.tx.wit.vtxinwit[5].scriptWitness.stack = [sig0b] + get_ms_stack(ms, 3)
        self.tx.wit.vtxinwit[9].scriptWitness.stack = [sig0b, sig1a] + get_ms_stack(ms, 5)
        self.tx_submit(0, self.tx, CHECKSIGFAIL)
        self.tx.wit.vtxinwit[9].scriptWitness.stack = [sig0a, sig1b] + get_ms_stack(ms, 5)
        self.tx_submit(0, self.tx, CHECKSIGFAIL)
        self.tx.wit.vtxinwit[9].scriptWitness.stack = [sig0a, sig1c] + get_ms_stack(ms, 5)
        self.tx_submit(0, self.tx, CHECKSIGFAIL)
        self.tx.wit.vtxinwit[9].scriptWitness.stack = [sig0a, sig1a] + get_ms_stack(ms, 5)

        print ("Testing prevout and amount signing")
        sigall = sign_msv0(key[0], CScript(), self.tx, 0, SIGHASH_MSV0_NONE & ~3, amount[0], self.fee)
        sigallx = sign_msv0(key[0], CScript(), self.tx, 0, SIGHASH_MSV0_NONE & ~3, amount[0]+1, self.fee)
        sigsingle = sign_msv0(key[0], CScript(), self.tx, 0, SIGHASH_MSV0_NONE & ~2, amount[0], self.fee)
        signo = sign_msv0(key[0], CScript(), self.tx, 0, SIGHASH_MSV0_NONE & ~1, amount[0], self.fee)
        self.tx.wit.vtxinwit[0].scriptWitness.stack = [sigallx] + get_ms_stack(ms, 0)
        self.tx_submit(0, self.tx, CHECKSIGFAIL)
        self.tx.wit.vtxinwit[0].scriptWitness.stack = [sigall] + get_ms_stack(ms, 0)
        self.tx.vin[10], self.tx.vin[11] = self.tx.vin[11], self.tx.vin[10]
        self.tx_submit(0, self.tx, CHECKSIGFAIL)
        self.tx.vin[10], self.tx.vin[11] = self.tx.vin[11], self.tx.vin[10]
        self.tx_submit(0, self.tx)
        self.rbf()
        self.tx.wit.vtxinwit[0].scriptWitness.stack = [sigsingle] + get_ms_stack(ms, 0)
        self.tx_submit(0, self.tx)
        self.rbf()
        self.tx.wit.vtxinwit[1].scriptWitness.stack = [sigsingle] + get_ms_stack(ms, 0)
        self.tx_submit(0, self.tx, CHECKSIGFAIL)
        self.tx.vin[0], self.tx.vin[1] = self.tx.vin[1], self.tx.vin[0]
        self.tx.wit.vtxinwit[0].scriptWitness.stack = [signone[0]] + get_ms_stack(ms, 0)
        self.tx_submit(0, self.tx)
        self.rbf()
        self.tx.vin[0], self.tx.vin[1] = self.tx.vin[1], self.tx.vin[0]
        self.tx.wit.vtxinwit[0].scriptWitness.stack = [signo] + get_ms_stack(ms, 0)
        self.tx.wit.vtxinwit[1].scriptWitness.stack = [signone[0]] + get_ms_stack(ms, 0)
        self.tx_submit(0, self.tx)
        self.rbf()

        print ("Testing nSequence signing")
        sigall = sign_msv0(key[0], CScript(), self.tx, 0, SIGHASH_MSV0_NONE & ~0xc, amount[0], self.fee)
        sigsingle = sign_msv0(key[0], CScript(), self.tx, 0, SIGHASH_MSV0_NONE & ~0x8, amount[0], self.fee)
        siginvalid = sign_msv0(key[0], CScript(), self.tx, 0, SIGHASH_MSV0_NONE & ~0x4, amount[0], self.fee)
        self.rbf()
        self.tx.vin[0].nSequence += 1
        self.tx.wit.vtxinwit[0].scriptWitness.stack = [sigall] + get_ms_stack(ms, 0)
        self.tx_submit(0, self.tx, CHECKSIGFAIL)
        self.tx.vin[0].nSequence -= 1
        self.tx.vin[1].nSequence += 1
        self.tx_submit(0, self.tx, CHECKSIGFAIL)
        self.tx.vin[1].nSequence -= 1
        self.tx_submit(0, self.tx)
        self.rbf()
        self.tx.vin[0].nSequence += 1
        self.tx.wit.vtxinwit[0].scriptWitness.stack = [sigsingle] + get_ms_stack(ms, 0)
        self.tx_submit(0, self.tx, CHECKSIGFAIL)
        self.tx.vin[0].nSequence -= 1
        self.tx.vin[1].nSequence += 1
        self.tx.wit.vtxinwit[0].scriptWitness.stack = [sigsingle] + get_ms_stack(ms, 0)
        self.tx_submit(0, self.tx)
        self.rbf()
        self.tx.wit.vtxinwit[0].scriptWitness.stack = [siginvalid] + get_ms_stack(ms, 0)
        self.tx_submit(0, self.tx, HASHTYPEFAIL)

        print ("Testing outputs signing")
        sigall = sign_msv0(key[0], CScript(), self.tx, 0, SIGHASH_MSV0_NONE & ~0x30, amount[0], self.fee)
        self.tx.wit.vtxinwit[0].scriptWitness.stack = [sigall] + get_ms_stack(ms, 0)
        self.tx.vout[1], self.tx.vout[2] = self.tx.vout[2], self.tx.vout[1]
        self.tx_submit(0, self.tx, CHECKSIGFAIL)
        self.tx.vout[1], self.tx.vout[2] = self.tx.vout[2], self.tx.vout[1]
        self.tx.vout[1].nValue += 1
        self.tx_submit(0, self.tx, CHECKSIGFAIL)
        self.tx.vout[1].nValue -= 1
        self.tx.vout[1].scriptPubKey = CScript([b'\x6a\x02'])
        self.tx_submit(0, self.tx, CHECKSIGFAIL)
        self.tx.vout[1].scriptPubKey = CScript([b'\x6a\x01'])
        self.tx_submit(0, self.tx)
        self.rbf()
        sigsingle = sign_msv0(key[0], CScript(), self.tx, 0, SIGHASH_MSV0_NONE & ~0x20, amount[0], self.fee)
        self.tx.wit.vtxinwit[0].scriptWitness.stack = [sigsingle] + get_ms_stack(ms, 0)
        self.tx.vout[1].scriptPubKey = CScript([b'\x6a\x02'])
        self.tx.vout[1].nValue += 1
        self.tx_submit(0, self.tx)
        self.rbf()
        self.tx.vout[1].scriptPubKey = CScript([b'\x6a\x01'])
        self.tx.vout[1].nValue -= 1
        self.tx.vout[0].scriptPubKey = CScript([b'\x6a\x02'])
        self.tx_submit(0, self.tx, CHECKSIGFAIL)
        self.tx.vout[0].scriptPubKey = CScript([b'\x6a\x00'])
        self.tx.vout[0].nValue += 1
        self.tx_submit(0, self.tx, CHECKSIGFAIL)
        self.tx.vout[0].nValue -= 1
        self.tx_submit(0, self.tx)
        self.rbf()
        sigsinglenovalue = sign_msv0(key[0], CScript(), self.tx, 2, SIGHASH_MSV0_NONE & ~0x10, amount[0], self.fee)
        self.tx.wit.vtxinwit[2].scriptWitness.stack = [sigsinglenovalue, b'']
        self.tx.vout[1].scriptPubKey = CScript([b'\x6a\x02'])
        self.tx.vout[1].nValue += 1
        self.tx_submit(0, self.tx)
        self.rbf()
        self.tx.vout[1].scriptPubKey = CScript([b'\x6a\x01'])
        self.tx.vout[1].nValue -= 1
        self.tx.vout[2].scriptPubKey = CScript([b'\x6a\x03'])
        self.tx_submit(0, self.tx, CHECKSIGFAIL)
        self.tx.vout[2].scriptPubKey = CScript([b'\x6a\x02'])
        self.tx.vout[2].nValue += 1
        self.tx_submit(0, self.tx)
        self.rbf()
        self.tx.vout[2].nValue -= 1
        self.tx_submit(0, self.tx)
        self.rbf()

        print ("Testing scriptWitCode signing")
        self.rbf()
        sigcode1 = [CScript([OP_14, OP_EQUALVERIFY]),CScript([OP_15, OP_EQUALVERIFY]),CScript(),CScript([OP_16, OP_EQUALVERIFY])]
        self.tx.wit.vtxinwit[0].scriptWitness.stack = [signone[0], b'\x0e', b'\x0f', b'\x10'] + get_ms_stack(ms, 0, sigcode1)
        self.tx_submit(0, self.tx, WITCODEFAIL)
        sig0_013 = sign_msv0(key[0], CScript(), self.tx, 0, SIGHASH_MSV0_NONE & ~SIGHASH_MSV0_NOSCRIPTSIGCODE0 & ~SIGHASH_MSV0_NOSCRIPTSIGCODE1 & ~SIGHASH_MSV0_NOSCRIPTSIGCODE3, 0, self.fee, sigcode1)
        sig0_01 = sign_msv0(key[0], CScript(), self.tx, 0, SIGHASH_MSV0_NONE & ~SIGHASH_MSV0_NOSCRIPTSIGCODE0 & ~SIGHASH_MSV0_NOSCRIPTSIGCODE1, 0, self.fee, sigcode1)
        sig2_3 = sign_msv0(key[2], CScript(), self.tx, 0, SIGHASH_MSV0_NONE & ~SIGHASH_MSV0_NOSCRIPTSIGCODE3, 0, self.fee, sigcode1)

        self.tx.wit.vtxinwit[0].scriptWitness.stack = [sig0_013, b'\x0e', b'\x0f', b'\x10'] + get_ms_stack(ms, 0, sigcode1)
        self.tx_submit(0, self.tx)
        self.rbf()
        self.tx.wit.vtxinwit[8].scriptWitness.stack = [b'\x05', signone[2], sig0_01, b'\x0e', b'\x0f', b'\x10'] + get_ms_stack(ms, 4, sigcode1)
        self.tx_submit(0, self.tx, WITCODEFAIL)
        self.tx.wit.vtxinwit[8].scriptWitness.stack = [b'\x05', sig2_3, signone[0], b'\x0e', b'\x0f', b'\x10'] + get_ms_stack(ms, 4, sigcode1)
        self.tx_submit(0, self.tx, WITCODEFAIL)
        self.tx.wit.vtxinwit[8].scriptWitness.stack = [b'\x05', sig2_3, sig0_01, b'\x0e', b'\x0f', b'\x10'] + get_ms_stack(ms, 4, sigcode1)
        self.tx_submit(0, self.tx)
        self.rbf()

    def rbf(self, fee = 1 * 1000 * 1000):
        self.fee += fee
        self.tx.vout[7].nValue -= fee

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
    MSV0Test().main()