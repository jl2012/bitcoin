#!/usr/bin/env python3
# Copyright (c) 2019 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
# Test taproot softfork.

from test_framework.blocktools import create_coinbase, create_block, create_transaction, add_witness_commitment
from test_framework.messages import CTransaction, CTxIn, CTxOut, COutPoint, CTxInWitness
from test_framework.script import CScript, TaprootSignatureHash, taproot_construct, GetP2SH, OP_0, OP_1, OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_CHECKSIGADD, OP_IF, OP_CODESEPARATOR, OP_ELSE, OP_ENDIF, OP_DROP, DEFAULT_TAPSCRIPT_VER, SIGHASH_SINGLE, is_op_success, CScriptOp, OP_RETURN, OP_VERIF, OP_RESERVED, OP_1NEGATE, OP_EQUAL, MAX_SCRIPT_ELEMENT_SIZE, LOCKTIME_THRESHOLD, ANNEX_TAG
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error, hex_str_to_bytes
from test_framework.key import ECKey
from test_framework.address import program_to_witness, script_to_p2sh
from binascii import hexlify
from hashlib import sha256
from io import BytesIO
import random
import struct

EMPTYWITNESS_ERROR = "non-mandatory-script-verify-flag (Witness program was passed an empty witness) (code 64)"
INVALIDKEYPATHSIG_ERROR = "non-mandatory-script-verify-flag (Invalid signature for taproot key path spending) (code 64)"
UNKNOWNWITNESS_ERROR = "non-mandatory-script-verify-flag (Witness version reserved for soft-fork upgrades) (code 64)"
VALID_SIGHASHES = [0,1,2,3,0x81,0x82,0x83]
VALID_NOINPUTSIGHASHES = [0x41,0x42,0x43,0xc1,0xc2,0xc3]

DUST_LIMIT = 600
MIN_FEE = 5000

def rand_nonnoinput():
    return random.choice(VALID_SIGHASHES)

def rand_noinput():
    return random.choice(VALID_NOINPUTSIGHASHES)

def tx_from_hex(hexstring):
    tx = CTransaction()
    f = BytesIO(hex_str_to_bytes(hexstring))
    tx.deserialize(f)
    return tx

def get_taproot_bech32(info):
    if isinstance(info, tuple):
        info = info[0]
    return program_to_witness(1, info[2:])

def get_taproot_p2sh(info):
    return script_to_p2sh(info[0])

def random_op_success():
    ret = 0
    while (not is_op_success(ret)):
        ret = random.randint(0x50, 0xfe)
    return CScriptOp(ret)

def random_unknown_tapscript_ver(no_annex_tag=True):
    ret = DEFAULT_TAPSCRIPT_VER
    while (ret == DEFAULT_TAPSCRIPT_VER or (no_annex_tag and ret == (ANNEX_TAG & 0xfe))):
        ret = random.randrange(128) * 2
    return ret

def random_bytes(n):
    return bytes(random.getrandbits(8) for i in range(n))

def random_script(size, no_success = True):
    ret = bytes()
    while (len(ret) < size):
        remain = size - len(ret)
        opcode = random.randrange(256)
        while (no_success and is_op_success(opcode)):
            opcode = random.randrange(256)
        if opcode == 0 or opcode >= OP_1NEGATE:
            ret += bytes([opcode])
        elif opcode <= 75 and opcode <= remain - 1:
            ret += bytes([opcode]) + random_bytes(opcode)
        elif opcode == 76 and remain >= 2:
            pushsize = random.randint(0, min(0xff, remain - 2))
            ret += bytes([opcode]) + bytes([pushsize]) + random_bytes(pushsize)
        elif opcode == 77 and remain >= 3:
            pushsize = random.randint(0, min(0xffff, remain - 3))
            ret += bytes([opcode]) + struct.pack(b'<H', pushsize) + random_bytes(pushsize)
        elif opcode == 78 and remain >= 5:
            pushsize = random.randint(0, min(0xffffffff, remain - 5))
            ret += bytes([opcode]) + struct.pack(b'<I', pushsize) + random_bytes(pushsize)
    assert len(ret) == size
    return ret

def random_invalid_push(size):
    assert size > 0
    ret = bytes()
    opcode = 78
    if size <= 75:
        opcode = random.randint(75, 78)
    elif size <= 255:
        opcode = random.randint(76, 78)
    elif size <= 0xffff:
        opcode = random.randint(77, 78)
    if opcode == 75:
        ret = bytes([size]) + random_bytes(size - 1)
    elif opcode == 76:
        ret = bytes([opcode]) + bytes([size]) + random_bytes(size - 2)
    elif opcode == 77:
        ret = bytes([opcode]) + struct.pack(b'<H', size) + random_bytes(max(0, size - 3))
    else:
        ret = bytes([opcode]) + struct.pack(b'<I', size) + random_bytes(max(0, size - 5))
    assert len(ret) >= size
    return ret[:size]

def random_checksig_style(pubkey):
    opcode = random.choice([OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_CHECKSIGADD])
    if (opcode == OP_CHECKSIGVERIFY):
        ret = CScript([pubkey, opcode, OP_1])
    elif (opcode == OP_CHECKSIGADD):
        num = random.choice([0, 0x7fffffff, -0x7fffffff])
        ret = CScript([num, pubkey, opcode, num+1, OP_EQUAL])
    else:
        ret = CScript([pubkey, opcode])
    return bytes(ret)

def damage_bytes(b):
    return (int.from_bytes(b, 'big') ^ (1 << random.randrange(len(b)*8))).to_bytes(len(b), 'big')

def spend_multi_sig(tx, input_index, spent_utxos, info, p2sh, sign, script=None, annex=None, damage=False):
    damage_type_range = 5 if script is None else 6
    damage_type = random.randrange(damage_type_range) if damage else -1
    damage_sig = random.randrange(len(sign))
    if damage:
        for i in sign:
            if 'dht' in i:
                damage_type = 100
                break
    '''
    * 0. bit flip the sighash
    * 1. bit flip the signature
    * If the expected hashtype is 0:
    -- 2. append a 0 to the signature
    -- 3. append a random value of 1-255 to the signature
    * If the expected hashtype is not 0:
    -- 2. do not append hashtype to the signature
    -- 3. append a random incorrect value of 0-255 to the signature
    * 4. extra witness element
    * 5. use a wrong key version for sighash
    * 100. fail with given sighash type (for rannisawni)
    '''

    # Taproot key path spend: tweak key
    if script is None:
        assert (len(sign) == 1)
        key = sign[0]['key'].tweak_add(info[1])
        assert(key is not None)
        ht = sign[0]["ht"] if "ht" in sign[0] else 0
        sign = [{'key':key,'ht':ht}]

    ret = []
    for n, i in enumerate(sign):
        damage_sig_type = damage_type if n == damage_sig else -1
        ht = i["ht"] if "ht" in i else 0
        if (damage_type == 100 and "dht" in i):
            ht = i["dht"]
        # Change SIGHASH_SINGLE into SIGHASH_ALL if no corresponding output
        if (input_index >= len(tx.vout) and (ht & 3) == SIGHASH_SINGLE):
            ht ^= 2
        # Compute sighash
        pos = i["pos"] if "pos" in i else 0xffff
        ver = i["ver"] if "ver" in i else 2
        if damage_sig_type == 5:
            ver = 0 if ver == 2 else 2

        if script:
            sighash = TaprootSignatureHash(tx, spent_utxos, ht, input_index, scriptpath = True, tapscript = script, codeseparator_pos = pos, annex = annex, key_ver = ver)
        else:
            sighash = TaprootSignatureHash(tx, spent_utxos, ht, input_index, scriptpath = False, annex = annex)
        if damage_sig_type == 0:
            sighash = damage_bytes(sighash)
        # Compute signature
        sig = i["key"].sign_schnorr(sighash)
        if damage_sig_type == 1:
            sig = damage_bytes(sig)
        if damage_sig_type == 2:
            if ht == 0:
                sig += bytes([0])
        elif damage_sig_type == 3:
            random_ht = ht
            while random_ht == ht:
                random_ht = random.randrange(256)
            sig += bytes([random_ht])
        elif ht > 0:
            sig += bytes([ht])
        # Construct witness
        if "pre" in i:
            ret += i["pre"]
        ret += [sig]
        if "suf" in i:
            ret += i["suf"]
    if script is not None:
        ret += [script, info[2][script]]
    if annex is not None:
        ret += [annex]
    if damage_type == 4:
        ret = [random_bytes(random.randrange(5))] + ret
    tx.wit.vtxinwit[input_index].scriptWitness.stack = ret
    # Construct P2SH redeemscript
    tx.vin[input_index].scriptSig = CScript([info[0]]) if p2sh else CScript()

def spend_alwaysvalid(tx, input_index, info, p2sh, script, annex=None, damage=False):
    if isinstance(script, tuple):
        version, script = script
    ret = [script, info[2][script]]
    if damage:
        # With 50% chance, we bit flip the script (unless the script is an empty vector)
        # With 50% chance, we bit flip the control block
        if random.choice([True, False]) or len(ret[0]) == 0:
            # Annex is always required for tapscript version 0x50
            # Unless the original version is 0x50, we couldn't convert it to 0x50 without using annex
            tmp = damage_bytes(ret[1])
            while annex is None and tmp[0] == ANNEX_TAG and ret[1][0] != ANNEX_TAG:
                tmp = damage_bytes(ret[1])
            ret[1] = tmp
        else:
            ret[0] = damage_bytes(ret[0])
    if annex is not None:
        ret += [annex]
    # Randomly add input witness
    if random.choice([True, False]):
        for i in range(random.randint(1, 10)):
            ret = [random_bytes(random.randint(0, MAX_SCRIPT_ELEMENT_SIZE*2))] + ret
    tx.wit.vtxinwit[input_index].scriptWitness.stack = ret
    # Construct P2SH redeemscript
    tx.vin[input_index].scriptSig = CScript([info[0]]) if p2sh else CScript()

def make_spender(spenders, info, p2sh, comment, key=None, sign=None, standard=True, **kwargs):
    spk = info[0]
    addr = get_taproot_bech32(info)
    if p2sh:
        spk = GetP2SH(spk)
        addr = get_taproot_p2sh(info)
    def fn(t, i, u, v):
        if (sign is not None):
            return spend_multi_sig(t, i, u, damage=not v, info=info, p2sh=p2sh, sign=sign, **kwargs)
        else:
            return spend_alwaysvalid(t, i, damage=not v, info=info, p2sh=p2sh, **kwargs)
    spenders.append((spk, addr, comment, standard, fn))

class TAPROOTTest(BitcoinTestFramework):

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-whitelist=127.0.0.1", "-acceptnonstdtxn=0", "-par=1"]]

    def block_submit(self, node, txs, msg, cb_pubkey=None, fees=0, witness=False, accept=False):
        block = create_block(self.tip, create_coinbase(self.lastblockheight + 1, pubkey=cb_pubkey, fees=fees), self.lastblocktime + 1)
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
            assert node.getbestblockhash() == block.hash, "Failed to accept: " + msg
            self.tip = block.sha256
            self.lastblockhash = block.hash
            self.lastblocktime += 1
            self.lastblockheight += 1
        else:
            assert node.getbestblockhash() == self.lastblockhash, "Failed to reject: " + msg

    def test_spenders(self, spenders, input_counts):
        """Run randomized tests with a number of "spenders".

        Each spender is a tuple of:
        - A scriptPubKey (CScript)
        - An address for that scriptPubKey (string)
        - A comment describing the test (string)
        - Whether the spending (on itself) is expected to be standard (bool)
        - A lambda taking as inputs:
          - A transaction to sign (CTransaction)
          - An input position (int)
          - The spent UTXOs by this transaction (list of CTxOut)
          - Whether to produce a valid spend (bool)

        Each spender embodies a test; in a large randomized test, it is verified
        that toggling the valid argument to each lambda toggles the validity of
        the transaction. This is accomplished by constructing transactions consisting
        of all valid inputs, except one invalid one.
        """

        # Construct a UTXO to spend for each of the spenders
        self.nodes[0].generate(110)
        bal = self.nodes[0].getbalance() * 3 / (4*len(spenders))
        random.shuffle(spenders)
        num_spenders = len(spenders)
        utxos = []
        while len(spenders):
            # Create the necessary outputs in multiple transactions, as sPKs may be repeated (which sendmany does not support)
            outputs = {}
            new_spenders = []
            batch = []
            for spender in spenders:
                addr = spender[1]
                if addr in outputs:
                    new_spenders.append(spender)
                else:
                    amount = random.randrange(int(bal * 95000000), int(bal * 105000000))
                    outputs[addr] = amount / 100000000
                    batch.append(spender)
            self.log.info("Constructing %i UTXOs for spending tests" % len(batch))
            tx = tx_from_hex(self.nodes[0].getrawtransaction(self.nodes[0].sendmany("", outputs)))
            tx.rehash()
            spenders = new_spenders
            random.shuffle(spenders)

            # Map created UTXOs back to the spenders they were created for
            vout_dict = {}
            for n, out in enumerate(tx.vout):
                vout_dict[out.scriptPubKey] = (COutPoint(tx.sha256, n), out)
            for spender in batch:
                utxos.append(vout_dict[spender[0]] + (spender,))
        assert(len(utxos) == num_spenders)
        random.shuffle(utxos)
        self.nodes[0].generate(1)

        # Construct a bunch of sPKs that send coins back to the host wallet
        self.log.info("Constructing 100 addresses for returning coins")
        host_spks = []
        host_pubkeys = []
        for i in range(100):
            addr = self.nodes[0].getnewaddress(address_type=random.choice(["legacy", "p2sh-segwit", "bech32"]))
            info = self.nodes[0].getaddressinfo(addr)
            spk = hex_str_to_bytes(info['scriptPubKey'])
            host_spks.append(spk)
            host_pubkeys.append(hex_str_to_bytes(info['pubkey']))

        # Pick random subsets of UTXOs to construct transactions with
        self.lastblockhash = self.nodes[0].getbestblockhash()
        self.tip = int("0x" + self.lastblockhash, 0)
        block = self.nodes[0].getblock(self.lastblockhash)
        self.lastblockheight = block['height']
        self.lastblocktime = block['time']
        while len(utxos):
            tx = CTransaction()
            tx.nVersion = random.choice([1, 2, random.randint(-0x80000000,0x7fffffff)])
            min_sequence = (tx.nVersion != 1 and tx.nVersion != 0) * 0x80000000 # The minimum sequence number to disable relative locktime
            if random.choice([True, False]):
                tx.nLockTime = random.randrange(LOCKTIME_THRESHOLD, self.lastblocktime - 7200) # all absolute locktimes in the past
            else:
                tx.nLockTime = random.randrange(self.lastblockheight+1) # all block heights in the past

            # Pick 1 to 4 UTXOs to construct transaction inputs
            acceptable_input_counts = [cnt for cnt in input_counts if cnt <= len(utxos)]
            while True:
                inputs = random.choice(acceptable_input_counts)
                remaining = len(utxos) - inputs
                if remaining == 0 or remaining >= max(input_counts) or remaining in input_counts:
                    break
            input_utxos = utxos[-inputs:]
            utxos = utxos[:-inputs]
            fee = random.randrange(MIN_FEE * 2, MIN_FEE * 4) # 10000-20000 sat fee
            in_value = sum(utxo[1].nValue for utxo in input_utxos) - fee
            tx.vin = [CTxIn(outpoint = input_utxos[i][0], nSequence = random.randint(min_sequence, 0xffffffff)) for i in range(inputs)]
            tx.wit.vtxinwit = [CTxInWitness() for i in range(inputs)]
            self.log.info("Test: %s" % (", ".join(utxo[2][2] for utxo in input_utxos)))

            # Add 1 to 4 outputs
            outputs = random.choice([1,2,3,4])
            for i in range(outputs):
                tx.vout.append(CTxOut())
                if in_value <= DUST_LIMIT:
                    tx.vout[-1].nValue = DUST_LIMIT
                elif i < outputs - 1:
                    tx.vout[-1].nValue = in_value
                else:
                    tx.vout[-1].nValue = random.randint(DUST_LIMIT, in_value)
                in_value -= tx.vout[-1].nValue
                tx.vout[-1].scriptPubKey = random.choice(host_spks)
            fee += in_value
            assert(fee >= MIN_FEE)

            # Fill correct inputs/witnesses
            for i in range(inputs):
                fn = input_utxos[i][2][4]
                fn(tx, i, [utxo[1] for utxo in input_utxos], True)
            tx.rehash()

            # For each inputs, make it fail once; then succeed once
            for fail_input in range(inputs + 1):
                txcopy = CTransaction(tx)
                # Fail a input
                if (fail_input != inputs):
                    fn = input_utxos[fail_input][2][4]
                    fn(txcopy, fail_input, [utxo[1] for utxo in input_utxos], False)
                txcopy.rehash()
                # Submit to mempool to check standardness
                standard = fail_input == inputs and all(utxo[2][3] for utxo in input_utxos) and txcopy.nVersion >= 1 and txcopy.nVersion <= 2
                if standard:
                    self.nodes[0].sendrawtransaction(txcopy.serialize().hex(), 0)
                    assert(self.nodes[0].getmempoolentry(txcopy.hash) is not None)
                else:
                    assert_raises_rpc_error(-26, None, self.nodes[0].sendrawtransaction, txcopy.serialize().hex(), 0)
                # Submit in a block
                msg = ','.join(utxo[2][2] + ("*" if n == fail_input else "") for n, utxo in enumerate(input_utxos))
                self.block_submit(self.nodes[0], [txcopy], msg, witness=True, accept=fail_input == inputs, cb_pubkey=random.choice(host_pubkeys), fees=fee)

    def run_test(self):
        spenders = []

        for p2sh in [False, True]:
            random_annex = bytes([ANNEX_TAG]) + random_bytes(random.randrange(0, 5))
            for annex in [None, random_annex]:
                standard = annex is None
                sec1, sec2, sec3 = ECKey(), ECKey(), ECKey()
                sec1.generate()
                sec2.generate()
                sec3.generate()
                pub1, pub2, pub3 = sec1.get_pubkey(), sec2.get_pubkey(), sec3.get_pubkey()

                # Sighash mutation tests
                for ht in VALID_SIGHASHES:
                    # Pure pubkey
                    info = taproot_construct(pub1, [])
                    make_spender(spenders, info, p2sh, "sighash/pk#pk", sign=[{'key':sec1, 'ht':ht}], annex=annex, standard=standard)
                    # Pubkey/P2PK script combination
                    scripts = [CScript(random_checksig_style(pub2.get_bytes()))]
                    info = taproot_construct(pub1, scripts)
                    make_spender(spenders, info, p2sh, "sighash/p2pk#pk", sign=[{'key':sec1, 'ht':ht}], annex=annex, standard=standard)
                    make_spender(spenders, info, p2sh, "sighash/p2pk#s0", script=scripts[0], sign=[{'key':sec2, 'ht':ht}], annex=annex, standard=standard)
                    # More complex script structure
                    scripts = [
                        CScript(random_checksig_style(pub2.get_bytes()) + bytes([OP_CODESEPARATOR])), # codesep after checksig
                        CScript(bytes([OP_CODESEPARATOR]) + random_checksig_style(pub2.get_bytes())), # codesep before checksig
                        CScript([bytes([1,2,3]), OP_DROP, OP_IF, OP_CODESEPARATOR, pub1.get_bytes(), OP_ELSE, OP_CODESEPARATOR, pub2.get_bytes(), OP_ENDIF, OP_CHECKSIG]), # branch dependent codesep
                    ]
                    info = taproot_construct(pub1, scripts)
                    make_spender(spenders, info, p2sh, "sighash/codesep#pk", sign=[{'key':sec1, 'ht':ht}], annex=annex, standard=standard)
                    make_spender(spenders, info, p2sh, "sighash/codesep#s0", script=scripts[0], sign=[{'key':sec2, 'ht':ht}], annex=annex, standard=standard)
                    make_spender(spenders, info, p2sh, "sighash/codesep#s1", script=scripts[1], sign=[{'key':sec2, 'ht':ht, 'pos':0}], annex=annex, standard=standard)
                    make_spender(spenders, info, p2sh, "sighash/codesep#s2a", script=scripts[2], sign=[{'key':sec1, 'ht':ht, 'pos':3, 'suf':[bytes([1])]}], annex=annex, standard=standard)
                    make_spender(spenders, info, p2sh, "sighash/codesep#s2b", script=scripts[2], sign=[{'key':sec2, 'ht':ht, 'pos':6, 'suf':[bytes([])]}], annex=annex, standard=standard)

                # OP_SUCCESSx and unknown tapscript versions
                scripts = [
                    CScript([random_op_success()]),
                    CScript([OP_0, OP_IF, random_op_success(), OP_ENDIF, OP_RETURN]),
                    CScript([random_op_success(), OP_VERIF]),
                    CScript(random_script(10000) + bytes([random_op_success()]) + random_invalid_push(random.randint(1,10))),
                    (random_unknown_tapscript_ver(), CScript([OP_RETURN])),
                    (random_unknown_tapscript_ver(), CScript(random_script(10000) + random_invalid_push(random.randint(1,10)))),
                    (ANNEX_TAG & 0xfe, CScript()),
                ]
                info = taproot_construct(pub1, scripts)
                make_spender(spenders, info, p2sh, "alwaysvalid/pk", sign=[{'key':sec1, 'ht':rand_nonnoinput()}], annex=annex, standard=standard)
                make_spender(spenders, info, p2sh, "alwaysvalid/success", script=scripts[0], annex=annex, standard=False)
                make_spender(spenders, info, p2sh, "alwaysvalid/success#if", script=scripts[1], annex=annex, standard=False)
                make_spender(spenders, info, p2sh, "alwaysvalid/success#verif", script=scripts[2], annex=annex, standard=False)
                make_spender(spenders, info, p2sh, "alwaysvalid/success#10000+", script=scripts[3], annex=annex, standard=False)
                make_spender(spenders, info, p2sh, "alwaysvalid/unknownversion#return", script=scripts[4], annex=annex, standard=False)
                make_spender(spenders, info, p2sh, "alwaysvalid/unknownversion#10000+", script=scripts[5], annex=annex, standard=False)
                if (info[2][scripts[6][1]][0] != ANNEX_TAG or annex is not None):
                    # Annex is mandatory for control block with version 0x50
                    make_spender(spenders, info, p2sh, "alwaysvalid/unknownversion#fe", script=scripts[6], annex=annex, standard=False)

                # Dual keys and NOINPUT
                scripts = [
                    CScript([pub2.get_bytes(), OP_CHECKSIGVERIFY, pub3.get_bytes(), OP_CHECKSIG]),
                    CScript([pub2.get_bytes(0), OP_CHECKSIGVERIFY, pub3.get_bytes(), OP_CHECKSIG]),
                    CScript([OP_1, OP_CHECKSIGVERIFY, pub3.get_bytes(), OP_CHECKSIG]),
                    CScript([OP_1, OP_CHECKSIGVERIFY, pub3.get_bytes(0), OP_CHECKSIG]),
                ]
                info = taproot_construct(pub1, scripts)
                # nni: non-noinput; ni: noinput; v0d: v0 internal key; ran: test rannisawni
                make_spender(spenders, info, p2sh, "dualsig/pk", sign=[{'key':sec1,'ht':rand_nonnoinput()}], annex=annex, standard=standard)
                make_spender(spenders, info, p2sh, "dualsig/v2nniv2nni", script=scripts[0], sign=[{'key':sec3,'ht':rand_nonnoinput()}, {'key':sec2,'ht':rand_nonnoinput()}], annex=annex, standard=standard)
                make_spender(spenders, info, p2sh, "dualsig/v0nniv2nni", script=scripts[1], sign=[{'key':sec3,'ht':rand_nonnoinput()}, {'key':sec2,'ht':rand_nonnoinput(),'ver':0}], annex=annex, standard=standard)
                make_spender(spenders, info, p2sh, "dualsig/v0niv2nni", script=scripts[1], sign=[{'key':sec3,'ht':rand_nonnoinput()}, {'key':sec2,'ht':rand_noinput(),'ver':0}], annex=annex, standard=standard)
                make_spender(spenders, info, p2sh, "dualsig/v0niv2nniran", script=scripts[1], sign=[{'key':sec3,'ht':rand_nonnoinput(),'dht':rand_noinput()}, {'key':sec2,'ht':rand_noinput(),'ver':0}], annex=annex, standard=standard)
                make_spender(spenders, info, p2sh, "dualsig/v0dnniv2nni", script=scripts[2], sign=[{'key':sec3,'ht':rand_nonnoinput()}, {'key':sec1,'ht':rand_nonnoinput(),'ver':0}], annex=annex, standard=standard)
                make_spender(spenders, info, p2sh, "dualsig/v0dniv2nni", script=scripts[2], sign=[{'key':sec3,'ht':rand_nonnoinput()}, {'key':sec1,'ht':rand_noinput(),'ver':0}], annex=annex, standard=standard)
                make_spender(spenders, info, p2sh, "dualsig/v0dniv2nniran", script=scripts[2], sign=[{'key':sec3,'ht':rand_nonnoinput(),'dht':rand_noinput()}, {'key':sec1,'ht':rand_noinput(),'ver':0}], annex=annex, standard=standard)
                make_spender(spenders, info, p2sh, "dualsig/v0dnniv0nni", script=scripts[3], sign=[{'key':sec3,'ht':rand_nonnoinput(),'ver':0}, {'key':sec1,'ht':rand_nonnoinput(),'ver':0}], annex=annex, standard=standard)
                make_spender(spenders, info, p2sh, "dualsig/v0dnniv0ni", script=scripts[3], sign=[{'key':sec3,'ht':rand_nonnoinput(),'ver':0}, {'key':sec1,'ht':rand_noinput(),'ver':0}], annex=annex, standard=standard)
                make_spender(spenders, info, p2sh, "dualsig/v0dniv0nni", script=scripts[3], sign=[{'key':sec3,'ht':rand_noinput(),'ver':0}, {'key':sec1,'ht':rand_nonnoinput(),'ver':0}], annex=annex, standard=standard)
                make_spender(spenders, info, p2sh, "dualsig/v0dniv0nniran", script=scripts[3], sign=[{'key':sec3,'ht':rand_nonnoinput(),'dht':rand_noinput(),'ver':0}, {'key':sec1,'ht':rand_noinput(),'ver':0}], annex=annex, standard=standard)
                make_spender(spenders, info, p2sh, "dualsig/v0dnniv0niran", script=scripts[3], sign=[{'key':sec3,'ht':rand_noinput(),'ver':0}, {'key':sec1,'ht':rand_nonnoinput(),'dht':rand_noinput(),'ver':0}], annex=annex, standard=standard)

        # Run all tests once with individual inputs, once with groups of inputs
        self.test_spenders(spenders, input_counts=[1])
        self.test_spenders(spenders, input_counts=[2,3,4])


if __name__ == '__main__':
    TAPROOTTest().main()
