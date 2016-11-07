// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "interpreter.h"

#include "primitives/transaction.h"
#include "crypto/ripemd160.h"
#include "crypto/sha1.h"
#include "crypto/sha256.h"
#include "pubkey.h"
#include "script/script.h"
#include "uint256.h"
#include "consensus/merkle.h"

using namespace std;

typedef vector<unsigned char> valtype;

namespace {

inline bool set_success(ScriptError* ret)
{
    if (ret)
        *ret = SCRIPT_ERR_OK;
    return true;
}

inline bool set_error(ScriptError* ret, const ScriptError serror)
{
    if (ret)
        *ret = serror;
    return false;
}

} // anon namespace

bool CastToBool(const valtype& vch)
{
    for (unsigned int i = 0; i < vch.size(); i++)
    {
        if (vch[i] != 0)
        {
            // Can be negative zero
            if (i == vch.size()-1 && vch[i] == 0x80)
                return false;
            return true;
        }
    }
    return false;
}

/**
 * Script is a stack machine (like Forth) that evaluates a predicate
 * returning a bool indicating valid or not.  There are no loops.
 */
#define stacktop(i)  (stack.at(stack.size()+(i)))
#define altstacktop(i)  (altstack.at(altstack.size()+(i)))
static inline void popstack(vector<valtype>& stack)
{
    if (stack.empty())
        throw runtime_error("popstack(): stack empty");
    stack.pop_back();
}

bool static IsCompressedOrUncompressedPubKey(const valtype &vchPubKey) {
    if (vchPubKey.size() < 33) {
        //  Non-canonical public key: too short
        return false;
    }
    if (vchPubKey[0] == 0x04) {
        if (vchPubKey.size() != 65) {
            //  Non-canonical public key: invalid length for uncompressed key
            return false;
        }
    } else if (vchPubKey[0] == 0x02 || vchPubKey[0] == 0x03) {
        if (vchPubKey.size() != 33) {
            //  Non-canonical public key: invalid length for compressed key
            return false;
        }
    } else {
        //  Non-canonical public key: neither compressed nor uncompressed
        return false;
    }
    return true;
}

bool static IsCompressedPubKey(const valtype &vchPubKey) {
    if (vchPubKey.size() != 33) {
        //  Non-canonical public key: invalid length for compressed key
        return false;
    }
    if (vchPubKey[0] != 0x02 && vchPubKey[0] != 0x03) {
        //  Non-canonical public key: invalid prefix for compressed key
        return false;
    }
    return true;
}

bool static IsKnownKeyVersion(const valtype &vchPubKey) {
    if (vchPubKey.empty())
        return true;
    if (vchPubKey[0] == 2 || vchPubKey[0] == 3 ||vchPubKey[0] == 4 || vchPubKey[0] == 6 || vchPubKey[0] == 7)
        return true;
    return false;
}

/**
 * A canonical signature exists of: <30> <total len> <02> <len R> <R> <02> <len S> <S> <hashtype>
 * Where R and S are not negative (their first byte has its highest bit not set), and not
 * excessively padded (do not start with a 0 byte, unless an otherwise negative number follows,
 * in which case a single 0 byte is necessary and even required).
 * 
 * See https://bitcointalk.org/index.php?topic=8392.msg127623#msg127623
 *
 * This function is consensus-critical since BIP66.
 */
bool static IsValidSignatureEncoding(const std::vector<unsigned char> &sig) {
    // Format: 0x30 [total-length] 0x02 [R-length] [R] 0x02 [S-length] [S] [sighash]
    // * total-length: 1-byte length descriptor of everything that follows,
    //   excluding the sighash byte.
    // * R-length: 1-byte length descriptor of the R value that follows.
    // * R: arbitrary-length big-endian encoded R value. It must use the shortest
    //   possible encoding for a positive integers (which means no null bytes at
    //   the start, except a single one when the next byte has its highest bit set).
    // * S-length: 1-byte length descriptor of the S value that follows.
    // * S: arbitrary-length big-endian encoded S value. The same rules apply.
    // * sighash: 1-byte value indicating what data is hashed (not part of the DER
    //   signature)

    // Minimum and maximum size constraints.
    if (sig.size() < 9) return false;
    if (sig.size() > 73) return false;

    // A signature is of type 0x30 (compound).
    if (sig[0] != 0x30) return false;

    // Make sure the length covers the entire signature.
    if (sig[1] != sig.size() - 3) return false;

    // Extract the length of the R element.
    unsigned int lenR = sig[3];

    // Make sure the length of the S element is still inside the signature.
    if (5 + lenR >= sig.size()) return false;

    // Extract the length of the S element.
    unsigned int lenS = sig[5 + lenR];

    // Verify that the length of the signature matches the sum of the length
    // of the elements.
    if ((size_t)(lenR + lenS + 7) != sig.size()) return false;
 
    // Check whether the R element is an integer.
    if (sig[2] != 0x02) return false;

    // Zero-length integers are not allowed for R.
    if (lenR == 0) return false;

    // Negative numbers are not allowed for R.
    if (sig[4] & 0x80) return false;

    // Null bytes at the start of R are not allowed, unless R would
    // otherwise be interpreted as a negative number.
    if (lenR > 1 && (sig[4] == 0x00) && !(sig[5] & 0x80)) return false;

    // Check whether the S element is an integer.
    if (sig[lenR + 4] != 0x02) return false;

    // Zero-length integers are not allowed for S.
    if (lenS == 0) return false;

    // Negative numbers are not allowed for S.
    if (sig[lenR + 6] & 0x80) return false;

    // Null bytes at the start of S are not allowed, unless S would otherwise be
    // interpreted as a negative number.
    if (lenS > 1 && (sig[lenR + 6] == 0x00) && !(sig[lenR + 7] & 0x80)) return false;

    return true;
}

bool static IsLowDERSignature(const valtype &vchSig, ScriptError* serror) {
    if (!IsValidSignatureEncoding(vchSig)) {
        return set_error(serror, SCRIPT_ERR_SIG_DER);
    }
    std::vector<unsigned char> vchSigCopy(vchSig.begin(), vchSig.begin() + vchSig.size() - 1);
    if (!CPubKey::CheckLowS(vchSigCopy)) {
        return set_error(serror, SCRIPT_ERR_SIG_HIGH_S);
    }
    return true;
}

bool static IsDefinedHashtypeSignature(const valtype &vchSig) {
    if (vchSig.size() == 0) {
        return false;
    }
    unsigned char nHashType = vchSig[vchSig.size() - 1] & (~(SIGHASH_ANYONECANPAY));
    if (nHashType < SIGHASH_ALL || nHashType > SIGHASH_SINGLE)
        return false;

    return true;
}

bool CheckSignatureEncoding(const vector<unsigned char> &vchSig, unsigned int flags, ScriptError* serror) {
    // Empty signature. Not strictly DER encoded, but allowed to provide a
    // compact way to provide an invalid signature for use with CHECK(MULTI)SIG
    if (vchSig.size() == 0) {
        return true;
    }
    if ((flags & (SCRIPT_VERIFY_DERSIG | SCRIPT_VERIFY_LOW_S | SCRIPT_VERIFY_STRICTENC)) != 0 && !IsValidSignatureEncoding(vchSig)) {
        return set_error(serror, SCRIPT_ERR_SIG_DER);
    } else if ((flags & SCRIPT_VERIFY_LOW_S) != 0 && !IsLowDERSignature(vchSig, serror)) {
        // serror is set
        return false;
    } else if ((flags & SCRIPT_VERIFY_STRICTENC) != 0 && !IsDefinedHashtypeSignature(vchSig)) {
        return set_error(serror, SCRIPT_ERR_SIG_HASHTYPE);
    }
    return true;
}

bool static CheckPubKeyEncoding(const valtype &vchPubKey, unsigned int flags, const SigVersion &sigversion, ScriptError* serror) {
    if (sigversion == SIGVERSION_WITNESS_V1) {
        if (!vchPubKey.empty() && !IsKnownKeyVersion(vchPubKey)) {
            if (flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM)
                return set_error(serror, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_KEYVERSION);
            return true;
        }
        if (!IsCompressedPubKey(vchPubKey))
            return set_error(serror, SCRIPT_ERR_WITNESS_PUBKEYTYPE);
    }
    if ((flags & SCRIPT_VERIFY_STRICTENC) != 0 && !IsCompressedOrUncompressedPubKey(vchPubKey)) {
        return set_error(serror, SCRIPT_ERR_PUBKEYTYPE);
    }
    // Only compressed keys are accepted in segwit
    if ((flags & SCRIPT_VERIFY_WITNESS_PUBKEYTYPE) != 0 && sigversion == SIGVERSION_WITNESS_V0 && !IsCompressedPubKey(vchPubKey)) {
        return set_error(serror, SCRIPT_ERR_WITNESS_PUBKEYTYPE);
    }
    return true;
}

bool static CheckMinimalPush(const valtype& data, opcodetype opcode) {
    if (data.size() == 0) {
        // Could have used OP_0.
        return opcode == OP_0;
    } else if (data.size() == 1 && data[0] >= 1 && data[0] <= 16) {
        // Could have used OP_1 .. OP_16.
        return opcode == OP_1 + (data[0] - 1);
    } else if (data.size() == 1 && data[0] == 0x81) {
        // Could have used OP_1NEGATE.
        return opcode == OP_1NEGATE;
    } else if (data.size() <= 75) {
        // Could have used a direct push (opcode indicating number of bytes pushed + those bytes).
        return opcode == data.size();
    } else if (data.size() <= 255) {
        // Could have used OP_PUSHDATA.
        return opcode == OP_PUSHDATA1;
    } else if (data.size() <= 65535) {
        // Could have used OP_PUSHDATA2.
        return opcode == OP_PUSHDATA2;
    }
    return true;
}

void VchRShift(valtype &vch1, int bits, bool fsigned) {
    int full_bytes = bits / 8;
    bits = bits % 8;
    valtype vch2;
    vch2.insert(vch2.begin(), vch1.begin() + full_bytes, vch1.end());

    uint16_t temp = 0;
    for (int i=(vch2.size()-1);i>=0;--i) {
        temp = (vch2[i] << (8 - bits)) | ((temp << 8) & 0xff00);
        vch2[i] = (temp & 0xff00) >> 8;
    }

    // 0x0fff >> 4 == 0x00ff or 0xff, reduce to minimal representation
    while (!vch2.empty() && vch2.back() == 0)
        vch2.pop_back();
    if (fsigned && vch2.back() & 0x80)
        vch2.push_back(0);
    vch1 = vch2;
}

void VchLShift(valtype &vch1, int bits, bool fsigned) {
    int full_bytes = bits / 8;
    bits = bits % 8;
    valtype vch2;
    vch2.reserve(vch1.size() + full_bytes + 1);
    vch2.insert(vch2.end(), full_bytes, 0);
    vch2.insert(vch2.end(), vch1.begin(), vch1.end());
    vch2.insert(vch2.end(), 1, 0);

    uint16_t temp = 0;
    for (size_t i=0;i<vch2.size();++i) {
        temp = (vch2[i] << bits) | (temp >> 8);
        vch2[i] = temp & 0xff;
    }

    // reduce to minimal representation
    while (!vch2.empty() && vch2.back() == 0)
        vch2.pop_back();
    if (fsigned && vch2.back() & 0x80)
        vch2.push_back(0);
    vch1 = vch2;
}

bool ToDERSig(vector<unsigned char>& vchSig, unsigned int& nHashType, unsigned int& nOut, ScriptError* serror)
{
    nHashType = 0;
    nOut = 0;
    if (vchSig.empty())
        return true;
    if (vchSig.size() < 64 || vchSig.size() > 68)
        return set_error(serror, SCRIPT_ERR_SIG_HASHTYPE);
    if (vchSig.size() >= 65) {
        if (vchSig.back() == 0)
            return set_error(serror, SCRIPT_ERR_SIG_HASHTYPE);
        nHashType = vchSig[64];
        if ((nHashType & SIGHASHV2_INVALID) == SIGHASHV2_INVALID && (nHashType & SIGHASHV2_ALLINPUT_ALLSEQUENCE) != SIGHASHV2_ALLINPUT_ALLSEQUENCE)
            return set_error(serror, SCRIPT_ERR_SIG_HASHTYPE);
        if (vchSig.size() >= 66) {
            nHashType |= static_cast<uint32_t>(vchSig[65]) << 8;
            if (vchSig.size() >= 67) {
                // Unless it is signing for SINGLEOUTPUT or DUALOUTPUT, maximum signature size is 66
                if ((nHashType & 0xc000) != SIGHASHV2_DUALOUTPUT && (nHashType & 0xc000) != SIGHASHV2_SINGLEOUTPUT)
                    return set_error(serror, SCRIPT_ERR_SIG_HASHTYPE);
                for (size_t i = 66; i < vchSig.size(); i++)
                    nOut |= static_cast<uint32_t>(vchSig[i]) << (8 * (i - 66));
            }
        }
    }

    valtype r, s;
    if (vchSig[0] & 0x80)
        r.push_back(0);
    if (vchSig[32] & 0x80)
        return set_error(serror, SCRIPT_ERR_SIG_HIGH_S);
    r.insert(r.end(), vchSig.begin(), vchSig.begin() + 32);
    s.insert(s.begin(), vchSig.begin() + 32, vchSig.begin() + 64);
    while(r.size() >= 2 && r[0] == 0 && !(r[1] & 0x80))
        r.erase(r.begin());
    while(s.size() >= 2 && s[0] == 0 && !(s[1] & 0x80))
        s.erase(s.begin());
    unsigned char rlen = r.size();
    unsigned char slen = s.size();
    unsigned char tlen = rlen + slen + 4;
    valtype sig = {0x30, tlen, 0x02, rlen};
    sig.insert(sig.end(), r.begin(), r.end());
    sig.push_back(0x02);
    sig.push_back(slen);
    sig.insert(sig.end(), s.begin(), s.end());
    vchSig = sig;
    sig.push_back(0x01);
    if (!IsLowDERSignature(sig, serror))
        return false;
    return true;
}

bool EvalScript(vector<vector<unsigned char> >& stack, const CScript& script, unsigned int flags, const BaseSignatureChecker& checker, SigVersion sigversion, ScriptError* serror)
{
    int nOpCount = 0;
    CScript prevScript = CScript();
    uint256 hashScript;
    std::vector<CScript> sigScriptCode;
    unsigned int fSigScriptCodeUncommitted = 0;
    return EvalScript(stack, script, flags, checker, sigversion, nOpCount, prevScript, hashScript, sigScriptCode, 0, fSigScriptCodeUncommitted, serror);
}

bool EvalScript(vector<vector<unsigned char> >& stack, const CScript& script, unsigned int flags, const BaseSignatureChecker& checker, SigVersion sigversion, int& nOpCount, const CScript& prevScript, const uint256& hashScript, const std::vector<CScript>& sigScriptCode, const size_t& posSigScriptCode, unsigned int& fSigScriptCodeUncommitted, ScriptError* serror)
{
    static const CScriptNum bnZero(0);
    static const CScriptNum bnOne(1);
    static const CScriptNum bnFalse(0);
    static const CScriptNum bnTrue(1);
    static const valtype vchFalse(0);
    static const valtype vchZero(0);
    static const valtype vchTrue(1, 1);

    CScript::const_iterator pc = script.begin();
    CScript::const_iterator pend = script.end();
    CScript::const_iterator pbegincodehash = script.begin();
    opcodetype opcode;
    valtype vchPushValue;
    vector<bool> vfExec;
    vector<valtype> altstack;
    set_error(serror, SCRIPT_ERR_UNKNOWN_ERROR);
    if (script.size() > MAX_SCRIPT_SIZE)
        return set_error(serror, SCRIPT_ERR_SCRIPT_SIZE);
    bool fRequireMinimal = (flags & SCRIPT_VERIFY_MINIMALDATA) != 0;
    size_t sizeCScriptNum = (sigversion <= SIGVERSION_WITNESS_V0 ? 4 : 7);

    try
    {
        while (pc < pend)
        {
            bool fExec = !count(vfExec.begin(), vfExec.end(), false);

            //
            // Read instruction
            //
            if (!script.GetOp(pc, opcode, vchPushValue))
                return set_error(serror, SCRIPT_ERR_BAD_OPCODE);
            if (vchPushValue.size() > MAX_SCRIPT_ELEMENT_SIZE)
                return set_error(serror, SCRIPT_ERR_PUSH_SIZE);

            // Note how OP_RESERVED does not count towards the opcode limit.
            if (opcode > OP_16 && ++nOpCount > MAX_OPS_PER_SCRIPT)
                return set_error(serror, SCRIPT_ERR_OP_COUNT);

            if (sigversion <= SIGVERSION_WITNESS_V0 &&
               (opcode == OP_CAT ||
                opcode == OP_SUBSTR ||
                opcode == OP_LEFT ||
                opcode == OP_RIGHT ||
                opcode == OP_INVERT ||
                opcode == OP_AND ||
                opcode == OP_OR ||
                opcode == OP_XOR ||
                opcode == OP_2MUL ||
                opcode == OP_2DIV ||
                opcode == OP_MUL ||
                opcode == OP_DIV ||
                opcode == OP_MOD ||
                opcode == OP_LSHIFT ||
                opcode == OP_RSHIFT))
                return set_error(serror, SCRIPT_ERR_DISABLED_OPCODE); // Disabled opcodes.

            if (fExec && 0 <= opcode && opcode <= OP_PUSHDATA4) {
                if (fRequireMinimal && !CheckMinimalPush(vchPushValue, opcode)) {
                    return set_error(serror, SCRIPT_ERR_MINIMALDATA);
                }
                stack.push_back(vchPushValue);
            } else if (fExec && sigversion <= SIGVERSION_WITNESS_V0 && opcode > OP_NOP10) {
                return set_error(serror, SCRIPT_ERR_BAD_OPCODE);
            } else if (fExec || (OP_IF <= opcode && opcode <= OP_ENDIF))
            switch (opcode)
            {
                //
                // Push value
                //
                case OP_1NEGATE:
                case OP_1:
                case OP_2:
                case OP_3:
                case OP_4:
                case OP_5:
                case OP_6:
                case OP_7:
                case OP_8:
                case OP_9:
                case OP_10:
                case OP_11:
                case OP_12:
                case OP_13:
                case OP_14:
                case OP_15:
                case OP_16:
                {
                    // ( -- value)
                    CScriptNum bn((int)opcode - (int)(OP_1 - 1));
                    stack.push_back(bn.getvch());
                    // The result of these opcodes should always be the minimal way to push the data
                    // they push, so no need for a CheckMinimalPush here.
                }
                break;


                //
                // Control
                //
                case OP_NOP:
                    break;

                case OP_CHECKLOCKTIMEVERIFY:
                {
                    if (!(flags & SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY)) {
                        // not enabled; treat as a NOP2
                        if (flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS) {
                            return set_error(serror, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS);
                        }
                        break;
                    }

                    if (stack.size() < 1)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);

                    // Note that elsewhere numeric opcodes are limited to
                    // operands in the range -2**31+1 to 2**31-1, however it is
                    // legal for opcodes to produce results exceeding that
                    // range. This limitation is implemented by CScriptNum's
                    // default 4-byte limit.
                    //
                    // If we kept to that limit we'd have a year 2038 problem,
                    // even though the nLockTime field in transactions
                    // themselves is uint32 which only becomes meaningless
                    // after the year 2106.
                    //
                    // Thus as a special case we tell CScriptNum to accept up
                    // to 5-byte bignums, which are good until 2**39-1, well
                    // beyond the 2**32-1 limit of the nLockTime field itself.
                    const CScriptNum nLockTime(stacktop(-1), fRequireMinimal, 5);

                    // In the rare event that the argument may be < 0 due to
                    // some arithmetic being done first, you can always use
                    // 0 MAX CHECKLOCKTIMEVERIFY.
                    if (nLockTime < 0)
                        return set_error(serror, SCRIPT_ERR_NEGATIVE_LOCKTIME);

                    // Actually compare the specified lock time with the transaction.
                    if (!checker.CheckLockTime(nLockTime))
                        return set_error(serror, SCRIPT_ERR_UNSATISFIED_LOCKTIME);

                    if (sigversion == SIGVERSION_WITNESS_V1)
                        popstack(stack);

                    break;
                }

                case OP_CHECKSEQUENCEVERIFY:
                {
                    if (!(flags & SCRIPT_VERIFY_CHECKSEQUENCEVERIFY)) {
                        // not enabled; treat as a NOP3
                        if (flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS) {
                            return set_error(serror, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS);
                        }
                        break;
                    }

                    if (stack.size() < 1)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);

                    // nSequence, like nLockTime, is a 32-bit unsigned integer
                    // field. See the comment in CHECKLOCKTIMEVERIFY regarding
                    // 5-byte numeric operands.
                    const CScriptNum nSequence(stacktop(-1), fRequireMinimal, 5);

                    // In the rare event that the argument may be < 0 due to
                    // some arithmetic being done first, you can always use
                    // 0 MAX CHECKSEQUENCEVERIFY.
                    if (nSequence < 0)
                        return set_error(serror, SCRIPT_ERR_NEGATIVE_LOCKTIME);

                    // To provide for future soft-fork extensibility, if the
                    // operand has the disabled lock-time flag set,
                    // CHECKSEQUENCEVERIFY behaves as a NOP.
                    if ((nSequence & CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG) != 0)
                        break;

                    // Compare the specified sequence number with the input.
                    if (!checker.CheckSequence(nSequence))
                        return set_error(serror, SCRIPT_ERR_UNSATISFIED_LOCKTIME);

                    if (sigversion == SIGVERSION_WITNESS_V1)
                        popstack(stack);

                    break;
                }

                case OP_NOP1: case OP_NOP4: case OP_NOP5:
                case OP_NOP6: case OP_NOP7: case OP_NOP8: case OP_NOP9: case OP_NOP10:
                {
                    if (flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS)
                        return set_error(serror, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS);
                }
                break;

                case OP_IF:
                case OP_NOTIF:
                {
                    // <expression> if [statements] [else [statements]] endif
                    bool fValue = false;
                    if (fExec)
                    {
                        if (stack.size() < 1)
                            return set_error(serror, SCRIPT_ERR_UNBALANCED_CONDITIONAL);
                        valtype& vch = stacktop(-1);
                        if (sigversion == SIGVERSION_WITNESS_V0 && (flags & SCRIPT_VERIFY_MINIMALIF)) {
                            if (vch.size() > 1)
                                return set_error(serror, SCRIPT_ERR_MINIMALIF);
                            if (vch.size() == 1 && vch[0] != 1)
                                return set_error(serror, SCRIPT_ERR_MINIMALIF);
                        }
                        fValue = CastToBool(vch);
                        if (opcode == OP_NOTIF)
                            fValue = !fValue;
                        popstack(stack);
                    }
                    vfExec.push_back(fValue);
                }
                break;

                case OP_ELSE:
                {
                    if (vfExec.empty())
                        return set_error(serror, SCRIPT_ERR_UNBALANCED_CONDITIONAL);
                    vfExec.back() = !vfExec.back();
                }
                break;

                case OP_ENDIF:
                {
                    if (vfExec.empty())
                        return set_error(serror, SCRIPT_ERR_UNBALANCED_CONDITIONAL);
                    vfExec.pop_back();
                }
                break;

                case OP_VERIFY:
                {
                    // (true -- ) or
                    // (false -- false) and return
                    if (stack.size() < 1)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    bool fValue = CastToBool(stacktop(-1));
                    if (fValue)
                        popstack(stack);
                    else
                        return set_error(serror, SCRIPT_ERR_VERIFY);
                }
                break;

                case OP_RETURN:
                {
                    return set_error(serror, SCRIPT_ERR_OP_RETURN);
                }
                break;


                //
                // Stack ops
                //
                case OP_TOALTSTACK:
                {
                    if (stack.size() < 1)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    altstack.push_back(stacktop(-1));
                    popstack(stack);
                }
                break;

                case OP_FROMALTSTACK:
                {
                    if (altstack.size() < 1)
                        return set_error(serror, SCRIPT_ERR_INVALID_ALTSTACK_OPERATION);
                    stack.push_back(altstacktop(-1));
                    popstack(altstack);
                }
                break;

                case OP_SWAPSTACK:
                {
                    swap(stack, altstack);
                }

                case OP_2DROP:
                {
                    // (x1 x2 -- )
                    if (stack.size() < 2)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    popstack(stack);
                    popstack(stack);
                }
                break;

                case OP_2DUP:
                {
                    // (x1 x2 -- x1 x2 x1 x2)
                    if (stack.size() < 2)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    valtype vch1 = stacktop(-2);
                    valtype vch2 = stacktop(-1);
                    stack.push_back(vch1);
                    stack.push_back(vch2);
                }
                break;

                case OP_3DUP:
                {
                    // (x1 x2 x3 -- x1 x2 x3 x1 x2 x3)
                    if (stack.size() < 3)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    valtype vch1 = stacktop(-3);
                    valtype vch2 = stacktop(-2);
                    valtype vch3 = stacktop(-1);
                    stack.push_back(vch1);
                    stack.push_back(vch2);
                    stack.push_back(vch3);
                }
                break;

                case OP_2OVER:
                {
                    // (x1 x2 x3 x4 -- x1 x2 x3 x4 x1 x2)
                    if (stack.size() < 4)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    valtype vch1 = stacktop(-4);
                    valtype vch2 = stacktop(-3);
                    stack.push_back(vch1);
                    stack.push_back(vch2);
                }
                break;

                case OP_2ROT:
                {
                    // (x1 x2 x3 x4 x5 x6 -- x3 x4 x5 x6 x1 x2)
                    if (stack.size() < 6)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    valtype vch1 = stacktop(-6);
                    valtype vch2 = stacktop(-5);
                    stack.erase(stack.end()-6, stack.end()-4);
                    stack.push_back(vch1);
                    stack.push_back(vch2);
                }
                break;

                case OP_2SWAP:
                {
                    // (x1 x2 x3 x4 -- x3 x4 x1 x2)
                    if (stack.size() < 4)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    swap(stacktop(-4), stacktop(-2));
                    swap(stacktop(-3), stacktop(-1));
                }
                break;

                case OP_IFDUP:
                {
                    // (x - 0 | x x)
                    if (stack.size() < 1)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    valtype vch = stacktop(-1);
                    if (CastToBool(vch))
                        stack.push_back(vch);
                }
                break;

                case OP_DEPTH:
                {
                    // -- stacksize
                    CScriptNum bn(stack.size());
                    stack.push_back(bn.getvch());
                }
                break;

                case OP_DROP:
                {
                    // (x -- )
                    if (stack.size() < 1)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    popstack(stack);
                }
                break;

                case OP_DUP:
                {
                    // (x -- x x)
                    if (stack.size() < 1)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    valtype vch = stacktop(-1);
                    stack.push_back(vch);
                }
                break;

                case OP_NIP:
                {
                    // (x1 x2 -- x2)
                    if (stack.size() < 2)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    stack.erase(stack.end() - 2);
                }
                break;

                case OP_OVER:
                {
                    // (x1 x2 -- x1 x2 x1)
                    if (stack.size() < 2)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    valtype vch = stacktop(-2);
                    stack.push_back(vch);
                }
                break;

                case OP_PICK:
                case OP_ROLL:
                {
                    // (xn ... x2 x1 x0 n - xn ... x2 x1 x0 xn)
                    // (xn ... x2 x1 x0 n - ... x2 x1 x0 xn)
                    if (stack.size() < 2)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    int n = CScriptNum(stacktop(-1), fRequireMinimal).getint();
                    popstack(stack);
                    if (n < 0 || n >= (int)stack.size())
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    valtype vch = stacktop(-n-1);
                    if (opcode == OP_ROLL)
                        stack.erase(stack.end()-n-1);
                    stack.push_back(vch);
                }
                break;

                case OP_ROT:
                {
                    // (x1 x2 x3 -- x2 x3 x1)
                    //  x2 x1 x3  after first swap
                    //  x2 x3 x1  after second swap
                    if (stack.size() < 3)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    swap(stacktop(-3), stacktop(-2));
                    swap(stacktop(-2), stacktop(-1));
                }
                break;

                case OP_SWAP:
                {
                    // (x1 x2 -- x2 x1)
                    if (stack.size() < 2)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    swap(stacktop(-2), stacktop(-1));
                }
                break;

                case OP_TUCK:
                {
                    // (x1 x2 -- x2 x1 x2)
                    if (stack.size() < 2)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    valtype vch = stacktop(-1);
                    stack.insert(stack.end()-2, vch);
                }
                break;

                //
                // String operators
                //

                case OP_SIZE:
                {
                    // (in -- in size)
                    if (stack.size() < 1)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    CScriptNum bn(stacktop(-1).size());
                    stack.push_back(bn.getvch());
                }
                break;

                case OP_CAT:
                {
                    if (stack.size() < 2)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);

                    valtype vch1 = stacktop(-2);
                    valtype vch2 = stacktop(-1);

                    if (vch1.size() + vch2.size() > MAX_SCRIPT_ELEMENT_SIZE)
                        return set_error(serror, SCRIPT_ERR_PUSH_SIZE);

                    valtype vch3;
                    vch3.reserve(vch1.size() + vch2.size());
                    vch3.insert(vch3.end(), vch1.begin(), vch1.end());
                    vch3.insert(vch3.end(), vch2.begin(), vch2.end());

                    popstack(stack);
                    popstack(stack);
                    stack.push_back(vch3);
                }
                break;

                case OP_SUBSTR:
                {
                    if (stack.size() < 3)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);

                    valtype vch1 = stacktop(-3);
                    CScriptNum start(stacktop(-2), fRequireMinimal);
                    CScriptNum length(stacktop(-1), fRequireMinimal);

                    if (length < 0 || start < 0 || length > vch1.size() || start > vch1.size())
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    if ((start + length) > vch1.size())
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);

                    valtype vch2;
                    if (length == 0)
                        vch2 = vchZero;
                    else
                        vch2.insert(vch2.begin(), vch1.begin() + start.getint(), vch1.begin() + (start + length).getint());

                    popstack(stack);
                    popstack(stack);
                    popstack(stack);
                    stack.push_back(vch2);
                }
                break;

                case OP_LEFT:
                case OP_RIGHT:
                {
                    if (stack.size() < 2)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);

                    valtype vch1 = stacktop(-2);
                    CScriptNum start(stacktop(-1), fRequireMinimal);

                    if (start < 0)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);

                    valtype vch2;
                    switch (opcode) {
                        case OP_RIGHT:
                        {
                            if (start >= vch1.size())
                                vch2 = vchZero;
                            else if (start == 0)
                                vch2 = vch1;
                            else
                                vch2.insert(vch2.begin(), vch1.begin() + start.getint(), vch1.end());
                            break;
                        }
                        case OP_LEFT:
                        {
                            if (start >= vch1.size())
                                vch2 = vch1;
                            else if (start == 0)
                                vch2 = vchZero;
                            else
                                vch2.insert(vch2.begin(), vch1.begin(), vch1.begin() + start.getint());
                            break;
                        }
                        default:
                        {
                            assert(!"invalid opcode");
                            break;
                        }
                    }
                    popstack(stack);
                    popstack(stack);
                    stack.push_back(vch2);
                }
                break;

                //
                // Bitwise logic
                //
                case OP_INVERT:
                {
                    // (in - out)
                    if (stack.size() < 1)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    valtype& vch = stacktop(-1);
                    for (size_t i = 0; i < vch.size(); i++)
                        vch[i] = ~vch[i];
                }
                break;

                case OP_AND:
                case OP_OR:
                case OP_XOR:
                {
                    // (x1 x2 -- out)
                    if (stack.size() < 2)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    valtype& vch1 = stacktop(-1);
                    valtype& vch2 = stacktop(-2);
                    if (vch1.size() != vch2.size())
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);

                    valtype vch3(vch1);

                    if (opcode == OP_AND) {
                        for (size_t i = 0; i < vch1.size(); i++)
                            vch3[i] &= vch2[i];
                    }
                    else if (opcode == OP_OR) {
                        for (size_t i = 0; i < vch1.size(); i++)
                            vch3[i] |= vch2[i];
                    }
                    else if (opcode == OP_XOR) {
                        for (size_t i = 0; i < vch1.size(); i++)
                            vch3[i] ^= vch2[i];
                    }

                    popstack(stack);
                    popstack(stack);
                    stack.push_back(vch3);
                }
                break;

                case OP_EQUAL:
                case OP_EQUALVERIFY:
                //case OP_NOTEQUAL: // use OP_NUMNOTEQUAL
                {
                    // (x1 x2 - bool)
                    if (stack.size() < 2)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    valtype& vch1 = stacktop(-2);
                    valtype& vch2 = stacktop(-1);
                    bool fEqual = (vch1 == vch2);
                    // OP_NOTEQUAL is disabled because it would be too easy to say
                    // something like n != 1 and have some wiseguy pass in 1 with extra
                    // zero bytes after it (numerically, 0x01 == 0x0001 == 0x000001)
                    //if (opcode == OP_NOTEQUAL)
                    //    fEqual = !fEqual;
                    popstack(stack);
                    popstack(stack);
                    stack.push_back(fEqual ? vchTrue : vchFalse);
                    if (opcode == OP_EQUALVERIFY)
                    {
                        if (fEqual)
                            popstack(stack);
                        else
                            return set_error(serror, SCRIPT_ERR_EQUALVERIFY);
                    }
                }
                break;

                case OP_RSHIFT:
                {
                    if (stack.size() < 2)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    valtype vch1 = stacktop(-2);
                    CScriptNum bn(stacktop(-1), fRequireMinimal);

                    if (bn < 0)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);

                    popstack(stack);
                    popstack(stack);

                    if (bn >= vch1.size() * 8) {
                        stack.push_back(vchZero);
                        break;
                    }

                    VchRShift(vch1, bn.getint(), false);
                    stack.push_back(vch1);
                }
                break;

                case OP_LSHIFT:
                {
                    if (stack.size() < 2)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    valtype vch1 = stacktop(-2);
                    CScriptNum bn(stacktop(-1), fRequireMinimal);

                    if (bn < 0)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);

                    if (bn > 8 * MAX_SCRIPT_ELEMENT_SIZE)
                        return set_error(serror, SCRIPT_ERR_PUSH_SIZE);

                    VchLShift(vch1, bn.getint(), false);
                    if (vch1.size() > MAX_SCRIPT_ELEMENT_SIZE)
                        return set_error(serror, SCRIPT_ERR_PUSH_SIZE);
                    popstack(stack);
                    popstack(stack);
                    stack.push_back(vch1);
                }
                break;

                //
                // Numeric
                //
                case OP_1ADD:
                case OP_1SUB:
                case OP_2MUL:
                case OP_NEGATE:
                case OP_ABS:
                case OP_NOT:
                case OP_0NOTEQUAL:
                {
                    // (in -- out)
                    if (stack.size() < 1)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    CScriptNum bn(stacktop(-1), fRequireMinimal, sizeCScriptNum);
                    switch (opcode)
                    {
                    case OP_1ADD:       bn += bnOne; break;
                    case OP_1SUB:       bn -= bnOne; break;
                    case OP_2MUL:       bn = bn + bn; break;
                    case OP_NEGATE:     bn = -bn; break;
                    case OP_ABS:        if (bn < bnZero) bn = -bn; break;
                    case OP_NOT:        bn = (bn == bnZero); break;
                    case OP_0NOTEQUAL:  bn = (bn != bnZero); break;
                    default:            assert(!"invalid opcode"); break;
                    }
                    popstack(stack);
                    stack.push_back(bn.getvch());
                    if (stacktop(-1).size() > sizeCScriptNum && sigversion == SIGVERSION_WITNESS_V1)
                        return set_error(serror, SCRIPT_ERR_NUM_PUSH_SIZE);
                }
                break;

                case OP_ADD:
                case OP_SUB:
                case OP_BOOLAND:
                case OP_BOOLOR:
                case OP_NUMEQUAL:
                case OP_NUMEQUALVERIFY:
                case OP_NUMNOTEQUAL:
                case OP_LESSTHAN:
                case OP_GREATERTHAN:
                case OP_LESSTHANOREQUAL:
                case OP_GREATERTHANOREQUAL:
                case OP_MIN:
                case OP_MAX:
                {
                    // (x1 x2 -- out)
                    if (stack.size() < 2)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    CScriptNum bn1(stacktop(-2), fRequireMinimal, sizeCScriptNum);
                    CScriptNum bn2(stacktop(-1), fRequireMinimal, sizeCScriptNum);
                    CScriptNum bn(0);
                    switch (opcode)
                    {
                    case OP_ADD:
                        bn = bn1 + bn2;
                        break;

                    case OP_SUB:
                        bn = bn1 - bn2;
                        break;

                    case OP_BOOLAND:             bn = (bn1 != bnZero && bn2 != bnZero); break;
                    case OP_BOOLOR:              bn = (bn1 != bnZero || bn2 != bnZero); break;
                    case OP_NUMEQUAL:            bn = (bn1 == bn2); break;
                    case OP_NUMEQUALVERIFY:      bn = (bn1 == bn2); break;
                    case OP_NUMNOTEQUAL:         bn = (bn1 != bn2); break;
                    case OP_LESSTHAN:            bn = (bn1 < bn2); break;
                    case OP_GREATERTHAN:         bn = (bn1 > bn2); break;
                    case OP_LESSTHANOREQUAL:     bn = (bn1 <= bn2); break;
                    case OP_GREATERTHANOREQUAL:  bn = (bn1 >= bn2); break;
                    case OP_MIN:                 bn = (bn1 < bn2 ? bn1 : bn2); break;
                    case OP_MAX:                 bn = (bn1 > bn2 ? bn1 : bn2); break;
                    default:                     assert(!"invalid opcode"); break;
                    }
                    popstack(stack);
                    popstack(stack);
                    stack.push_back(bn.getvch());

                    if (stacktop(-1).size() > sizeCScriptNum && sigversion == SIGVERSION_WITNESS_V1)
                        return set_error(serror, SCRIPT_ERR_NUM_PUSH_SIZE);
                    if (opcode == OP_NUMEQUALVERIFY)
                    {
                        if (CastToBool(stacktop(-1)))
                            popstack(stack);
                        else
                            return set_error(serror, SCRIPT_ERR_NUMEQUALVERIFY);
                    }
                }
                break;

                case OP_WITHIN:
                {
                    // (x min max -- out)
                    if (stack.size() < 3)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    CScriptNum bn1(stacktop(-3), fRequireMinimal, sizeCScriptNum);
                    CScriptNum bn2(stacktop(-2), fRequireMinimal, sizeCScriptNum);
                    CScriptNum bn3(stacktop(-1), fRequireMinimal, sizeCScriptNum);
                    bool fValue = (bn2 <= bn1 && bn1 < bn3);
                    popstack(stack);
                    popstack(stack);
                    popstack(stack);
                    stack.push_back(fValue ? vchTrue : vchFalse);
                }
                break;

                case OP_MUL:
                {
                    if (stack.size() < 2)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    if (stacktop(-1).size() > stacktop(-2).size())
                        swap(stacktop(-2), stacktop(-1));

                    CScriptNum bn1(stacktop(-2), fRequireMinimal, 7);
                    CScriptNum bn2(stacktop(-1), fRequireMinimal, 4);
                    CScriptNum bn(0);
                    bool negative = false;

                    popstack(stack);
                    popstack(stack);
                    if (bn1 == bnZero || bn2 == bnZero) {
                        stack.push_back(vchZero);
                        break;
                    }
                    if (bn1 < bnZero) {
                        negative = !negative;
                        bn1 = -bn1;
                    }
                    if (bn2 < bnZero) {
                        negative = !negative;
                        bn2 = -bn2;
                    }

                    const int multipier = bn2.getint();
                    const valtype vch = bn1.getvch();
                    for (unsigned int i = 0; i < 31; ++i) {
                        if ((1U << i) & multipier) {
                            valtype vchtmp = vch;
                            VchLShift(vchtmp, i, true);
                            if (vchtmp.size() > 7)
                                return set_error(serror, SCRIPT_ERR_NUM_PUSH_SIZE);
                            bn += CScriptNum(vchtmp, false, 7);
                        }
                    }

                    if (negative)
                        bn = -bn;

                    stack.push_back(bn.getvch());
                    if (stacktop(-1).size() > 7)
                        return set_error(serror, SCRIPT_ERR_NUM_PUSH_SIZE);
                }
                break;

                case OP_2DIV:
                case OP_DIV:
                case OP_MOD:
                {
                    if (opcode == OP_2DIV) {
                        CScriptNum bnTwo(2);
                        stack.push_back(bnTwo.getvch());
                    }
                    if (stack.size() < 2)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    CScriptNum bn1(stacktop(-2), fRequireMinimal, 7);
                    CScriptNum bn2(stacktop(-1), fRequireMinimal, 7);
                    CScriptNum bn(0);
                    bool negativediv = false;
                    bool negativemod = false;

                    if (bn2 == bnZero)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);

                    if (bn1 < bnZero) {
                        negativediv = !negativediv;
                        negativemod = !negativemod;
                        bn1 = -bn1;
                    }
                    if (bn2 < bnZero) {
                        negativediv = !negativediv;
                        bn2 = -bn2;
                    }
                    if (bn1 > bn2) {
                        int maskshift = 0;
                        while (bn2 < bn1) {
                            valtype vch = bn2.getvch();
                            VchLShift(vch, 1, true);
                            bn2 = CScriptNum(vch, false, 8);
                            maskshift++;
                        }
                        valtype vchMask = bnOne.getvch();
                        VchLShift(vchMask, maskshift, true);
                        CScriptNum bnMask(vchMask, false, 8);
                        while (bnMask > 0) {
                            if (bn1 >= bn2) {
                                bn1 -= bn2;
                                bn += bnMask;
                            }
                            valtype vch2 = bn2.getvch();
                            VchRShift(vchMask, 1, true);
                            bnMask = CScriptNum(vchMask, false, 7);
                            VchRShift(vch2, 1, true);
                            bn2 = CScriptNum(vch2, false, 7);
                        }
                    }
                    else if (bn1 == bn2) {
                        bn = 1;
                        bn1 = 0;
                    }
                    if (negativediv)
                        bn = -bn;
                    if (negativemod)
                        bn1 = -bn1;

                    popstack(stack);
                    popstack(stack);
                    if (opcode == OP_MOD)
                        stack.push_back(bn1.getvch());
                    else
                        stack.push_back(bn.getvch());
                }
                break;

                //
                // Crypto
                //
                case OP_RIPEMD160:
                case OP_SHA1:
                case OP_SHA256:
                case OP_HASH160:
                case OP_HASH256:
                {
                    // (in -- hash)
                    if (stack.size() < 1)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    valtype& vch = stacktop(-1);
                    valtype vchHash((opcode == OP_RIPEMD160 || opcode == OP_SHA1 || opcode == OP_HASH160) ? 20 : 32);
                    if (opcode == OP_RIPEMD160)
                        CRIPEMD160().Write(begin_ptr(vch), vch.size()).Finalize(begin_ptr(vchHash));
                    else if (opcode == OP_SHA1)
                        CSHA1().Write(begin_ptr(vch), vch.size()).Finalize(begin_ptr(vchHash));
                    else if (opcode == OP_SHA256)
                        CSHA256().Write(begin_ptr(vch), vch.size()).Finalize(begin_ptr(vchHash));
                    else if (opcode == OP_HASH160)
                        CHash160().Write(begin_ptr(vch), vch.size()).Finalize(begin_ptr(vchHash));
                    else if (opcode == OP_HASH256)
                        CHash256().Write(begin_ptr(vch), vch.size()).Finalize(begin_ptr(vchHash));
                    popstack(stack);
                    stack.push_back(vchHash);
                }
                break;

                case OP_CODESEPARATOR:
                {
                    // Hash starts after the code separator
                    pbegincodehash = pc;
                }
                break;

                case OP_CHECKSIG:
                case OP_CHECKSIGVERIFY:
                {
                    // (sig pubkey -- bool)
                    if (stack.size() < 2)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);

                    valtype& vchSig    = stacktop(-2);
                    valtype& vchPubKey = stacktop(-1);
                    bool fSuccess = false;

                    // Subset of script starting at the most recent codeseparator
                    CScript scriptCode(pbegincodehash, pend);

                    // Drop the signature in pre-segwit scripts but not segwit scripts
                    if (sigversion == SIGVERSION_BASE) {
                        scriptCode.FindAndDelete(CScript(vchSig));
                    }

                    if (sigversion == SIGVERSION_WITNESS_V1) {
                        unsigned int nHashType = 0;
                        unsigned int nOut = 0;
                        if (!CheckPubKeyEncoding(vchPubKey, flags, sigversion, serror))
                            return false;
                        if (!IsKnownKeyVersion(vchPubKey)) {
                            fSuccess = true;
                            nHashType = 0x3f00;
                        }
                        else if (!ToDERSig(vchSig, nHashType, nOut, serror))
                            return false;

                        if (!fSuccess)
                            fSuccess = checker.CheckSig(vchSig, vchPubKey, scriptCode, sigversion, prevScript, hashScript, sigScriptCode, nHashType, nOut);

                        if (!fSuccess && vchSig.size())
                            return set_error(serror, SCRIPT_ERR_SIG_NULLFAIL);

                        if (fSuccess) {
                            unsigned int mask = (1U << posSigScriptCode) - 1;
                            fSigScriptCodeUncommitted &= ~((nHashType >> 8) & mask);
                        }
                    }
                    else {
                        if (!CheckSignatureEncoding(vchSig, flags, serror) || !CheckPubKeyEncoding(vchPubKey, flags, sigversion, serror)) {
                            //serror is set
                            return false;
                        }
                        fSuccess = checker.CheckSig(vchSig, vchPubKey, scriptCode, sigversion, prevScript, hashScript, sigScriptCode, 0, 0);

                        if (!fSuccess && (flags & SCRIPT_VERIFY_NULLFAIL) && vchSig.size())
                            return set_error(serror, SCRIPT_ERR_SIG_NULLFAIL);
                    }

                    popstack(stack);
                    popstack(stack);
                    stack.push_back(fSuccess ? vchTrue : vchFalse);
                    if (opcode == OP_CHECKSIGVERIFY)
                    {
                        if (fSuccess)
                            popstack(stack);
                        else
                            return set_error(serror, SCRIPT_ERR_CHECKSIGVERIFY);
                    }
                }
                break;

                case OP_CHECKSIGFROMSTACKVERIFY:
                {
                    // (sig hash pubkey  -- )
                    if (stack.size() < 3)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);

                    valtype vchSig    = stacktop(-3);
                    valtype vchHash   = stacktop(-2);
                    valtype vchPubKey = stacktop(-1);

                    if (!CheckPubKeyEncoding(vchPubKey, flags, sigversion, serror))
                        return false;

                    if (IsKnownKeyVersion(vchPubKey)) {
                        CPubKey pubkey(vchPubKey);

                        if (vchHash.size() != 32)
                            return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                        uint256 hash(vchHash);

                        if (vchSig.size() != 64)
                            return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                        unsigned int nHashType = 0;
                        unsigned int nOut = 0;
                        if (!ToDERSig(vchSig, nHashType, nOut, serror))
                            return false;

                        if (!pubkey.Verify(hash, vchSig))
                            return set_error(serror, SCRIPT_ERR_CHECKSIGVERIFY);
                    }

                    popstack(stack);
                    popstack(stack);
                    popstack(stack);
                }
                break;

                case OP_CHECKMULTISIG:
                case OP_CHECKMULTISIGVERIFY:
                {
                    // ([dummy/flag] [sig ...] num_of_signatures [pubkey ...] num_of_pubkeys -- bool)

                    int i = 1;
                    if ((int)stack.size() < i)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);

                    int nKeysCount = CScriptNum(stacktop(-i), fRequireMinimal).getint();
                    if (nKeysCount < 0 || nKeysCount > MAX_PUBKEYS_PER_MULTISIG)
                        return set_error(serror, SCRIPT_ERR_PUBKEY_COUNT);
                    int ikey = ++i;
                    // ikey2 is the position of last non-signature item in the stack. Top stack item = 1.
                    // With SCRIPT_VERIFY_NULLFAIL, this is used for cleanup if operation fails.
                    int ikey2 = nKeysCount + 2;
                    i += nKeysCount;
                    if ((int)stack.size() < i)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);

                    int nSigsCount = CScriptNum(stacktop(-i), fRequireMinimal).getint();
                    if (nSigsCount < 0 || nSigsCount > nKeysCount)
                        return set_error(serror, SCRIPT_ERR_SIG_COUNT);
                    if (sigversion != SIGVERSION_WITNESS_V1)
                        nOpCount += nKeysCount;
                    else
                        nOpCount += nSigsCount;
                    if (nOpCount > MAX_OPS_PER_SCRIPT)
                        return set_error(serror, SCRIPT_ERR_OP_COUNT);
                    int isig = ++i;
                    i += nSigsCount;
                    if ((int)stack.size() < i)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);

                    // Subset of script starting at the most recent codeseparator
                    CScript scriptCode(pbegincodehash, pend);

                    // Drop the signature in pre-segwit scripts but not segwit scripts
                    for (int k = 0; k < nSigsCount; k++)
                    {
                        valtype& vchSig = stacktop(-isig-k);
                        if (sigversion == SIGVERSION_BASE) {
                            scriptCode.FindAndDelete(CScript(vchSig));
                        }
                    }

                    bool fSuccess = true;

                    if (sigversion == SIGVERSION_WITNESS_V1) {
                        // The previous dummy item becomes a bitmap of used pubkeys, encoded as CScriptNum
                        int nFlag = CScriptNum(stacktop(-i), fRequireMinimal).getint();
                        if (nFlag < 0)
                            return set_error(serror, SCRIPT_ERR_CHECKMULTISIG_FLAGS);
                        else if (nFlag == 0 && nSigsCount > 0)
                            fSuccess = false;
                        unsigned int fSignedSigScriptCode = 0;
                        while (fSuccess && nFlag > 0) {
                            if (ikey >= ikey2) {
                                // ikey2 is the position for nSigsCount.
                                // ikey >= ikey2 means the flags are out of the range of public keys
                                return set_error(serror, SCRIPT_ERR_CHECKMULTISIG_FLAGS);
                            }

                            if (nFlag & 1) {
                                if (isig >= i) {
                                    // i is the position for the flag.
                                    // isig >= i means the number of set bits is more than number of signatures
                                    return set_error(serror, SCRIPT_ERR_CHECKMULTISIG_FLAGS);
                                }

                                valtype &vchSig = stacktop(-isig);
                                valtype &vchPubKey = stacktop(-ikey);
                                unsigned int nHashType = 0;
                                unsigned int nOut = 0;

                                if (!CheckPubKeyEncoding(vchPubKey, flags, sigversion, serror))
                                    return false;

                                if (!IsKnownKeyVersion(vchPubKey)) {
                                    // If the KEYVERSION is unknown, we skip validation and assume the signature
                                    // covers all sigScriptCode, which could be tightened in a later softfork
                                    fSignedSigScriptCode |= 0x3f;
                                }
                                else {
                                    if (!ToDERSig(vchSig, nHashType, nOut, serror))
                                        return false;
                                    if (!checker.CheckSig(vchSig, vchPubKey, scriptCode, sigversion, prevScript, hashScript, sigScriptCode, nHashType, nOut))
                                        return set_error(serror, SCRIPT_ERR_SIG_NULLFAIL);
                                    fSignedSigScriptCode |= ((nHashType >> 8) & 0x3f);
                                }
                                isig++;
                            }
                            nFlag >>= 1;
                            ikey++;
                        }

                        if (fSuccess && isig != i)
                            // Number of set bits is less than number of signatures
                            return set_error(serror, SCRIPT_ERR_CHECKMULTISIG_FLAGS);

                        while (i--) {
                            // If the operation failed, we require that all signatures and the flag must be empty vector
                            if (!fSuccess && !ikey2 && stacktop(-1).size())
                                return set_error(serror, SCRIPT_ERR_SIG_NULLFAIL);
                            if (ikey2 > 0)
                                ikey2--;
                            popstack(stack);
                        }
                        if (fSuccess) {
                            unsigned int mask = (1U << posSigScriptCode) - 1;
                            fSigScriptCodeUncommitted &= ~(fSignedSigScriptCode & mask);
                        }

                        stack.push_back(fSuccess ? vchTrue : vchFalse);

                        if (opcode == OP_CHECKMULTISIGVERIFY)
                        {
                            if (fSuccess)
                                popstack(stack);
                            else
                                return set_error(serror, SCRIPT_ERR_CHECKMULTISIGVERIFY);
                        }
                        break;
                    }

                    while (fSuccess && nSigsCount > 0)
                    {
                        valtype& vchSig    = stacktop(-isig);
                        valtype& vchPubKey = stacktop(-ikey);

                        // Note how this makes the exact order of pubkey/signature evaluation
                        // distinguishable by CHECKMULTISIG NOT if the STRICTENC flag is set.
                        // See the script_(in)valid tests for details.
                        if (!CheckSignatureEncoding(vchSig, flags, serror) || !CheckPubKeyEncoding(vchPubKey, flags, sigversion, serror)) {
                            // serror is set
                            return false;
                        }

                        // Check signature
                        bool fOk = checker.CheckSig(vchSig, vchPubKey, scriptCode, sigversion, prevScript, hashScript, sigScriptCode, 0, 0);

                        if (fOk) {
                            isig++;
                            nSigsCount--;
                        }
                        ikey++;
                        nKeysCount--;

                        // If there are more signatures left than keys left,
                        // then too many signatures have failed. Exit early,
                        // without checking any further signatures.
                        if (nSigsCount > nKeysCount)
                            fSuccess = false;
                    }

                    // Clean up stack of actual arguments
                    while (i-- > 1) {
                        // If the operation failed, we require that all signatures must be empty vector
                        if (!fSuccess && (flags & SCRIPT_VERIFY_NULLFAIL) && !ikey2 && stacktop(-1).size())
                            return set_error(serror, SCRIPT_ERR_SIG_NULLFAIL);
                        if (ikey2 > 0)
                            ikey2--;
                        popstack(stack);
                    }

                    // A bug causes CHECKMULTISIG to consume one extra argument
                    // whose contents were not checked in any way.
                    //
                    // Unfortunately this is a potential source of mutability,
                    // so optionally verify it is exactly equal to zero prior
                    // to removing it from the stack.
                    if (stack.size() < 1)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    if ((flags & SCRIPT_VERIFY_NULLDUMMY) && stacktop(-1).size())
                        return set_error(serror, SCRIPT_ERR_SIG_NULLDUMMY);
                    popstack(stack);

                    stack.push_back(fSuccess ? vchTrue : vchFalse);

                    if (opcode == OP_CHECKMULTISIGVERIFY)
                    {
                        if (fSuccess)
                            popstack(stack);
                        else
                            return set_error(serror, SCRIPT_ERR_CHECKMULTISIGVERIFY);
                    }
                }
                break;

                case OP_PUSHTXDATA:
                {
                    if (stack.size() < 1)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);

                    const CScriptNum nType(stacktop(-1), fRequireMinimal, 7);
                    popstack(stack);
                    if (nType < 0 || nType > 15)
                        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                    else if (nType <= 9) {
                        stack.push_back(checker.PushTxData(nType.getint(), 0));
                    }
                    else if (nType == 10) {
                        valtype vchHash(32);
                        memcpy(&vchHash[0], &hashScript, 32);
                        stack.push_back(vchHash);
                    }
                    else if (nType == 11) {
                        valtype vchScript(prevScript.size());
                        memcpy(&vchScript[0], &prevScript[0], prevScript.size());
                        stack.push_back(vchScript);
                    }
                    else {
                        if (stack.size() < 1)
                            return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                        CScriptNum nIndex(stacktop(-1), fRequireMinimal, 7);
                        popstack(stack);
                        if (nIndex < -1)
                            return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                        if (nIndex == -1)
                            nIndex = CScriptNum(checker.PushTxData(0, 0), false);
                        if (nType <= 14) {
                            if (nIndex >= CScriptNum(checker.PushTxData(1, 0), false))
                                return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                            if (nType != 13) {
                                stack.push_back(checker.PushTxData(13, nIndex.getint()));
                                stack.push_back(checker.PushTxData(10, nIndex.getint()));
                            }
                            if (nType >= 13)
                                stack.push_back(checker.PushTxData(11, nIndex.getint()));
                        }
                        else {
                            if (nIndex >= CScriptNum(checker.PushTxData(2, 0), false))
                                return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                            stack.push_back(checker.PushTxData(14, nIndex.getint()));
                            stack.push_back(checker.PushTxData(12, nIndex.getint()));
                        }
                    }
                }
                break;

                default:
                    return set_error(serror, SCRIPT_ERR_BAD_OPCODE);
            }

            // Size limits
            if (stack.size() + altstack.size() > 1000)
                return set_error(serror, SCRIPT_ERR_STACK_SIZE);
        }
    }
    catch (...)
    {
        return set_error(serror, SCRIPT_ERR_UNKNOWN_ERROR);
    }

    if (!vfExec.empty())
        return set_error(serror, SCRIPT_ERR_UNBALANCED_CONDITIONAL);

    return set_success(serror);
}

namespace {

/**
 * Wrapper that serializes like CTransaction, but with the modifications
 *  required for the signature hash done in-place
 */
class CTransactionSignatureSerializer {
private:
    const CTransaction& txTo;  //!< reference to the spending transaction (the one being serialized)
    const CScript& scriptCode; //!< output script being consumed
    const unsigned int nIn;    //!< input index of txTo being signed
    const bool fAnyoneCanPay;  //!< whether the hashtype has the SIGHASH_ANYONECANPAY flag set
    const bool fHashSingle;    //!< whether the hashtype is SIGHASH_SINGLE
    const bool fHashNone;      //!< whether the hashtype is SIGHASH_NONE

public:
    CTransactionSignatureSerializer(const CTransaction &txToIn, const CScript &scriptCodeIn, unsigned int nInIn, int nHashTypeIn) :
        txTo(txToIn), scriptCode(scriptCodeIn), nIn(nInIn),
        fAnyoneCanPay(!!(nHashTypeIn & SIGHASH_ANYONECANPAY)),
        fHashSingle((nHashTypeIn & 0x1f) == SIGHASH_SINGLE),
        fHashNone((nHashTypeIn & 0x1f) == SIGHASH_NONE) {}

    /** Serialize the passed scriptCode, skipping OP_CODESEPARATORs */
    template<typename S>
    void SerializeScriptCode(S &s, int nType, int nVersion) const {
        CScript::const_iterator it = scriptCode.begin();
        CScript::const_iterator itBegin = it;
        opcodetype opcode;
        unsigned int nCodeSeparators = 0;
        while (scriptCode.GetOp(it, opcode)) {
            if (opcode == OP_CODESEPARATOR)
                nCodeSeparators++;
        }
        ::WriteCompactSize(s, scriptCode.size() - nCodeSeparators);
        it = itBegin;
        while (scriptCode.GetOp(it, opcode)) {
            if (opcode == OP_CODESEPARATOR) {
                s.write((char*)&itBegin[0], it-itBegin-1);
                itBegin = it;
            }
        }
        if (itBegin != scriptCode.end())
            s.write((char*)&itBegin[0], it-itBegin);
    }

    /** Serialize an input of txTo */
    template<typename S>
    void SerializeInput(S &s, unsigned int nInput, int nType, int nVersion) const {
        // In case of SIGHASH_ANYONECANPAY, only the input being signed is serialized
        if (fAnyoneCanPay)
            nInput = nIn;
        // Serialize the prevout
        ::Serialize(s, txTo.vin[nInput].prevout, nType, nVersion);
        // Serialize the script
        if (nInput != nIn)
            // Blank out other inputs' signatures
            ::Serialize(s, CScriptBase(), nType, nVersion);
        else
            SerializeScriptCode(s, nType, nVersion);
        // Serialize the nSequence
        if (nInput != nIn && (fHashSingle || fHashNone))
            // let the others update at will
            ::Serialize(s, (int)0, nType, nVersion);
        else
            ::Serialize(s, txTo.vin[nInput].nSequence, nType, nVersion);
    }

    /** Serialize an output of txTo */
    template<typename S>
    void SerializeOutput(S &s, unsigned int nOutput, int nType, int nVersion) const {
        if (fHashSingle && nOutput != nIn)
            // Do not lock-in the txout payee at other indices as txin
            ::Serialize(s, CTxOut(), nType, nVersion);
        else
            ::Serialize(s, txTo.vout[nOutput], nType, nVersion);
    }

    /** Serialize txTo */
    template<typename S>
    void Serialize(S &s, int nType, int nVersion) const {
        // Serialize nVersion
        ::Serialize(s, txTo.nVersion, nType, nVersion);
        // Serialize vin
        unsigned int nInputs = fAnyoneCanPay ? 1 : txTo.vin.size();
        ::WriteCompactSize(s, nInputs);
        for (unsigned int nInput = 0; nInput < nInputs; nInput++)
             SerializeInput(s, nInput, nType, nVersion);
        // Serialize vout
        unsigned int nOutputs = fHashNone ? 0 : (fHashSingle ? nIn+1 : txTo.vout.size());
        ::WriteCompactSize(s, nOutputs);
        for (unsigned int nOutput = 0; nOutput < nOutputs; nOutput++)
             SerializeOutput(s, nOutput, nType, nVersion);
        // Serialize nLockTime
        ::Serialize(s, txTo.nLockTime, nType, nVersion);
    }
};

uint256 GetPrevoutHash(const CTransaction& txTo) {
    CHashWriter ss(SER_GETHASH, 0);
    for (unsigned int n = 0; n < txTo.vin.size(); n++) {
        ss << txTo.vin[n].prevout;
    }
    return ss.GetHash();
}

uint256 GetSequenceHash(const CTransaction& txTo) {
    CHashWriter ss(SER_GETHASH, 0);
    for (unsigned int n = 0; n < txTo.vin.size(); n++) {
        ss << txTo.vin[n].nSequence;
    }
    return ss.GetHash();
}

uint256 GetOutputsHash(const CTransaction& txTo) {
    CHashWriter ss(SER_GETHASH, 0);
    for (unsigned int n = 0; n < txTo.vout.size(); n++) {
        ss << txTo.vout[n];
    }
    return ss.GetHash();
}

} // anon namespace

PrecomputedTransactionData::PrecomputedTransactionData(const CTransaction& txTo)
{
    hashPrevouts = GetPrevoutHash(txTo);
    hashSequence = GetSequenceHash(txTo);
    hashOutputs = GetOutputsHash(txTo);
}

uint256 SignatureHash(const CPubKey& pubkey, const CScript& scriptCodeIn, const uint256& hashScriptIn, std::vector<CScript> sigScriptCode, const CTransaction& txTo, unsigned int nIn, const unsigned int& nOut, unsigned int nHashType, const CAmount& amountIn, const CAmount& nFeesIn, SigVersion sigversion, const PrecomputedTransactionData* cache)
{
    if (sigversion == SIGVERSION_WITNESS_V1) {
        // nSigVersion is 0x01000000 (witness v1) + 0x200000 (program size = 32) + 0 (MAST v0)
        // Each future version should have its unique nSigVersion > 255 to avoid collision with legacy signatures
        unsigned int nSigVersion = 0x01200000;
        uint256 hashPrevouts;
        uint256 hashSequence;
        uint256 hashOutputs;
        int32_t nVersion = (nHashType & SIGHASHV2_VERSION ? txTo.nVersion : -1);
        uint32_t nLockTime = (nHashType & SIGHASHV2_LOCKTIME ? txTo.nLockTime : 0xffffffff);
        uint32_t nSequence = (nHashType & SIGHASHV2_THISSEQUENCE ? txTo.vin[nIn].nSequence : 0xffffffff);
        uint256 hashScript = (nHashType & SIGHASHV2_KEYSCRIPTHASH ? hashScriptIn : uint256());
        CAmount nFees = (nHashType & SIGHASHV2_FEE ? nFeesIn : -1);
        CAmount amount = (nHashType & (SIGHASHV2_THISINPUT | SIGHASHV2_AMOUNT) ? amountIn : -1);
        CScript scriptPubKey = (nHashType & (SIGHASHV2_THISINPUT | SIGHASHV2_PROGRAM) ? scriptCodeIn : CScript());
        COutPoint prevout = (nHashType & SIGHASHV2_THISINPUT ? txTo.vin[nIn].prevout : COutPoint());

        if ((nHashType & SIGHASHV2_ALLINPUT) == SIGHASHV2_ALLINPUT)
            hashPrevouts = cache ? cache->hashPrevouts : GetPrevoutHash(txTo);

        if ((nHashType & SIGHASHV2_ALLINPUT_ALLSEQUENCE) == SIGHASHV2_ALLINPUT_ALLSEQUENCE)
            hashSequence = cache ? cache->hashSequence : GetSequenceHash(txTo);
        else if ((nHashType & SIGHASHV2_INVALID) == SIGHASHV2_INVALID)
            assert(false);

        if ((nHashType & SIGHASHV2_ALLOUTPUT) == SIGHASHV2_ALLOUTPUT) {
            hashOutputs = cache ? cache->hashOutputs : GetOutputsHash(txTo);
        }
        else if (nHashType & SIGHASHV2_DUALOUTPUT) {
            assert(nIn < txTo.vout.size() && nOut < txTo.vout.size() && nIn != nOut);
            CHashWriter ss(SER_GETHASH, 0);
            ss << txTo.vout[nOut] << txTo.vout[nIn];
            hashOutputs = ss.GetHash();
        }
        else if (nHashType & SIGHASHV2_SINGLEOUTPUT) {
            assert(nOut < txTo.vout.size());
            CHashWriter ss(SER_GETHASH, 0);
            ss << txTo.vout[nOut];
            hashOutputs = ss.GetHash();
        }

        CHashWriter ss(SER_GETHASH, 0);

        ss << nVersion << prevout;
        assert (sigScriptCode.size() == MAX_MAST_V0_SIGSCRIPTCODE);
        for (unsigned int i = 0; i < MAX_MAST_V0_SIGSCRIPTCODE; i++) {
            if (!(nHashType & (1U << (8 + i))))
                ss << static_cast<const CScriptBase&>(CScript());
            else
                ss << static_cast<const CScriptBase&>(sigScriptCode[i]);
        }
        ss << hashScript;
        ss << static_cast<const CScriptBase&>(scriptPubKey);
        ss << amount << nSequence << hashPrevouts << hashSequence << hashOutputs << nFees << nLockTime << nHashType << pubkey << nSigVersion;

        return ss.GetHash();
    }
    else if (sigversion == SIGVERSION_WITNESS_V0) {
        uint256 hashPrevouts;
        uint256 hashSequence;
        uint256 hashOutputs;

        if (!(nHashType & SIGHASH_ANYONECANPAY)) {
            hashPrevouts = cache ? cache->hashPrevouts : GetPrevoutHash(txTo);
        }

        if (!(nHashType & SIGHASH_ANYONECANPAY) && (nHashType & 0x1f) != SIGHASH_SINGLE && (nHashType & 0x1f) != SIGHASH_NONE) {
            hashSequence = cache ? cache->hashSequence : GetSequenceHash(txTo);
        }


        if ((nHashType & 0x1f) != SIGHASH_SINGLE && (nHashType & 0x1f) != SIGHASH_NONE) {
            hashOutputs = cache ? cache->hashOutputs : GetOutputsHash(txTo);
        } else if ((nHashType & 0x1f) == SIGHASH_SINGLE && nIn < txTo.vout.size()) {
            CHashWriter ss(SER_GETHASH, 0);
            ss << txTo.vout[nIn];
            hashOutputs = ss.GetHash();
        }

        CHashWriter ss(SER_GETHASH, 0);
        // Version
        ss << txTo.nVersion;
        // Input prevouts/nSequence (none/all, depending on flags)
        ss << hashPrevouts;
        ss << hashSequence;
        // The input being signed (replacing the scriptSig with scriptCode + amount)
        // The prevout may already be contained in hashPrevout, and the nSequence
        // may already be contain in hashSequence.
        ss << txTo.vin[nIn].prevout;
        ss << static_cast<const CScriptBase&>(scriptCodeIn);
        ss << amountIn;
        ss << txTo.vin[nIn].nSequence;
        // Outputs (none/one/all, depending on flags)
        ss << hashOutputs;
        // Locktime
        ss << txTo.nLockTime;
        // Sighash type
        ss << nHashType;

        return ss.GetHash();
    }

    static const uint256 one(uint256S("0000000000000000000000000000000000000000000000000000000000000001"));
    if (nIn >= txTo.vin.size()) {
        //  nIn out of range
        return one;
    }

    // Check for invalid use of SIGHASH_SINGLE
    if ((nHashType & 0x1f) == SIGHASH_SINGLE) {
        if (nIn >= txTo.vout.size()) {
            //  nOut out of range
            return one;
        }
    }

    // Wrapper to serialize only the necessary parts of the transaction being signed
    CTransactionSignatureSerializer txTmp(txTo, scriptCodeIn, nIn, nHashType);

    // Serialize and hash
    CHashWriter ss(SER_GETHASH, 0);
    ss << txTmp << nHashType;
    return ss.GetHash();
}

bool TransactionSignatureChecker::VerifySignature(const std::vector<unsigned char>& vchSig, const CPubKey& pubkey, const uint256& sighash) const
{
    return pubkey.Verify(sighash, vchSig);
}

bool TransactionSignatureChecker::CheckSig(const vector<unsigned char>& vchSigIn, const vector<unsigned char>& vchPubKey, const CScript& scriptCodeIn, SigVersion sigversion, const CScript& prevScript, const uint256& hashScript, const std::vector<CScript>& sigScriptCode, unsigned int nHashType, const unsigned int& nOut) const
{
    CPubKey pubkey(vchPubKey);
    if (!pubkey.IsValid())
        return false;

    vector<unsigned char> vchSig(vchSigIn);
    if (vchSig.empty())
        return false;
    if (sigversion != SIGVERSION_WITNESS_V1) {
        // Hash type is one byte tacked on to the end of the signature
        nHashType = vchSig.back();
        vchSig.pop_back();
    }
    else {
        if (nOut >= txTo->vout.size())
            return false;
        if ((nHashType & 0xc000) == SIGHASHV2_DUALOUTPUT) {
            if (nIn == nOut || nIn >= txTo->vout.size())
                return false;
        }
    }

    CScript scriptCode = (sigversion == SIGVERSION_WITNESS_V1 ? prevScript : scriptCodeIn);
    uint256 sighash = SignatureHash(pubkey, scriptCode, hashScript, sigScriptCode, *txTo, nIn, nOut, nHashType, amount, nFees, sigversion, this->txdata);

    if (!VerifySignature(vchSig, pubkey, sighash))
        return false;

    return true;
}

bool TransactionSignatureChecker::CheckLockTime(const CScriptNum& nLockTime) const
{
    // There are two kinds of nLockTime: lock-by-blockheight
    // and lock-by-blocktime, distinguished by whether
    // nLockTime < LOCKTIME_THRESHOLD.
    //
    // We want to compare apples to apples, so fail the script
    // unless the type of nLockTime being tested is the same as
    // the nLockTime in the transaction.
    if (!(
        (txTo->nLockTime <  LOCKTIME_THRESHOLD && nLockTime <  LOCKTIME_THRESHOLD) ||
        (txTo->nLockTime >= LOCKTIME_THRESHOLD && nLockTime >= LOCKTIME_THRESHOLD)
    ))
        return false;

    // Now that we know we're comparing apples-to-apples, the
    // comparison is a simple numeric one.
    if (nLockTime > (int64_t)txTo->nLockTime)
        return false;

    // Finally the nLockTime feature can be disabled and thus
    // CHECKLOCKTIMEVERIFY bypassed if every txin has been
    // finalized by setting nSequence to maxint. The
    // transaction would be allowed into the blockchain, making
    // the opcode ineffective.
    //
    // Testing if this vin is not final is sufficient to
    // prevent this condition. Alternatively we could test all
    // inputs, but testing just this input minimizes the data
    // required to prove correct CHECKLOCKTIMEVERIFY execution.
    if (CTxIn::SEQUENCE_FINAL == txTo->vin[nIn].nSequence)
        return false;

    return true;
}

bool TransactionSignatureChecker::CheckSequence(const CScriptNum& nSequence) const
{
    // Relative lock times are supported by comparing the passed
    // in operand to the sequence number of the input.
    const int64_t txToSequence = (int64_t)txTo->vin[nIn].nSequence;

    // Fail if the transaction's version number is not set high
    // enough to trigger BIP 68 rules.
    if (static_cast<uint32_t>(txTo->nVersion) < 2)
        return false;

    // Sequence numbers with their most significant bit set are not
    // consensus constrained. Testing that the transaction's sequence
    // number do not have this bit set prevents using this property
    // to get around a CHECKSEQUENCEVERIFY check.
    if (txToSequence & CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG)
        return false;

    // Mask off any bits that do not have consensus-enforced meaning
    // before doing the integer comparisons
    const uint32_t nLockTimeMask = CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG | CTxIn::SEQUENCE_LOCKTIME_MASK;
    const int64_t txToSequenceMasked = txToSequence & nLockTimeMask;
    const CScriptNum nSequenceMasked = nSequence & nLockTimeMask;

    // There are two kinds of nSequence: lock-by-blockheight
    // and lock-by-blocktime, distinguished by whether
    // nSequenceMasked < CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG.
    //
    // We want to compare apples to apples, so fail the script
    // unless the type of nSequenceMasked being tested is the same as
    // the nSequenceMasked in the transaction.
    if (!(
        (txToSequenceMasked <  CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG && nSequenceMasked <  CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG) ||
        (txToSequenceMasked >= CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG && nSequenceMasked >= CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG)
    )) {
        return false;
    }

    // Now that we know we're comparing apples-to-apples, the
    // comparison is a simple numeric one.
    if (nSequenceMasked > txToSequenceMasked)
        return false;

    return true;
}

std::vector<unsigned char> TransactionSignatureChecker::PushTxData(const int& nType, const int& nIndex) const
{
    //std::vector<unsigned char> vchFalse(0);
    CScriptNum bn(0);
    if (nType <= 12) {
        if (nType == 0)
            bn = nIn;
        else if (nType == 1)
            bn = txTo->vin.size();
        else if (nType == 2)
            bn = txTo->vout.size();
        else if (nType == 3)
            bn = amount;
        else if (nType == 4)
            bn = nFees;
        else if (nType == 5)
            bn = static_cast<uint32_t>(txTo->nVersion);
        else if (nType == 6)
            bn = txTo->nLockTime;
        else if (nType == 7)
            bn = ::GetSerializeSize(*txTo, SER_NETWORK, PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS);
        else if (nType == 8)
            bn = ::GetSerializeSize(*txTo, SER_NETWORK, PROTOCOL_VERSION);
        else if (nType == 9)
            bn = GetTransactionWeight(*txTo);
        else if (nType == 10)
            bn = txTo->vin[nIndex].prevout.n;
        else if (nType == 11)
            bn = txTo->vin[nIndex].nSequence;
        else
            bn = txTo->vout[nIndex].nValue;
        return bn.getvch();
    }
    else if (nType == 13) {
        valtype vchHash(32);
        memcpy(&vchHash[0], &txTo->vin[nIndex].prevout.hash, 32);
        return vchHash;
    }
    else if (nType == 14) {
        const CScript scriptPubKey = txTo->vout[nIndex].scriptPubKey;
        valtype vchScript(scriptPubKey.size());
        memcpy(&vchScript[0], &scriptPubKey[0], scriptPubKey.size());
        return vchScript;
    }
    return bn.getvch();
}

bool IsMASTStack(const CScriptWitness& witness, uint32_t& nMASTVersion, std::vector<uint256>& path, uint32_t& position, std::vector<std::vector<unsigned char> >& stack, std::vector<CScript>& keyScriptCode)
{
    size_t witstacksize = witness.stack.size();
    if (witstacksize < 4)
        return false;
    std::vector<unsigned char> metadata = witness.stack.back(); // The last witness stack item is metadata
    if (metadata.size() < 1 || metadata.size() > 5)
        return false;

    // The first byte of metadata is the number of keyScriptCode (1 to 255)
    uint32_t nKeyScriptCode = static_cast<uint32_t>(metadata[0]);
    if (nKeyScriptCode == 0 || witstacksize < nKeyScriptCode + 3)
        return false;

    // The rest of metadata is MAST version in minimally-coded unsigned little endian int
    nMASTVersion = 0;
    if (metadata.back() == 0)
        return false;
    if (metadata.size() > 1) {
        for (size_t i = 1; i != metadata.size(); ++i)
            nMASTVersion |= static_cast<uint32_t>(metadata[i]) << 8 * (i - 1);
    }

    // The second last witness stack item is the pathdata
    // Size of pathdata must be divisible by 32 (0 is allowed)
    // Depth of the Merkle tree is implied by the size of pathdata, and must not be greater than 32
    std::vector<unsigned char> pathdata = witness.stack.at(witstacksize - 2);
    if (pathdata.size() & 0x1F)
        return false;
    unsigned int depth = pathdata.size() >> 5;
    if (depth > 32)
        return false;

    // path is a vector of 32-byte hashes
    path.resize(depth);
    for (unsigned int j = 0; j < depth; j++)
        memcpy(path[j].begin(), &pathdata[32 * j], 32);

    // The third last witness stack item is the positiondata
    // Position is in minimally-coded unsigned little endian int
    std::vector<unsigned char> positiondata = witness.stack.at(witstacksize - 3);
    position = 0;
    if (positiondata.size() > 4)
        return false;
    if (positiondata.size() > 0) {
        if (positiondata.back() == 0)
            return false;
        for (size_t k = 0; k != positiondata.size(); ++k)
            position |= static_cast<uint32_t>(positiondata[k]) << 8 * k;
    }

    // Position value must not exceed the number of leaves at the depth
    if (depth < 32) {
        if (position >= (1U << depth))
            return false;
    }

    // keyScriptCode are located before positiondata
    keyScriptCode.resize(nKeyScriptCode);
    for (size_t i = 0; i < nKeyScriptCode; i++) {
        size_t pos = witstacksize - 3 - nKeyScriptCode + i;
        keyScriptCode.at(i) = CScript(witness.stack.at(pos).begin(), witness.stack.at(pos).end());
    }

    // Return unused items as stack
    stack = std::vector<std::vector<unsigned char> > (witness.stack.begin(), witness.stack.end() - 3 - nKeyScriptCode);

    return true;
}

bool IsMASTV0Stack(std::vector<std::vector<unsigned char> >& stack, std::vector<CScript>& sigScriptCode)
{
    if (stack.size() == 0)
        return false;

    size_t nSigScriptCode = 0;
    if (stack.back().size() == 0)
        nSigScriptCode = 0;
    else if (stack.back().size() == 1 && stack.back().at(0) >= 1 && stack.back().at(0) <= MAX_MAST_V0_SIGSCRIPTCODE)
        nSigScriptCode = static_cast<size_t>(stack.back().at(0));
    else
        return false;

    if (stack.size() < nSigScriptCode + 1)
        return false;

    sigScriptCode.clear();
    sigScriptCode.resize(MAX_MAST_V0_SIGSCRIPTCODE);
    for (size_t i = nSigScriptCode; i > 0; i--) {
        size_t pos = stack.size() - 1 - i;
        // The first defined sigScriptCode must not be empty or that becomes malleable.
        if (i == nSigScriptCode && stack.at(pos).size() == 0)
            return false;
        sigScriptCode.at(MAX_MAST_V0_SIGSCRIPTCODE - i) = CScript(stack.at(pos).begin(), stack.at(pos).end());
    }

    // Unused items are input stack
    stack = std::vector<std::vector<unsigned char> > (stack.begin(), stack.end() - 1 - nSigScriptCode);
    return true;
}

static bool VerifyWitnessProgram(const CScriptWitness& witness, const CScript& prevScript, int witversion, const std::vector<unsigned char>& program, unsigned int flags, const BaseSignatureChecker& checker, ScriptError* serror)
{
    vector<vector<unsigned char> > stack;
    CScript scriptPubKey;

    if (witversion == 0) {
        if (program.size() == 32) {
            // Version 0 segregated witness program: SHA256(CScript) inside the program, CScript + inputs in witness
            if (witness.stack.size() == 0) {
                return set_error(serror, SCRIPT_ERR_WITNESS_PROGRAM_WITNESS_EMPTY);
            }
            scriptPubKey = CScript(witness.stack.back().begin(), witness.stack.back().end());
            stack = std::vector<std::vector<unsigned char> >(witness.stack.begin(), witness.stack.end() - 1);
            uint256 hashScriptPubKey;
            CSHA256().Write(&scriptPubKey[0], scriptPubKey.size()).Finalize(hashScriptPubKey.begin());
            if (memcmp(hashScriptPubKey.begin(), &program[0], 32)) {
                return set_error(serror, SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH);
            }
        } else if (program.size() == 20) {
            // Special case for pay-to-pubkeyhash; signature + pubkey in witness
            if (witness.stack.size() != 2) {
                return set_error(serror, SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH); // 2 items in witness
            }
            scriptPubKey << OP_DUP << OP_HASH160 << program << OP_EQUALVERIFY << OP_CHECKSIG;
            stack = witness.stack;
        } else {
            return set_error(serror, SCRIPT_ERR_WITNESS_PROGRAM_WRONG_LENGTH);
        }
    } else if (witversion == 1 && (flags & SCRIPT_VERIFY_MAST)) {
        if (program.size() == 32 || program.size() == 33) {
            uint256 hashScript;
            uint32_t nMASTVersion = 0xffffffff;
            std::vector <uint256> path;
            uint32_t position;
            std::vector <CScript> keyScriptCode, sigScriptCode;
            if (program.size() == 32) {
                if (!IsMASTStack(witness, nMASTVersion, path, position, stack, keyScriptCode))
                    return set_error(serror, SCRIPT_ERR_INVALID_MAST_STACK);
                if (nMASTVersion == 0 && !IsMASTV0Stack(stack, sigScriptCode))
                    return set_error(serror, SCRIPT_ERR_INVALID_MAST_STACK);

                // Calculate the script hash
                CHashWriter sScriptHash(SER_GETHASH, 0);
                // Starts with 1-byte number of keyScriptCode
                sScriptHash << static_cast<unsigned char>(keyScriptCode.size());

                for (size_t i = 0; i < keyScriptCode.size(); i++) {
                    CScript subscript = keyScriptCode.at(i);
                    uint256 hashSubScript;
                    CHash256().Write(&subscript[0], subscript.size()).Finalize(hashSubScript.begin());
                    sScriptHash << hashSubScript;
                }
                hashScript = sScriptHash.GetHash();

                // Calculate MAST Root and compare against witness program
                uint256 rootScript = ComputeMerkleRootFromBranch(hashScript, path, position);
                CHashWriter sRoot(SER_GETHASH, 0);
                sRoot << nMASTVersion << rootScript;
                uint256 rootMAST = sRoot.GetHash();
                if (memcmp(rootMAST.begin(), &program[0], 32))
                    return set_error(serror, SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH);
            }
            else if (program.size() == 33) {
                stack = witness.stack;
                nMASTVersion = 0;
                if (!IsMASTV0Stack(stack, sigScriptCode))
                    return set_error(serror, SCRIPT_ERR_INVALID_MAST_STACK);
                scriptPubKey << program << OP_CHECKSIGVERIFY;
                keyScriptCode.push_back(scriptPubKey);
                uint256 hashSubScript;
                CHash256().Write(&scriptPubKey[0], scriptPubKey.size()).Finalize(hashSubScript.begin());
                CHashWriter sScriptHash(SER_GETHASH, 0);
                sScriptHash << static_cast<unsigned char>(1) << hashSubScript;
                hashScript = sScriptHash.GetHash();
            }

            if (nMASTVersion == 0) {
                int nOpCount = keyScriptCode.size() + path.size(); // Each keyScriptCode and tree depth consumes an nOpCount
                if (nOpCount > MAX_OPS_PER_SCRIPT)
                    return set_error(serror, SCRIPT_ERR_OP_COUNT);

                // Check the size of input stack
                for (unsigned int i = 0; i < stack.size(); i++) {
                    if (stack.at(i).size() > MAX_SCRIPT_ELEMENT_SIZE)
                        return set_error(serror, SCRIPT_ERR_PUSH_SIZE);
                }

                // Check script size and evaluate scripts. Stack must be empty after evaluation of all scripts
                size_t totalScriptSize = 0;
                unsigned int fSigScriptCodeUncommitted = 0;
                for (size_t i = 0; i < MAX_MAST_V0_SIGSCRIPTCODE; i++) {
                    totalScriptSize += sigScriptCode[i].size();
                    if (totalScriptSize > MAX_SCRIPT_SIZE)
                        return set_error(serror, SCRIPT_ERR_SCRIPT_SIZE);
                    if (sigScriptCode[i].size() > 0) {
                        fSigScriptCodeUncommitted |= (1U << i);
                        if (!EvalScript(stack, sigScriptCode[i], flags, checker, SIGVERSION_WITNESS_V1, nOpCount, prevScript, hashScript, sigScriptCode, i, fSigScriptCodeUncommitted, serror))
                            return false;
                    }
                }
                for (size_t i = 0; i < keyScriptCode.size(); i++) {
                    totalScriptSize += keyScriptCode[i].size();
                    if (totalScriptSize > MAX_SCRIPT_SIZE)
                        return set_error(serror, SCRIPT_ERR_SCRIPT_SIZE);
                    if (!EvalScript(stack, keyScriptCode[i], flags, checker, SIGVERSION_WITNESS_V1, nOpCount, prevScript, hashScript, sigScriptCode, MAX_MAST_V0_SIGSCRIPTCODE, fSigScriptCodeUncommitted, serror))
                        return false;
                }
                // All non-empty sigScriptCode must be directly or indirectly committed to by at least one signature operation in keyScriptCode
                if (fSigScriptCodeUncommitted)
                    return set_error(serror, SCRIPT_ERR_UNCOMMITED_SIGSCRIPTCODE);
                if (stack.size() != 0)
                    return set_error(serror, SCRIPT_ERR_EVAL_FALSE);
            }
            // Unknown MAST version is non-standard
            else if (flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM)
                return set_error(serror, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM);
            return set_success(serror);
        }
    } else if (flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM) {
        return set_error(serror, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM);
    } else {
        // Higher version witness scripts return true for future softfork compatibility
        return set_success(serror);
    }

    // Disallow stack item size > MAX_SCRIPT_ELEMENT_SIZE in witness stack
    for (unsigned int i = 0; i < stack.size(); i++) {
        if (stack.at(i).size() > MAX_SCRIPT_ELEMENT_SIZE)
            return set_error(serror, SCRIPT_ERR_PUSH_SIZE);
    }

    if (!EvalScript(stack, scriptPubKey, flags, checker, SIGVERSION_WITNESS_V0, serror)) {
        return false;
    }

    // Scripts inside witness implicitly require cleanstack behaviour
    if (stack.size() != 1)
        return set_error(serror, SCRIPT_ERR_EVAL_FALSE);
    if (!CastToBool(stack.back()))
        return set_error(serror, SCRIPT_ERR_EVAL_FALSE);
    return true;
}

bool VerifyScript(const CScript& scriptSig, const CScript& scriptPubKey, const CScriptWitness* witness, unsigned int flags, const BaseSignatureChecker& checker, ScriptError* serror)
{
    static const CScriptWitness emptyWitness;
    if (witness == NULL) {
        witness = &emptyWitness;
    }
    bool hadWitness = false;

    set_error(serror, SCRIPT_ERR_UNKNOWN_ERROR);

    if ((flags & SCRIPT_VERIFY_SIGPUSHONLY) != 0 && !scriptSig.IsPushOnly()) {
        return set_error(serror, SCRIPT_ERR_SIG_PUSHONLY);
    }

    vector<vector<unsigned char> > stack, stackCopy;
    if (!EvalScript(stack, scriptSig, flags, checker, SIGVERSION_BASE, serror))
        // serror is set
        return false;
    if (flags & SCRIPT_VERIFY_P2SH)
        stackCopy = stack;
    if (!EvalScript(stack, scriptPubKey, flags, checker, SIGVERSION_BASE, serror))
        // serror is set
        return false;
    if (stack.empty())
        return set_error(serror, SCRIPT_ERR_EVAL_FALSE);
    if (CastToBool(stack.back()) == false)
        return set_error(serror, SCRIPT_ERR_EVAL_FALSE);

    // Bare witness programs
    int witnessversion;
    std::vector<unsigned char> witnessprogram;
    if (flags & SCRIPT_VERIFY_WITNESS) {
        if (scriptPubKey.IsWitnessProgram(witnessversion, witnessprogram)) {
            hadWitness = true;
            if (scriptSig.size() != 0) {
                // The scriptSig must be _exactly_ CScript(), otherwise we reintroduce malleability.
                return set_error(serror, SCRIPT_ERR_WITNESS_MALLEATED);
            }
            if (!VerifyWitnessProgram(*witness, scriptPubKey, witnessversion, witnessprogram, flags, checker, serror)) {
                return false;
            }
            // Bypass the cleanstack check at the end. The actual stack is obviously not clean
            // for witness programs.
            stack.resize(1);
        }
    }

    // Additional validation for spend-to-script-hash transactions:
    if ((flags & SCRIPT_VERIFY_P2SH) && scriptPubKey.IsPayToScriptHash())
    {
        // scriptSig must be literals-only or validation fails
        if (!scriptSig.IsPushOnly())
            return set_error(serror, SCRIPT_ERR_SIG_PUSHONLY);

        // Restore stack.
        swap(stack, stackCopy);

        // stack cannot be empty here, because if it was the
        // P2SH  HASH <> EQUAL  scriptPubKey would be evaluated with
        // an empty stack and the EvalScript above would return false.
        assert(!stack.empty());

        const valtype& pubKeySerialized = stack.back();
        CScript pubKey2(pubKeySerialized.begin(), pubKeySerialized.end());
        popstack(stack);

        if (!EvalScript(stack, pubKey2, flags, checker, SIGVERSION_BASE, serror))
            // serror is set
            return false;
        if (stack.empty())
            return set_error(serror, SCRIPT_ERR_EVAL_FALSE);
        if (!CastToBool(stack.back()))
            return set_error(serror, SCRIPT_ERR_EVAL_FALSE);

        // P2SH witness program
        if (flags & SCRIPT_VERIFY_WITNESS) {
            if (pubKey2.IsWitnessProgram(witnessversion, witnessprogram)) {
                hadWitness = true;
                if (scriptSig != CScript() << std::vector<unsigned char>(pubKey2.begin(), pubKey2.end())) {
                    // The scriptSig must be _exactly_ a single push of the redeemScript. Otherwise we
                    // reintroduce malleability.
                    return set_error(serror, SCRIPT_ERR_WITNESS_MALLEATED_P2SH);
                }
                if (!VerifyWitnessProgram(*witness, pubKey2, witnessversion, witnessprogram, flags, checker, serror)) {
                    return false;
                }
                // Bypass the cleanstack check at the end. The actual stack is obviously not clean
                // for witness programs.
                stack.resize(1);
            }
        }
    }

    // The CLEANSTACK check is only performed after potential P2SH evaluation,
    // as the non-P2SH evaluation of a P2SH script will obviously not result in
    // a clean stack (the P2SH inputs remain). The same holds for witness evaluation.
    if ((flags & SCRIPT_VERIFY_CLEANSTACK) != 0) {
        // Disallow CLEANSTACK without P2SH, as otherwise a switch CLEANSTACK->P2SH+CLEANSTACK
        // would be possible, which is not a softfork (and P2SH should be one).
        assert((flags & SCRIPT_VERIFY_P2SH) != 0);
        assert((flags & SCRIPT_VERIFY_WITNESS) != 0);
        if (stack.size() != 1) {
            return set_error(serror, SCRIPT_ERR_CLEANSTACK);
        }
    }

    if (flags & SCRIPT_VERIFY_WITNESS) {
        // We can't check for correct unexpected witness data if P2SH was off, so require
        // that WITNESS implies P2SH. Otherwise, going from WITNESS->P2SH+WITNESS would be
        // possible, which is not a softfork.
        assert((flags & SCRIPT_VERIFY_P2SH) != 0);
        if (!hadWitness && !witness->IsNull()) {
            return set_error(serror, SCRIPT_ERR_WITNESS_UNEXPECTED);
        }
    }

    return set_success(serror);
}

size_t static WitnessSigOps(int witversion, const std::vector<unsigned char>& witprogram, const CScriptWitness& witness, int flags)
{
    if (witversion == 0) {
        if (witprogram.size() == 20)
            return 1;

        if (witprogram.size() == 32 && witness.stack.size() > 0) {
            CScript subscript(witness.stack.back().begin(), witness.stack.back().end());
            return subscript.GetSigOpCount(true);
        }
    }
    else if (witversion == 1) {
        size_t nSigOp = 0;
        std::vector <std::vector<unsigned char> > stack;
        std::vector <CScript> keyScriptCode, sigScriptCode;
        if (witprogram.size() == 32) {
            uint32_t nMASTVersion;
            std::vector <uint256> path;
            uint32_t position;
            if (IsMASTStack(witness, nMASTVersion, path, position, stack, keyScriptCode) && nMASTVersion == 0 && IsMASTV0Stack(stack, sigScriptCode)) {
                for (size_t i = 0; i < sigScriptCode.size(); i++)
                    nSigOp += sigScriptCode[i].GetSigOpCount(true, true);
                for (size_t i = 0; i < keyScriptCode.size(); i++)
                    nSigOp += keyScriptCode[i].GetSigOpCount(true, true);
            }
        }
        else if (witprogram.size() == 33) {
            nSigOp = 1;
            stack = witness.stack;
            if (IsMASTV0Stack(stack, sigScriptCode)) {
                for (size_t i = 0; i < sigScriptCode.size(); i++)
                    nSigOp += sigScriptCode[i].GetSigOpCount(true, true);
            }
        }
        return nSigOp;
    }

    // Future flags may be implemented here.
    return 0;
}

size_t CountWitnessSigOps(const CScript& scriptSig, const CScript& scriptPubKey, const CScriptWitness* witness, unsigned int flags)
{
    static const CScriptWitness witnessEmpty;

    if ((flags & SCRIPT_VERIFY_WITNESS) == 0) {
        return 0;
    }
    assert((flags & SCRIPT_VERIFY_P2SH) != 0);

    int witnessversion;
    std::vector<unsigned char> witnessprogram;
    if (scriptPubKey.IsWitnessProgram(witnessversion, witnessprogram)) {
        return WitnessSigOps(witnessversion, witnessprogram, witness ? *witness : witnessEmpty, flags);
    }

    if (scriptPubKey.IsPayToScriptHash() && scriptSig.IsPushOnly()) {
        CScript::const_iterator pc = scriptSig.begin();
        vector<unsigned char> data;
        while (pc < scriptSig.end()) {
            opcodetype opcode;
            scriptSig.GetOp(pc, opcode, data);
        }
        CScript subscript(data.begin(), data.end());
        if (subscript.IsWitnessProgram(witnessversion, witnessprogram)) {
            return WitnessSigOps(witnessversion, witnessprogram, witness ? *witness : witnessEmpty, flags);
        }
    }

    return 0;
}
