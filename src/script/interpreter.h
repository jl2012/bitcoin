// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SCRIPT_INTERPRETER_H
#define BITCOIN_SCRIPT_INTERPRETER_H

#include "script_error.h"
#include "primitives/transaction.h"

#include <vector>
#include <stdint.h>
#include <string>

class CPubKey;
class CScript;
class CTransaction;
class uint256;

/** Signature hash types/flags */
enum
{
    SIGHASH_ALL = 1,
    SIGHASH_NONE = 2,
    SIGHASH_SINGLE = 3,
    SIGHASH_ANYONECANPAY = 0x80,
};

enum
{
    /*  In order to minimize the signature size for the default type (SIGHASH_MSV0_ALL), a SIGHASH_MSV0 flag is set
     *  only if a user wants to skip the signing of some transaction components.
     *
     *  Shorthards for signing all/none of the followings. WARNING: a SIGHASH_MSV0_NONE signature effectively allows
     *  anyone to spend all existing and future MSV0 UTXOs related to the public key, unless it is also protected by
     *  other methods such as multi-sig.
     */
    SIGHASH_MSV0_ALL = 0,
    SIGHASH_MSV0_NONE = 0xffff,

    /*
     *  The bit 0 and 1 indicates signing for the input prevout
     *
     *  Value    prevout      value
     *  =====    ==========   ==========
     *  00       All          This input
     *  01       This input   This input
     *  10       No           This input
     *  11       No           No
     *
     *  WARNING: signatures with SIGHASH_MSV0_NOINPUT or SIGHASH_MSV0_NOINPUT_NOVALUE are replayable and might lead to
     *  unexpected fund loss in case of public key reuse. If the signatures are not properly restricted by other flags,
     *  the effect would be similar to that of SIGHASH_MSV0_NONE
     */
    SIGHASH_MSV0_SINGLEINPUT = 1,
    SIGHASH_MSV0_NOINPUT = 2,
    SIGHASH_MSV0_NOINPUT_NOVALUE = 3,

    /*
     *  The bit 2 and 3 indicates signing for the input nSequence
     *
     *  Value    nSequence
     *  =====    ==========
     *  00       All
     *  01       This input
     *  10       Invalid
     *  11       No
     *
     *  Evaluation will fail if the bits are set to "10"
     */
    SIGHASH_MSV0_SINGLESEQUENCE = 4,
    SIGHASH_MSV0_NOSEQUENCE = 0xc,

    /*
     *  The bit 4 and 5 indicates signing for the output
     *
     *  Value    scriptPubKey               value
     *  =====    ========================   ========================
     *  00       All                        All
     *  01       Same index of this input   Same index of this input
     *  10       Same index of this input   No
     *  11       No                         No
     *
     *  For SIGHASH_MSV0_SINGLEOUTPUT and SIGHASH_MSV0_SINGLEOUTPUT_NOVALUE,
     *  evaluation will fail if there is no matching output.
     */
    SIGHASH_MSV0_SINGLEOUTPUT = 0x10,
    SIGHASH_MSV0_SINGLEOUTPUT_NOVALUE = 0x20,
    SIGHASH_MSV0_NOOUTPUT = 0x30,

    /*
     *  Whether signing the input index. In the original (SIGVERSION_BASE) format, input index is implied by the
     *  position of scriptCode. The SIGHASH_MSV0_NOINPUTINDEX flag allows users to explicitly indicate whether the input
     *  index should be signed. Setting this flags makes the signature valid for any input index in the same/different
     *  transaction, depending on the use of the other flags.
     */
    SIGHASH_MSV0_NOINPUTINDEX = 0x40,

    SIGHASH_MSV0_NOFEE = 0x80,                 // Whether signing the amount of transaction fees
    SIGHASH_MSV0_NOSCRIPTCODE = 0x100,         // Whether signing the scriptCode (as defined in BIP143)
    SIGHASH_MSV0_NOVERSION = 0x200,            // Whether signing the transaction nVersion
    SIGHASH_MSV0_NOLOCKTIME = 0x400,           // Whether signing the transaction nLockTime

    /*
     *  Whether signing the different scriptWitCode. For example, SIGHASH_MSV0_NOSCRIPTWITCODE0 refers to the first
     *  script in the vscriptWitCode vector (the last executed scriptWitCode).
     */
    SIGHASH_MSV0_NOSCRIPTWITCODE0 = 0x800,
    SIGHASH_MSV0_NOSCRIPTWITCODE1 = 0x1000,
    SIGHASH_MSV0_NOSCRIPTWITCODE2 = 0x2000,
    SIGHASH_MSV0_NOSCRIPTWITCODE3 = 0x4000,
    SIGHASH_MSV0_NOSCRIPTWITCODE4 = 0x8000
};

/** Script verification flags */
enum
{
    SCRIPT_VERIFY_NONE      = 0,

    // Evaluate P2SH subscripts (softfork safe, BIP16).
    SCRIPT_VERIFY_P2SH      = (1U << 0),

    // Passing a non-strict-DER signature or one with undefined hashtype to a checksig operation causes script failure.
    // Evaluating a pubkey that is not (0x04 + 64 bytes) or (0x02 or 0x03 + 32 bytes) by checksig causes script failure.
    // (softfork safe, but not used or intended as a consensus rule).
    SCRIPT_VERIFY_STRICTENC = (1U << 1),

    // Passing a non-strict-DER signature to a checksig operation causes script failure (softfork safe, BIP62 rule 1)
    SCRIPT_VERIFY_DERSIG    = (1U << 2),

    // Passing a non-strict-DER signature or one with S > order/2 to a checksig operation causes script failure
    // (softfork safe, BIP62 rule 5).
    SCRIPT_VERIFY_LOW_S     = (1U << 3),

    // verify dummy stack item consumed by CHECKMULTISIG is of zero-length (softfork safe, BIP62 rule 7).
    SCRIPT_VERIFY_NULLDUMMY = (1U << 4),

    // Using a non-push operator in the scriptSig causes script failure (softfork safe, BIP62 rule 2).
    SCRIPT_VERIFY_SIGPUSHONLY = (1U << 5),

    // Require minimal encodings for all push operations (OP_0... OP_16, OP_1NEGATE where possible, direct
    // pushes up to 75 bytes, OP_PUSHDATA up to 255 bytes, OP_PUSHDATA2 for anything larger). Evaluating
    // any other push causes the script to fail (BIP62 rule 3).
    // In addition, whenever a stack element is interpreted as a number, it must be of minimal length (BIP62 rule 4).
    // (softfork safe)
    SCRIPT_VERIFY_MINIMALDATA = (1U << 6),

    // Discourage use of NOPs reserved for upgrades (NOP1-10)
    //
    // Provided so that nodes can avoid accepting or mining transactions
    // containing executed NOP's whose meaning may change after a soft-fork,
    // thus rendering the script invalid; with this flag set executing
    // discouraged NOPs fails the script. This verification flag will never be
    // a mandatory flag applied to scripts in a block. NOPs that are not
    // executed, e.g.  within an unexecuted IF ENDIF block, are *not* rejected.
    SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS  = (1U << 7),

    // Require that only a single stack element remains after evaluation. This changes the success criterion from
    // "At least one stack element must remain, and when interpreted as a boolean, it must be true" to
    // "Exactly one stack element must remain, and when interpreted as a boolean, it must be true".
    // (softfork safe, BIP62 rule 6)
    // Note: CLEANSTACK should never be used without P2SH or WITNESS.
    SCRIPT_VERIFY_CLEANSTACK = (1U << 8),

    // Verify CHECKLOCKTIMEVERIFY
    //
    // See BIP65 for details.
    SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY = (1U << 9),

    // support CHECKSEQUENCEVERIFY opcode
    //
    // See BIP112 for details
    SCRIPT_VERIFY_CHECKSEQUENCEVERIFY = (1U << 10),

    // Support segregated witness
    //
    SCRIPT_VERIFY_WITNESS = (1U << 11),

    // Making undefined witness program non-standard
    //
    SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM = (1U << 12),

    // Segwit script only: Require the argument of OP_IF/NOTIF to be exactly 0x01 or empty vector
    //
    SCRIPT_VERIFY_MINIMALIF = (1U << 13),

    // Signature(s) must be empty vector if an CHECK(MULTI)SIG operation failed
    //
    SCRIPT_VERIFY_NULLFAIL = (1U << 14),

    // Public keys in segregated witness scripts must be compressed
    //
    SCRIPT_VERIFY_WITNESS_PUBKEYTYPE = (1U << 15),

    // Support MSV0 and new opcode. Should not be used without WITNESS
    //
    SCRIPT_VERIFY_MSV0 = (1U << 16),
};

enum
{
    // External types
    TXDATA_THIS_VIN_INDEX = 0,
    TXDATA_VIN_SIZE = 1,
    TXDATA_VOUT_SIZE = 2,
    TXDATA_THIS_VIN_VALUE = 3,
    TXDATA_FEE = 4,
    TXDATA_VERSION = 5,
    TXDATA_LOCKTIME = 6,
    TXDATA_BASE_SIZE = 7,
    TXDATA_TOTAL_SIZE = 8,
    TXDATA_WEIGHT = 9,
    TXDATA_VIN_PREVOUT = 10,
    TXDATA_VIN_SEQUENCE = 11,
    TXDATA_VIN = 12,
    TXDATA_VOUT_VALUE = 13,
    TXDATA_VOUT_SCRIPTPUBKEY = 14,
    TXDATA_VOUT = 15,

    // Internal types
    TXDATA_VIN_PREVOUT_HASH = 200,
    TXDATA_VIN_PREVOUT_N = 201,
};

struct PrecomputedTransactionData
{
    uint256 hashPrevouts, hashSequence, hashOutputs;

    explicit PrecomputedTransactionData(const CTransaction& tx);
};

enum SigVersion
{
    SIGVERSION_BASE = 0,
    SIGVERSION_WITNESS_V0 = 1,
    SIGVERSION_MSV0 = 2,
};

bool CheckSignatureEncoding(const std::vector<unsigned char> &vchSig, unsigned int flags, const SigVersion &sigversion, ScriptError* serror);

uint256 SignatureHash(const CScript &scriptCode, std::vector<CScript> vscriptWitCode, const CTransaction& txTo, unsigned int nIn, unsigned int nHashType, const CAmount& amount, const CAmount& nFees, SigVersion sigversion, const PrecomputedTransactionData* cache = nullptr);

class BaseSignatureChecker
{
public:
    virtual bool CheckSig(const std::vector<unsigned char>& scriptSig, const std::vector<unsigned char>& vchPubKey, const CScript& scriptCode, SigVersion sigversion, const std::vector<CScript>& vscriptWitCode) const
    {
        return false;
    }

    virtual bool CheckLockTime(const CScriptNum& nLockTime) const
    {
         return false;
    }

    virtual bool CheckSequence(const CScriptNum& nSequence) const
    {
         return false;
    }

    virtual std::vector<unsigned char> PushTxData(const int& nType, const int& nIndex) const
    {
         std::vector<unsigned char> vchZero(0);
         return vchZero;
    }

    virtual ~BaseSignatureChecker() {}
};

class TransactionSignatureChecker : public BaseSignatureChecker
{
private:
    const CTransaction* txTo;
    unsigned int nIn;
    const CAmount amount;
    const CAmount nFees;
    const PrecomputedTransactionData* txdata;

protected:
    virtual bool VerifySignature(const std::vector<unsigned char>& vchSig, const CPubKey& vchPubKey, const uint256& sighash, const bool& compact) const;

public:
    TransactionSignatureChecker(const CTransaction* txToIn, unsigned int nInIn, const CAmount& amountIn, const CAmount& nFeesIn) : txTo(txToIn), nIn(nInIn), amount(amountIn), nFees(nFeesIn), txdata(nullptr) {}
    TransactionSignatureChecker(const CTransaction* txToIn, unsigned int nInIn, const CAmount& amountIn, const CAmount& nFeesIn, const PrecomputedTransactionData& txdataIn) : txTo(txToIn), nIn(nInIn), amount(amountIn), nFees(nFeesIn), txdata(&txdataIn) {}
    bool CheckSig(const std::vector<unsigned char>& scriptSig, const std::vector<unsigned char>& vchPubKey, const CScript& scriptCode, SigVersion sigversion, const std::vector<CScript>& vscriptWitCode) const override;
    bool CheckLockTime(const CScriptNum& nLockTime) const override;
    bool CheckSequence(const CScriptNum& nSequence) const override;
    std::vector<unsigned char> PushTxData(const int& nType, const int& nIndex) const override;
};

class MutableTransactionSignatureChecker : public TransactionSignatureChecker
{
private:
    const CTransaction txTo;

public:
    MutableTransactionSignatureChecker(const CMutableTransaction* txToIn, unsigned int nInIn, const CAmount& amountIn, const CAmount& nFeesIn) : TransactionSignatureChecker(&txTo, nInIn, amountIn, nFeesIn), txTo(*txToIn) {}
};

bool EvalScript(std::vector<std::vector<unsigned char> >& stack, const CScript& script, unsigned int flags, const BaseSignatureChecker& checker, SigVersion sigversion, ScriptError* error = nullptr);
bool EvalScript(std::vector<std::vector<unsigned char> >& stack, const CScript& script, unsigned int flags, const BaseSignatureChecker& checker, SigVersion sigversion, int& nOpCount, const std::vector<CScript>& vscriptWitCode, const size_t& posScriptWitCode, unsigned int& fUncoveredScriptWitCode, ScriptError* serror = nullptr);
bool VerifyScript(const CScript& scriptSig, const CScript& scriptPubKey, const CScriptWitness* witness, unsigned int flags, const BaseSignatureChecker& checker, ScriptError* serror = nullptr);

size_t CountWitnessSigOps(const CScript& scriptSig, const CScript& scriptPubKey, const CScriptWitness* witness, unsigned int flags);

#endif // BITCOIN_SCRIPT_INTERPRETER_H
