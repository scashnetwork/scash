// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Copyright (c) 2024 The Scash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POW_H
#define BITCOIN_POW_H

#include <consensus/params.h>

#include <stdint.h>

#include <randomx.h>

class CBlockHeader;
class CBlockIndex;
class uint256;

unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params&);
unsigned int CalculateNextWorkRequired(const CBlockIndex* pindexLast, int64_t nFirstBlockTime, const Consensus::Params&);

/** Check whether a block hash satisfies the proof-of-work requirement specified by nBits */
bool CheckProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params&);

/**
 * Return false if the proof-of-work requirement specified by new_nbits at a
 * given height is not possible, given the proof-of-work on the prior block as
 * specified by old_nbits.
 *
 * This function only checks that the new value is within a factor of 4 of the
 * old value for blocks at the difficulty adjustment interval, and otherwise
 * requires the values to be the same.
 *
 * Always returns true on networks where min difficulty blocks are allowed,
 * such as regtest/testnet.
 */
bool PermittedDifficultyTransition(const Consensus::Params& params, int64_t height, uint32_t old_nbits, uint32_t new_nbits);

// !SCASH

typedef enum POWVerifyMode_t
{
    POW_VERIFY_FULL = 0,
    POW_VERIFY_COMMITMENT_ONLY,
    POW_VERIFY_MINING
} POWVerifyMode;

/** Faster RandomX computation but requires more memory */
static constexpr bool DEFAULT_RANDOMX_FAST_MODE = false;

/** Number of epochs to cache. There is one VM per epoch. Minimum is 1.*/
static constexpr int DEFAULT_RANDOMX_VM_CACHE_SIZE = 2;

/** Calculate epoch from timestamp */
uint32_t GetEpoch(uint32_t nTime, uint32_t nDuration);

/** Calculate RandomX key for a given epoch */
uint256 GetSeedHash(uint32_t nEpoch);

/** Check if RandomX commitment of block satisfies the proof-of-work requirement specified by nBits */
bool CheckProofOfWorkRandomX(const CBlockHeader& block, const Consensus::Params& params, POWVerifyMode mode = POW_VERIFY_FULL, uint256 *outHash = nullptr);

/** Calculate RandomX commitment of block */
uint256 GetRandomXCommitment(const CBlockHeader& block, uint256 *inHash = nullptr);

/**
 * Bitcoin cash's difficulty adjustment mechanism.
 */
class arith_uint256;
arith_uint256 CalculateASERT(const arith_uint256 &refTarget,
                             const int64_t nPowTargetSpacing,
                             const int64_t nTimeDiff,
                             const int64_t nHeightDiff,
                             const arith_uint256 &powLimit,
                             const int64_t nHalfLife) noexcept;

uint32_t GetNextASERTWorkRequired(const CBlockIndex *pindexPrev,
                                  const CBlockHeader *pblock,
                                  const Consensus::Params &params,
                                  const CBlockIndex *pindexAnchorBlock) noexcept;

// !SCASH END

#endif // BITCOIN_POW_H
