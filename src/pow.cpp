// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Copyright (c) 2024 The Scash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pow.h>

#include <arith_uint256.h>
#include <chain.h>
#include <primitives/block.h>
#include <uint256.h>

// !SCASH
#include <common/args.h>
#include <crypto/sha256.h>
#include <randomx.h>
#include <logging.h>
#include <boost/compute/detail/lru_cache.hpp>

static Mutex rx_caches_mutex;

typedef struct RandomXCacheWrapper {
    randomx_cache *cache = nullptr;
    RandomXCacheWrapper(randomx_cache *inCache) : cache(inCache) {}
    ~RandomXCacheWrapper() {
        if (cache) randomx_release_cache(cache);
    }
} RandomXCacheWrapper;

typedef struct RandomXDatasetWrapper {
    randomx_dataset *dataset = nullptr;
    RandomXDatasetWrapper(randomx_dataset *inDataset) : dataset(inDataset) {}
    ~RandomXDatasetWrapper() {
        if (dataset) randomx_release_dataset(dataset);
    }
} RandomXDatasetWrapper;

using RandomXDatasetRef = std::shared_ptr<RandomXDatasetWrapper>;
using RandomXCacheRef = std::shared_ptr<RandomXCacheWrapper>;

typedef struct RandomXVMWrapper
{
    randomx_vm *vm = nullptr;
    RandomXCacheRef cache = nullptr;
    RandomXDatasetRef dataset = nullptr;
    mutable Mutex m_hashing_mutex;
    RandomXVMWrapper(randomx_vm *inVm, RandomXCacheRef inCacheRef, RandomXDatasetRef inDatasetRef) : vm(inVm), cache(inCacheRef), dataset(inDatasetRef) {}
    ~RandomXVMWrapper() {
        if (vm) {
            randomx_destroy_vm(vm);
            cache = nullptr;
            dataset = nullptr;
        }
    }
} RandomXVMWrapper;

using RandomXVMRef = std::shared_ptr<RandomXVMWrapper>;

using LRURandomXCacheRef = std::shared_ptr< boost::compute::detail::lru_cache<int32_t, RandomXCacheRef>>;
using LRURandomXVMRef = std::shared_ptr< boost::compute::detail::lru_cache<int32_t, RandomXVMRef>>;
using LRURandomXDatasetRef = std::shared_ptr< boost::compute::detail::lru_cache<int32_t, RandomXDatasetRef>>;

static LRURandomXCacheRef cache_rx_cache;
static LRURandomXVMRef cache_rx_vm_light;
static LRURandomXVMRef cache_rx_vm_fast;
static LRURandomXDatasetRef cache_rx_dataset;

// !SCASH END


// !BITCOINCASH

/**
 * ASERT Difficulty Adjustment Algorithm (aserti3-2d)
 * https://reference.cash/protocol/forks/2020-11-15-asert
 * Source code:
 * https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/4ee1083307d2aaac92dd7c409cc9d6f2eb52be78/src/pow.cpp
 *
 * Any changes to the Bitcoin Cash code because Scash has a different powlimit are marked with Scash guards.
 */

/**
 * Compute the next required proof of work using an absolutely scheduled
 * exponentially weighted target (ASERT).
 *
 * With ASERT, we define an ideal schedule for block issuance (e.g. 1 block every 600 seconds), and we calculate the
 * difficulty based on how far the most recent block's timestamp is ahead of or behind that schedule.
 * We set our targets (difficulty) exponentially. For every [nHalfLife] seconds ahead of or behind schedule we get, we
 * double or halve the difficulty.
 */
static uint32_t GetNextASERTWorkRequired(const CBlockIndex *pindexPrev,
                                         const CBlockHeader *pblock,
                                         const Consensus::Params &params,
                                         const Consensus::Params::ASERTAnchor &anchorParams) noexcept {
    // This cannot handle the genesis block and early blocks in general.
    assert(pindexPrev != nullptr);

    // We make no further assumptions other than the height of the prev block must be >= that of the anchor block.
    assert(pindexPrev->nHeight >= anchorParams.nHeight);

    // Special difficulty rule for testnet
    // If the new block's timestamp is more than 2 * 10 minutes then allow
    // mining of a min-difficulty block.
    if (params.fPowAllowMinDifficultyBlocks &&
        (pblock->GetBlockTime() >
         pindexPrev->GetBlockTime() + 2 * params.nPowTargetSpacing)) {
        return UintToArith256(params.powLimit).GetCompact();
    }

    const arith_uint256 powLimit = UintToArith256(params.powLimit);

    // For nTimeDiff calculation, the timestamp of the parent to the anchor block is used,
    // as per the absolute formulation of ASERT.
    // This is somewhat counterintuitive since it is referred to as the anchor timestamp, but
    // as per the formula the timestamp of block M-1 must be used if the anchor is M.
    assert(pindexPrev->pprev != nullptr);

    const arith_uint256 refBlockTarget = arith_uint256().SetCompact(anchorParams.nBits);

    // Time difference is from anchor block's parent block's timestamp
    const int64_t nTimeDiff = pindexPrev->GetBlockTime() - anchorParams.nPrevBlockTime;
    // Height difference is from current block to anchor block
    const int nHeightDiff = pindexPrev->nHeight - anchorParams.nHeight;

    // Do the actual target adaptation calculation in separate
    // CalculateASERT() function
    arith_uint256 nextTarget = CalculateASERT(refBlockTarget,
                                              params.nPowTargetSpacing,
                                              nTimeDiff,
                                              nHeightDiff,
                                              powLimit,
                                              params.nASERTHalfLife);

    // CalculateASERT() already clamps to powLimit.
    return nextTarget.GetCompact();
}

uint32_t GetNextASERTWorkRequired(const CBlockIndex *pindexPrev,
                                  const CBlockHeader *pblock,
                                  const Consensus::Params &params,
                                  const CBlockIndex *pindexAnchorBlock) noexcept {

    // If hard-coded params exist for this chain, we use those
    if (params.asertAnchorParams) {
        return GetNextASERTWorkRequired(pindexPrev, pblock, params, *params.asertAnchorParams);
    }

    // Otherwise, caller should have specified the anchor block (chain where it has not yet
    // activated such as ScaleNet).
    //
    // Anchor block is the block on which all ASERT scheduling calculations are based.
    // It too must exist, and it must have a valid parent.
    assert(pindexAnchorBlock != nullptr);


    // Note: time difference is to parent of anchor block (or to anchor block itself iff anchor is genesis).
    //       (according to absolute formulation of ASERT)
    const auto anchorTime = pindexAnchorBlock->pprev
                                    ? pindexAnchorBlock->pprev->GetBlockTime()
                                    : pindexAnchorBlock->GetBlockTime();

    const Consensus::Params::ASERTAnchor anchorParams{
        pindexAnchorBlock->nHeight,
        pindexAnchorBlock->nBits,
        anchorTime
    };

    // Call the overloaded function that does the actual calculation using anchorParams
    return GetNextASERTWorkRequired(pindexPrev, pblock, params, anchorParams);
}


// ASERT calculation function.
// Clamps to powLimit.
arith_uint256 CalculateASERT(const arith_uint256 &refTarget,
                             const int64_t nPowTargetSpacing,
                             const int64_t nTimeDiff,
                             const int64_t nHeightDiff,
                             const arith_uint256 &powLimit,
                             const int64_t nHalfLife) noexcept {

    // Input target must never be zero nor exceed powLimit.
    assert(refTarget > 0 && refTarget <= powLimit);

    // We need some leading zero bits in powLimit in order to have room to handle
    // overflows easily. 32 leading zero bits is more than enough.

    // !SCASH
    // Scash has a higher powLimits and uses uint512 internally, so this check is disabled
    // assert((powLimit >> 224) == 0);
    // !SCASH END

    // Height diff should NOT be negative.
    assert(nHeightDiff >= 0);

    // It will be helpful when reading what follows, to remember that
    // nextTarget is adapted from anchor block target value.

    // Ultimately, we want to approximate the following ASERT formula, using only integer (fixed-point) math:
    //     new_target = old_target * 2^((blocks_time - IDEAL_BLOCK_TIME * (height_diff + 1)) / nHalfLife)

    // First, we'll calculate the exponent:
    assert( llabs(nTimeDiff - nPowTargetSpacing * nHeightDiff) < (1ll << (63 - 16)) );
    const int64_t exponent = ((nTimeDiff - nPowTargetSpacing * (nHeightDiff + 1)) * 65536) / nHalfLife;

    // Next, we use the 2^x = 2 * 2^(x-1) identity to shift our exponent into the [0, 1) interval.
    // The truncated exponent tells us how many shifts we need to do
    // Note1: This needs to be a right shift. Right shift rounds downward (floored division),
    //        whereas integer division in C++ rounds towards zero (truncated division).
    // Note2: This algorithm uses arithmetic shifts of negative numbers. This
    //        is unpecified but very common behavior for C++ compilers before
    //        C++20, and standard with C++20. We must check this behavior e.g.
    //        using static_assert.
    static_assert(int64_t(-1) >> 1 == int64_t(-1),
                  "ASERT algorithm needs arithmetic shift support");

    // Now we compute an approximated target * 2^(exponent/65536.0)

    // First decompose exponent into 'integer' and 'fractional' parts:
    int64_t shifts = exponent >> 16;
    const auto frac = uint16_t(exponent);
    assert(exponent == (shifts * 65536) + frac);

    // multiply target by 65536 * 2^(fractional part)
    // 2^x ~= (1 + 0.695502049*x + 0.2262698*x**2 + 0.0782318*x**3) for 0 <= x < 1
    // Error versus actual 2^x is less than 0.013%.
    const uint32_t factor = 65536 + ((
        + 195766423245049ull * frac
        + 971821376ull * frac * frac
        + 5127ull * frac * frac * frac
        + (1ull << 47)
        ) >> 48);

    // !SCASH
    // Intermediate computation uses 512 bit integers to avoid potential overflow from chain parameters.
    arith_uint512 nextTarget512 = arith_uint512::from(refTarget) * factor;
    arith_uint512 powLimit512 = arith_uint512::from(powLimit);

    // multiply by 2^(integer part) / 65536
    shifts -= 16;
    if (shifts <= 0) {
        nextTarget512 >>= -shifts;
    } else {
        // Detect overflow that would discard high bits
        const auto nextTarget512Shifted = nextTarget512 << shifts;
        if ((nextTarget512Shifted >> shifts) != nextTarget512) {
            nextTarget512 = powLimit512;
        } else {
            // Shifting produced no overflow, can assign value
            nextTarget512 = nextTarget512Shifted;
        }
    }

    if (nextTarget512 > powLimit512) {
        nextTarget512 = powLimit512;
    }
    arith_uint256 nextTarget = arith_uint256::from(nextTarget512);
    // !SCASH END

    if (nextTarget == 0) {
        // 0 is not a valid target, but 1 is.
        nextTarget = arith_uint256(1);
    } else if (nextTarget > powLimit) {
        nextTarget = powLimit;
    }

    // we return from only 1 place for copy elision
    return nextTarget;
}

// !BITCOINCASH END


unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params)
{
    assert(pindexLast != nullptr);
    unsigned int nProofOfWorkLimit = UintToArith256(params.powLimit).GetCompact();

    // !SCASH
    // Use ASERT DAA if activated, otherwise use legacy Bitcoin DAA
    if (params.asertAnchorParams) {
        if (pindexLast->nHeight + 1 >= params.nASERTActivationHeight) {
            return GetNextASERTWorkRequired(pindexLast, pblock, params, *params.asertAnchorParams);
        }
    }
    // !SCASH END

    // Only change once per difficulty adjustment interval
    if ((pindexLast->nHeight+1) % params.DifficultyAdjustmentInterval() != 0)
    {
        if (params.fPowAllowMinDifficultyBlocks)
        {
            // Special difficulty rule for testnet:
            // If the new block's timestamp is more than 2* 10 minutes
            // then allow mining of a min-difficulty block.
            if (pblock->GetBlockTime() > pindexLast->GetBlockTime() + params.nPowTargetSpacing*2)
                return nProofOfWorkLimit;
            else
            {
                // Return the last non-special-min-difficulty-rules-block
                const CBlockIndex* pindex = pindexLast;
                while (pindex->pprev && pindex->nHeight % params.DifficultyAdjustmentInterval() != 0 && pindex->nBits == nProofOfWorkLimit)
                    pindex = pindex->pprev;
                return pindex->nBits;
            }
        }
        return pindexLast->nBits;
    }

    // Go back by what we want to be 14 days worth of blocks

    // !SCASH
    // Fix legacy Bitcoin off-by-one retargeting bug to prevent a time warp attack.
    // Difficulty is now correctly calculated over block intervals which overlap.
    int nHeightFirst = (g_isRandomX) ? std::max(0, pindexLast->nHeight - (int)params.DifficultyAdjustmentInterval()) :
                                       pindexLast->nHeight - (params.DifficultyAdjustmentInterval() - 1);
    // !SCASH END

    assert(nHeightFirst >= 0);
    const CBlockIndex* pindexFirst = pindexLast->GetAncestor(nHeightFirst);
    assert(pindexFirst);

    return CalculateNextWorkRequired(pindexLast, pindexFirst->GetBlockTime(), params);
}

unsigned int CalculateNextWorkRequired(const CBlockIndex* pindexLast, int64_t nFirstBlockTime, const Consensus::Params& params)
{
    if (params.fPowNoRetargeting)
        return pindexLast->nBits;

    // Limit adjustment step
    int64_t nActualTimespan = pindexLast->GetBlockTime() - nFirstBlockTime;
    if (nActualTimespan < params.nPowTargetTimespan/4)
        nActualTimespan = params.nPowTargetTimespan/4;
    if (nActualTimespan > params.nPowTargetTimespan*4)
        nActualTimespan = params.nPowTargetTimespan*4;

    // Retarget
    const arith_uint256 bnPowLimit = UintToArith256(params.powLimit);
    arith_uint256 bnNew;
    bnNew.SetCompact(pindexLast->nBits);

    // !SCASH
    // Intermediate computation uses 512 bit integers to avoid potential overflow from chain parameters.
    // No overflow with default Bitcoin chain parameters so behaviour remains the same.
    arith_uint512 bnNew512 = arith_uint512::from(bnNew);
    bnNew512 *= nActualTimespan;
    bnNew512 /= params.nPowTargetTimespan;
    if (bnNew512 > arith_uint512::from(bnPowLimit)) {
        bnNew = bnPowLimit; 
    } else {
        bnNew = arith_uint256::from(bnNew512);
    }
    // !SCASH END

    return bnNew.GetCompact();
}

// Check that on difficulty adjustments, the new difficulty does not increase
// or decrease beyond the permitted limits.
bool PermittedDifficultyTransition(const Consensus::Params& params, int64_t height, uint32_t old_nbits, uint32_t new_nbits)
{
    if (params.fPowAllowMinDifficultyBlocks) return true;

    if (height % params.DifficultyAdjustmentInterval() == 0) {
        int64_t smallest_timespan = params.nPowTargetTimespan/4;
        int64_t largest_timespan = params.nPowTargetTimespan*4;

        const arith_uint256 pow_limit = UintToArith256(params.powLimit);
        arith_uint256 observed_new_target;
        observed_new_target.SetCompact(new_nbits);

        // Calculate the largest difficulty value possible:
        arith_uint256 largest_difficulty_target;
        largest_difficulty_target.SetCompact(old_nbits);

        // !SCASH
        // Intermediate computation uses 512 bit integers to avoid potential overflow from chain parameters.
        // No overflow with default Bitcoin chain parameters so behaviour remains the same.
        arith_uint512 tmp = arith_uint512::from(largest_difficulty_target);
        tmp *= largest_timespan;
        tmp /= params.nPowTargetTimespan;
        if (tmp > arith_uint512::from(pow_limit)) {
            largest_difficulty_target = pow_limit; 
        } else {
            largest_difficulty_target = arith_uint256::from(tmp);
        }
        // !SCASH END

        // Round and then compare this new calculated value to what is
        // observed.
        arith_uint256 maximum_new_target;
        maximum_new_target.SetCompact(largest_difficulty_target.GetCompact());
        if (maximum_new_target < observed_new_target) return false;

        // Calculate the smallest difficulty value possible:
        arith_uint256 smallest_difficulty_target;
        smallest_difficulty_target.SetCompact(old_nbits);
        smallest_difficulty_target *= smallest_timespan;
        smallest_difficulty_target /= params.nPowTargetTimespan;

        if (smallest_difficulty_target > pow_limit) {
            smallest_difficulty_target = pow_limit;
        }

        // Round and then compare this new calculated value to what is
        // observed.
        arith_uint256 minimum_new_target;
        minimum_new_target.SetCompact(smallest_difficulty_target.GetCompact());
        if (minimum_new_target > observed_new_target) return false;
    } else if (old_nbits != new_nbits) {
        return false;
    }
    return true;
}

bool CheckProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params& params)
{
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    // Check range
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(params.powLimit))
        return false;

    // Check proof of work matches claimed amount
    if (UintToArith256(hash) > bnTarget)
        return false;

    return true;
}

// !SCASH

// Seed string contains an epoch integer and is sha256d hashed to derive the seed hash (RandomX key).
static const char *RANDOMX_EPOCH_SEED_STRING = "Scash/RandomX/Epoch/%d";

// Epoch is Unix time stamp in seconds divided by epoch duration in seconds.
uint32_t GetEpoch(uint32_t nTimestamp, uint32_t nDuration) {
    return nTimestamp / nDuration;
}

// Compute seed hash (the RandomX key) for an epoch. Applies sha256d to the seed string.
uint256 GetSeedHash(uint32_t nEpoch)
{
    std::string s = strprintf(RANDOMX_EPOCH_SEED_STRING, nEpoch);
    uint256 h1, h2;
    CSHA256().Write((const unsigned char*)s.data(), s.size()).Finalize(h1.begin());
    CSHA256().Write(h1.begin(), 32).Finalize(h2.begin());
    return h2;
}

// Create a VM in fast mode. Run this in a background thread as it can take a long time.
// Can be optimized by using multiple threads to init the dataset.
static void CreateFastVM(uint32_t nEpoch, RandomXCacheRef myCache)
{
    randomx_flags flags = randomx_get_flags();
    flags |= RANDOMX_FLAG_FULL_MEM;

    RandomXDatasetRef myDataset = nullptr;
    if (cache_rx_dataset->contains(nEpoch)) {
        myDataset = cache_rx_dataset->get(nEpoch).get();
    } else {
        randomx_dataset* pDataset = randomx_alloc_dataset(flags);
        if (pDataset == nullptr) {
            LogPrintf("Error: randomx_alloc_dataset() failed\n");
            return;
        }

        const auto start{SteadyClock::now()};

        randomx_init_dataset(pDataset, myCache->cache, 0, randomx_dataset_item_count());
        myDataset = std::make_shared<RandomXDatasetWrapper>(pDataset);
        {
            LOCK(rx_caches_mutex);
            cache_rx_dataset->insert(nEpoch, myDataset);
        }

        LogPrintf("Created RandomX dataset: %.2fs\n", Ticks<SecondsDouble>(SteadyClock::now() - start));

    }

    randomx_vm* myVM = nullptr;
    myVM = randomx_create_vm(flags, NULL, myDataset.get()->dataset);
    if (!myVM) {
        LogPrintf("Error: randomx_create_vm() failed\n");
        return;
    }

    LOCK(rx_caches_mutex);
    cache_rx_vm_fast->insert(nEpoch, std::make_shared<RandomXVMWrapper>(myVM, nullptr, myDataset));
}

// Get VM for a given epoch, creating and caching if necessary.
static boost::optional<RandomXVMRef> GetVM(int32_t nEpoch)
{
    // Initialize caches once with desired size
    static std::once_flag flag;
    std::call_once(flag, []() {
        int n = gArgs.GetIntArg("-randomxvmcachesize", DEFAULT_RANDOMX_VM_CACHE_SIZE);
        cache_rx_cache = std::make_shared<boost::compute::detail::lru_cache<int32_t, RandomXCacheRef>>(n);
        cache_rx_vm_light = std::make_shared<boost::compute::detail::lru_cache<int32_t, RandomXVMRef>>(n);
        cache_rx_vm_fast = std::make_shared<boost::compute::detail::lru_cache<int32_t, RandomXVMRef>>(n);
        cache_rx_dataset = std::make_shared<boost::compute::detail::lru_cache<int32_t, RandomXDatasetRef>>(n);
        LogPrintf("Created RandomX caches of size %d\n", n);
    });

    uint256 seedHash = GetSeedHash(nEpoch);

    // When IBD has finished, if fastmode is enabled, clear the light mode caches to trigger building fast mode vms.
    if (g_isIBDFinished) {
        static std::once_flag allowFlag;
        std::call_once(allowFlag, []() {
            if (gArgs.GetBoolArg("-randomxfastmode", DEFAULT_RANDOMX_FAST_MODE)) {
                LOCK(rx_caches_mutex);
                cache_rx_vm_light->clear();
                LogPrintf("RandomX fast mode enabled\n");
            }
        });
    }


    // If VM in fast mode is cached, return it first, due to faster performance than light mode
    if (cache_rx_vm_fast->contains(nEpoch)) {
        return cache_rx_vm_fast->get(nEpoch);
    } else if (cache_rx_vm_light->contains(nEpoch)) {
        return cache_rx_vm_light->get(nEpoch);
    }

    // No VM exists, so create light mode VM first and create fast mode VM in background thread.
    randomx_flags flags = randomx_get_flags();

    LOCK(rx_caches_mutex);

    // Create randomx cache if requred
    RandomXCacheRef myCache = nullptr;
    if (cache_rx_cache->contains(nEpoch)) {
        myCache = cache_rx_cache->get(nEpoch).get();
    } else {
        randomx_cache* pCache = randomx_alloc_cache(flags);
        if (!pCache) {
            LogPrintf("Error: randomx_alloc_cache() failed\n");
            return boost::none;
        }
        randomx_init_cache(pCache, seedHash.data(), seedHash.size());
        myCache = std::make_shared<RandomXCacheWrapper>(pCache);
        cache_rx_cache->insert(nEpoch, myCache); // store in LRU cache
    }

    // Create light VM using randomx cache
    randomx_vm* myVM = nullptr;
    myVM = randomx_create_vm(flags, myCache->cache, NULL);
    if (!myVM) {
        LogPrintf("Error: randomx_create_vm() failed\n");
        return boost::none;
    }

    RandomXVMRef vmRef = std::make_shared<RandomXVMWrapper>(myVM, myCache, nullptr);
    cache_rx_vm_light->insert(nEpoch, vmRef);

    // When IBD has finished, allow background thread to create fast mode VM (can be disabled to reduce memory usage)
    if (g_isIBDFinished && gArgs.GetBoolArg("-randomxfastmode", DEFAULT_RANDOMX_FAST_MODE)) {
        std::thread t(CreateFastVM, nEpoch, myCache);
        t.detach();
    }

    return vmRef;
}

// Compute randomx commitment from block header. If inHash parameter is not provided, use hash from block header.
uint256 GetRandomXCommitment(const CBlockHeader& block, uint256 *inHash) {
    uint256 rx_hash = inHash==nullptr ? block.hashRandomX : *inHash;
    CBlockHeader rx_blockHeader(block);
    rx_blockHeader.hashRandomX.SetNull();   // set to null when hashing
    char rx_cm[RANDOMX_HASH_SIZE];
    randomx_calculate_commitment(&rx_blockHeader, sizeof(rx_blockHeader), rx_hash.data(), rx_cm);
    return uint256(std::vector<unsigned char>(rx_cm, rx_cm + sizeof(rx_cm)));
}


/**
 * Check the RandomX commitment value, derived from the block header, meets the desired target.
 *
 * @param[in] block The block header to verify or block header template to mine.
 * @param[in] params Consensus parameters
 * @param[in] verifyMode
 *            POW_VERIFY_COMMITMENT is 'light' verification. Only checks RandomX commitment meets target.
 *            POW_VERIFY_FULL is 'full' verification. Checks both RandomX hash and commitment values.
 *            POW_VERIFY_MINING calculates both RandomX hash and commitment values from block header template.
 * @param[out] outHash If the block is valid, return RandomX hash for the block. Optional, but required for POW_VERIFY_MINING.
 * @return True if the RandomX commitment value meets target. Set outHash parameter to RandomX hash value.
 */
bool CheckProofOfWorkRandomX(const CBlockHeader& block, const Consensus::Params& params, POWVerifyMode verifyMode, uint256 *outHash)
{
    // Legacy chains continue to use original sha256d PoW
    if (!params.fPowRandomX) {
        return CheckProofOfWork(block.GetHash(), block.nBits, params);
    }

    unsigned int nBits = block.nBits;

    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    // Check range
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(params.powLimit))
        return false;

    uint256 hashRandomX;
    bool fHashVerified = false;
    bool fCommitmentVerified = false;

    if (outHash == nullptr && verifyMode == POW_VERIFY_MINING) {
        throw std::runtime_error("mining requires outHash parameter");
    }

    // Do cheaper commitment verification first
    if (verifyMode != POW_VERIFY_MINING ) {
        if (block.hashRandomX.IsNull()) {
            return false;
        }
        if (UintToArith256(GetRandomXCommitment(block)) > bnTarget) {
            return false;
        }
        hashRandomX = block.hashRandomX;
        fCommitmentVerified = true;
    }

    // Compute RandomX hash if necessary
    if (verifyMode == POW_VERIFY_FULL || verifyMode == POW_VERIFY_MINING) {
        int32_t nEpoch = GetEpoch(block.nTime, params.nRandomXEpochDuration);
        boost::optional<RandomXVMRef> vmRef = GetVM(nEpoch);
        if (!vmRef) {
            LogPrintf("Error: Could not obtain VM for RandomX\n");
            return false;
        }

	    char rx_hash[RANDOMX_HASH_SIZE];

        CBlockHeader tmp(block);
        tmp.hashRandomX.SetNull();   // set to null when hashing

        {
            AssertLockNotHeld(vmRef.get()->m_hashing_mutex);
            LOCK(vmRef.get()->m_hashing_mutex);
            randomx_calculate_hash(vmRef.get()->vm, &tmp, sizeof(tmp), rx_hash);
        }

        // If not mining, compare hash in block header with our computed value
        if (verifyMode != POW_VERIFY_MINING) {
            if (memcmp(rx_hash, block.hashRandomX.begin(), RANDOMX_HASH_SIZE) != 0) {
                LogPrintf("Error: Possible spam. RandomX hash value in block [%s] != computed hash value [%s]\n",
                    block.hashRandomX.GetHex(), uint256(std::vector<unsigned char>(rx_hash, rx_hash + RANDOMX_HASH_SIZE)).GetHex());
                return false;
            }
        }
        else {
            // If mining, randomx hash generated, so now check if commitment meets target
            hashRandomX = uint256(std::vector<unsigned char>(rx_hash, rx_hash + RANDOMX_HASH_SIZE));
            if (UintToArith256(GetRandomXCommitment(block, &hashRandomX)) > bnTarget) {
                return false;
            }
            fCommitmentVerified = true;
        }
        fHashVerified = true;
    }

    // Sanity check logic
    assert((fHashVerified && fCommitmentVerified) || 
           (verifyMode == POW_VERIFY_COMMITMENT_ONLY && !fHashVerified && fCommitmentVerified));

    if (outHash != NULL) {
        *outHash = hashRandomX;
    }

    return true;
}

// !SCASH END
