// Copyright (c) 2015-2022 The Bitcoin Core developers
// Copyright (c) 2024 The Scash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <chainparams.h>
#include <pow.h>
#include <test/util/random.h>
#include <test/util/setup_common.h>
#include <util/chaintype.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(pow_tests, BasicTestingSetup)

/* Test calculation of next difficulty target with no constraints applying */
BOOST_AUTO_TEST_CASE(get_next_work)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    int64_t nLastRetargetTime = 1261130161; // Block #30240
    CBlockIndex pindexLast;
    pindexLast.nHeight = 32255;
    pindexLast.nTime = 1262152739;  // Block #32255
    pindexLast.nBits = 0x1d00ffff;

    // Here (and below): expected_nbits is calculated in
    // CalculateNextWorkRequired(); redoing the calculation here would be just
    // reimplementing the same code that is written in pow.cpp. Rather than
    // copy that code, we just hardcode the expected result.
    unsigned int expected_nbits = 0x1d00d86aU;
    BOOST_CHECK_EQUAL(CalculateNextWorkRequired(&pindexLast, nLastRetargetTime, chainParams->GetConsensus()), expected_nbits);
    BOOST_CHECK(PermittedDifficultyTransition(chainParams->GetConsensus(), pindexLast.nHeight+1, pindexLast.nBits, expected_nbits));
}

/* Test the constraint on the upper bound for next work */
BOOST_AUTO_TEST_CASE(get_next_work_pow_limit)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    int64_t nLastRetargetTime = 1231006505; // Block #0
    CBlockIndex pindexLast;
    pindexLast.nHeight = 2015;
    pindexLast.nTime = 1233061996;  // Block #2015
    pindexLast.nBits = 0x1d00ffff;
    unsigned int expected_nbits = 0x1d00ffffU;
    BOOST_CHECK_EQUAL(CalculateNextWorkRequired(&pindexLast, nLastRetargetTime, chainParams->GetConsensus()), expected_nbits);
    BOOST_CHECK(PermittedDifficultyTransition(chainParams->GetConsensus(), pindexLast.nHeight+1, pindexLast.nBits, expected_nbits));
}

/* Test the constraint on the lower bound for actual time taken */
BOOST_AUTO_TEST_CASE(get_next_work_lower_limit_actual)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    int64_t nLastRetargetTime = 1279008237; // Block #66528
    CBlockIndex pindexLast;
    pindexLast.nHeight = 68543;
    pindexLast.nTime = 1279297671;  // Block #68543
    pindexLast.nBits = 0x1c05a3f4;
    unsigned int expected_nbits = 0x1c0168fdU;
    BOOST_CHECK_EQUAL(CalculateNextWorkRequired(&pindexLast, nLastRetargetTime, chainParams->GetConsensus()), expected_nbits);
    BOOST_CHECK(PermittedDifficultyTransition(chainParams->GetConsensus(), pindexLast.nHeight+1, pindexLast.nBits, expected_nbits));
    // Test that reducing nbits further would not be a PermittedDifficultyTransition.
    unsigned int invalid_nbits = expected_nbits-1;
    BOOST_CHECK(!PermittedDifficultyTransition(chainParams->GetConsensus(), pindexLast.nHeight+1, pindexLast.nBits, invalid_nbits));
}

/* Test the constraint on the upper bound for actual time taken */
BOOST_AUTO_TEST_CASE(get_next_work_upper_limit_actual)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    int64_t nLastRetargetTime = 1263163443; // NOTE: Not an actual block time
    CBlockIndex pindexLast;
    pindexLast.nHeight = 46367;
    pindexLast.nTime = 1269211443;  // Block #46367
    pindexLast.nBits = 0x1c387f6f;
    unsigned int expected_nbits = 0x1d00e1fdU;
    BOOST_CHECK_EQUAL(CalculateNextWorkRequired(&pindexLast, nLastRetargetTime, chainParams->GetConsensus()), expected_nbits);
    BOOST_CHECK(PermittedDifficultyTransition(chainParams->GetConsensus(), pindexLast.nHeight+1, pindexLast.nBits, expected_nbits));
    // Test that increasing nbits further would not be a PermittedDifficultyTransition.
    unsigned int invalid_nbits = expected_nbits+1;
    BOOST_CHECK(!PermittedDifficultyTransition(chainParams->GetConsensus(), pindexLast.nHeight+1, pindexLast.nBits, invalid_nbits));
}

BOOST_AUTO_TEST_CASE(CheckProofOfWork_test_negative_target)
{
    const auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    uint256 hash;
    unsigned int nBits;
    nBits = UintToArith256(consensus.powLimit).GetCompact(true);
    hash.SetHex("0x1");
    BOOST_CHECK(!CheckProofOfWork(hash, nBits, consensus));
}

BOOST_AUTO_TEST_CASE(CheckProofOfWork_test_overflow_target)
{
    const auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    uint256 hash;
    unsigned int nBits{~0x00800000U};
    hash.SetHex("0x1");
    BOOST_CHECK(!CheckProofOfWork(hash, nBits, consensus));
}

BOOST_AUTO_TEST_CASE(CheckProofOfWork_test_too_easy_target)
{
    const auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    uint256 hash;
    unsigned int nBits;
    arith_uint256 nBits_arith = UintToArith256(consensus.powLimit);
    nBits_arith *= 2;
    nBits = nBits_arith.GetCompact();
    hash.SetHex("0x1");
    BOOST_CHECK(!CheckProofOfWork(hash, nBits, consensus));
}

BOOST_AUTO_TEST_CASE(CheckProofOfWork_test_biger_hash_than_target)
{
    const auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    uint256 hash;
    unsigned int nBits;
    arith_uint256 hash_arith = UintToArith256(consensus.powLimit);
    nBits = hash_arith.GetCompact();
    hash_arith *= 2; // hash > nBits
    hash = ArithToUint256(hash_arith);
    BOOST_CHECK(!CheckProofOfWork(hash, nBits, consensus));
}

BOOST_AUTO_TEST_CASE(CheckProofOfWork_test_zero_target)
{
    const auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    uint256 hash;
    unsigned int nBits;
    arith_uint256 hash_arith{0};
    nBits = hash_arith.GetCompact();
    hash = ArithToUint256(hash_arith);
    BOOST_CHECK(!CheckProofOfWork(hash, nBits, consensus));
}

BOOST_AUTO_TEST_CASE(GetBlockProofEquivalentTime_test)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    std::vector<CBlockIndex> blocks(10000);
    for (int i = 0; i < 10000; i++) {
        blocks[i].pprev = i ? &blocks[i - 1] : nullptr;
        blocks[i].nHeight = i;
        blocks[i].nTime = 1269211443 + i * chainParams->GetConsensus().nPowTargetSpacing;
        blocks[i].nBits = 0x207fffff; /* target 0x7fffff000... */
        blocks[i].nChainWork = i ? blocks[i - 1].nChainWork + GetBlockProof(blocks[i - 1]) : arith_uint256(0);
    }

    for (int j = 0; j < 1000; j++) {
        CBlockIndex *p1 = &blocks[InsecureRandRange(10000)];
        CBlockIndex *p2 = &blocks[InsecureRandRange(10000)];
        CBlockIndex *p3 = &blocks[InsecureRandRange(10000)];

        int64_t tdiff = GetBlockProofEquivalentTime(*p1, *p2, *p3, chainParams->GetConsensus());
        BOOST_CHECK_EQUAL(tdiff, p1->GetBlockTime() - p2->GetBlockTime());
    }
}

void sanity_check_chainparams(const ArgsManager& args, ChainType chain_type)
{
    const auto chainParams = CreateChainParams(args, chain_type);
    const auto consensus = chainParams->GetConsensus();

    // hash genesis is correct
    BOOST_CHECK_EQUAL(consensus.hashGenesisBlock, chainParams->GenesisBlock().GetHash());

    // target timespan is an even multiple of spacing
    BOOST_CHECK_EQUAL(consensus.nPowTargetTimespan % consensus.nPowTargetSpacing, 0);

    // genesis nBits is positive, doesn't overflow and is lower than powLimit
    arith_uint256 pow_compact;
    bool neg, over;
    pow_compact.SetCompact(chainParams->GenesisBlock().nBits, &neg, &over);
    BOOST_CHECK(!neg && pow_compact != 0);
    BOOST_CHECK(!over);
    BOOST_CHECK(UintToArith256(consensus.powLimit) >= pow_compact);

    // check max target * 4*nPowTargetTimespan doesn't overflow -- see pow.cpp:CalculateNextWorkRequired()

    // SCASH
    if (g_isRandomX && !consensus.fPowNoRetargeting) {
        arith_uint512 targ_max_512("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
        targ_max_512 /= consensus.nPowTargetTimespan*4;
        arith_uint512 powLimit_512 = arith_uint512::from(UintToArith256(consensus.powLimit));
        BOOST_CHECK(powLimit_512 < targ_max_512);
    } else
    // !SCASH END
    if (!consensus.fPowNoRetargeting) {
        arith_uint256 targ_max("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
        targ_max /= consensus.nPowTargetTimespan*4;
        BOOST_CHECK(UintToArith256(consensus.powLimit) < targ_max);
    }
}

BOOST_AUTO_TEST_CASE(ChainParams_MAIN_sanity)
{
    sanity_check_chainparams(*m_node.args, ChainType::MAIN);
}

BOOST_AUTO_TEST_CASE(ChainParams_REGTEST_sanity)
{
    sanity_check_chainparams(*m_node.args, ChainType::REGTEST);
}

BOOST_AUTO_TEST_CASE(ChainParams_TESTNET_sanity)
{
    sanity_check_chainparams(*m_node.args, ChainType::TESTNET);
}

BOOST_AUTO_TEST_CASE(ChainParams_SIGNET_sanity)
{
    sanity_check_chainparams(*m_node.args, ChainType::SIGNET);
}

// !SCASH
BOOST_AUTO_TEST_CASE(ChainParams_SCASHREGTEST_sanity)
{
    g_isRandomX = true;
    sanity_check_chainparams(*m_node.args, ChainType::SCASHREGTEST);
    g_isRandomX = false;
}

BOOST_AUTO_TEST_CASE(ChainParams_SCASHTESTNET_sanity)
{
    g_isRandomX = true;
    sanity_check_chainparams(*m_node.args, ChainType::SCASHTESTNET);
    g_isRandomX = false;
}

BOOST_AUTO_TEST_CASE(ChainParams_SCASHMAIN_sanity)
{
    g_isRandomX = true;
    sanity_check_chainparams(*m_node.args, ChainType::SCASHMAIN);
    g_isRandomX = false;
}

BOOST_AUTO_TEST_CASE(Check_Epoch_Calculation)
{
    // Epoch is unix timestamp in seconds since 1970 divided by epoch duration in seconds
    BOOST_CHECK(0 / 10000 == GetEpoch(0, 10000));
    BOOST_CHECK(1600000000 / 1 == GetEpoch(1600000000, 1));
    BOOST_CHECK(1707328799 / 3600 == GetEpoch(1707328799, 3600));
    BOOST_CHECK_EQUAL(474257, GetEpoch(1707328799, 3600));
    BOOST_CHECK_EQUAL(474258, GetEpoch(1707328800, 3600));
    BOOST_CHECK_EQUAL(474258, GetEpoch(1707330114, 3600));
    BOOST_CHECK_EQUAL(474258, GetEpoch(1707332399, 3600));
    BOOST_CHECK_EQUAL(474259, GetEpoch(1707332400, 3600));
}

BOOST_AUTO_TEST_CASE(Check_RandomX_Key_Generation)
{
    // RandomX key is sha256d of seed string where the epoch number changes
    // "Scash/RandomX/Epoch/1"
    uint256 hash = GetSeedHash(1);
    BOOST_CHECK_EQUAL(hash, uint256S("ccbde830c787b2061cbd9515d9c83d411fcf04cc6e1e47dcc3903c0dee4b1536"));
    // "Scash/RandomX/Epoch/999"
    hash = GetSeedHash(999);
    BOOST_CHECK_EQUAL(hash, uint256S("b8ea6d0f30d6f7250bd8f2f62c9d83a61e1391e14cff95888db3a89bbdd183d5"));
}

BOOST_AUTO_TEST_CASE(Check_RandomX_BlockHeader)
{
    m_node.args->ForceSetArg("-randomxfastmode", "0"); // disable fast mode which requires at least 2GB of memory
    
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::SCASHTESTNET);
    const auto consensus = chainParams->GetConsensus();

    // Sanity check: block header GetHash() function includes RandomX field when running as Scash
    assert(!g_isRandomX);
    BOOST_CHECK_NE(consensus.hashGenesisBlock, chainParams->GenesisBlock().GetHash());
    g_isRandomX = true;
    BOOST_CHECK_EQUAL(consensus.hashGenesisBlock, chainParams->GenesisBlock().GetHash());
    g_isRandomX = false;

    // CheckProofOfWorkRandomX() checks if commitment (computed from block header) meets targett
    CBlockHeader block = chainParams->GenesisBlock().GetBlockHeader();
    assert(CheckProofOfWorkRandomX(block, consensus, POW_VERIFY_COMMITMENT_ONLY)); 
    assert(CheckProofOfWorkRandomX(block, consensus, POW_VERIFY_FULL));

    // Invalid if randomx hash is null, unless in mining mode
    block.hashRandomX.SetNull();
    assert(!CheckProofOfWorkRandomX(block, consensus, POW_VERIFY_COMMITMENT_ONLY));
    assert(!CheckProofOfWorkRandomX(block, consensus, POW_VERIFY_FULL));

    uint256 rx_hash;

    // If block header is valid, the optional outHash is set with the randomx hash
    block = chainParams->GenesisBlock().GetBlockHeader();
    assert(CheckProofOfWorkRandomX(block, consensus, POW_VERIFY_COMMITMENT_ONLY, &rx_hash));
    BOOST_CHECK_EQUAL(rx_hash, chainParams->GenesisBlock().hashRandomX);
    rx_hash.SetNull();
    assert(CheckProofOfWorkRandomX(block, consensus, POW_VERIFY_FULL, &rx_hash));
    BOOST_CHECK_EQUAL(rx_hash, chainParams->GenesisBlock().hashRandomX);

     // If block header is invalid, the optional outHash is not set with the randomx hash
    block.hashRandomX = uint256::ONE;
    rx_hash.SetNull();
    assert(!CheckProofOfWorkRandomX(block, consensus, POW_VERIFY_COMMITMENT_ONLY, &rx_hash));
    BOOST_CHECK_NE(rx_hash, uint256::ONE);
    rx_hash.SetNull();
    assert(!CheckProofOfWorkRandomX(block, consensus, POW_VERIFY_FULL, &rx_hash));
    BOOST_CHECK_NE(rx_hash, uint256::ONE);   

    // Mining requires the outHash parameter
    BOOST_CHECK_THROW(CheckProofOfWorkRandomX(block, consensus, POW_VERIFY_MINING), std::runtime_error);
    BOOST_CHECK_THROW(CheckProofOfWorkRandomX(block, consensus, POW_VERIFY_MINING, NULL), std::runtime_error);

    // Mining success: outHash is set, so miner can add to block header
    block = chainParams->GenesisBlock().GetBlockHeader();
    assert(CheckProofOfWorkRandomX(block, consensus, POW_VERIFY_MINING, &rx_hash));
    BOOST_CHECK_EQUAL(rx_hash, chainParams->GenesisBlock().hashRandomX);
    block.hashRandomX.SetNull();    
    assert(CheckProofOfWorkRandomX(block, consensus, POW_VERIFY_MINING, &rx_hash));
    BOOST_CHECK_EQUAL(rx_hash, chainParams->GenesisBlock().hashRandomX);

    // Mining fails: outHash parameter is not set
    block.nNonce = 123456;
    rx_hash.SetNull();
    assert(!CheckProofOfWorkRandomX(block, consensus, POW_VERIFY_MINING, &rx_hash));
    assert(rx_hash.IsNull());
    rx_hash = uint256(123);
    assert(!CheckProofOfWorkRandomX(block, consensus, POW_VERIFY_MINING, &rx_hash));
    BOOST_CHECK_EQUAL(rx_hash, uint256(123));

    // Light verification can be useful when blocks are already known to be fully verified.
    // The trade-off is reduced security. For example, a RandomX hash value in the block header
    // can be chosen so that the commitment meets the target, even though the hash is invalid.
    // rx = 0a4a15246bd06225436f4bbfa9f8c8e1c027435edd4dd6854295f877176b6607
    // cm = 000023da558c59d4cadbb3dd60078a55be1c2e10ed9b3e43628cf609561d2392
    block = chainParams->GenesisBlock().GetBlockHeader();
    block.hashRandomX = uint256S("0a4a15246bd06225436f4bbfa9f8c8e1c027435edd4dd6854295f877176b6607");
    assert(CheckProofOfWorkRandomX(block, consensus, POW_VERIFY_COMMITMENT_ONLY));
    assert(!CheckProofOfWorkRandomX(block, consensus, POW_VERIFY_FULL));

    // Commitment calculation requires Randomx hash value in block header to be null
    block = chainParams->GenesisBlock().GetBlockHeader();
    rx_hash = block.hashRandomX;
	char rx_cm_bad[RANDOMX_HASH_SIZE];
    randomx_calculate_commitment(&block, sizeof(block), rx_hash.data(), rx_cm_bad);
    block.hashRandomX = uint256();
	char rx_cm[RANDOMX_HASH_SIZE];
    randomx_calculate_commitment(&block, sizeof(block), rx_hash.data(), rx_cm);
    assert(memcmp(rx_cm, rx_cm_bad, sizeof(rx_cm)) != 0);
    BOOST_CHECK_EQUAL(uint256(std::vector<unsigned char>(rx_cm, rx_cm + sizeof(rx_cm))), uint256S("0000388a6a0aa5eaa14ce3aa066106e1d3f82a05b4a8fc6c6c7b128924a24868"));

    // Basic tests of GetRandomXCommitment()
    block = chainParams->GenesisBlock();
    uint256 cm = GetRandomXCommitment(chainParams->GenesisBlock());
    BOOST_CHECK_EQUAL(cm, uint256S("0000388a6a0aa5eaa14ce3aa066106e1d3f82a05b4a8fc6c6c7b128924a24868"));
    cm = GetRandomXCommitment(chainParams->GenesisBlock(), NULL);
    BOOST_CHECK_EQUAL(cm, uint256S("0000388a6a0aa5eaa14ce3aa066106e1d3f82a05b4a8fc6c6c7b128924a24868"));
    // set inHash parameter
    cm = GetRandomXCommitment(chainParams->GenesisBlock(), &block.hashRandomX);
    BOOST_CHECK_EQUAL(cm, uint256S("0000388a6a0aa5eaa14ce3aa066106e1d3f82a05b4a8fc6c6c7b128924a24868"));
    rx_hash = uint256(123);
    cm = GetRandomXCommitment(chainParams->GenesisBlock(), &rx_hash);
    BOOST_CHECK_NE(cm, uint256S("0000388a6a0aa5eaa14ce3aa066106e1d3f82a05b4a8fc6c6c7b128924a24868"));
}

// !SCASH END

BOOST_AUTO_TEST_SUITE_END()
