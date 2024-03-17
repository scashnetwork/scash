// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2021 The Bitcoin Core developers
// Copyright (c) 2024 The Scash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparamsbase.h>

#include <common/args.h>
#include <tinyformat.h>
#include <util/chaintype.h>

#include <assert.h>

void SetupChainParamsBaseOptions(ArgsManager& argsman)
{
// !SCASH
    argsman.AddArg("-chain=<chain>", "Use the chain <chain> (default: main). Allowed values: scash, scashtestnet, scashregtest, main, test, signet, regtest", ArgsManager::ALLOW_ANY, OptionsCategory::CHAINPARAMS);
    argsman.AddArg("-scashregtest", "Enter scash regression test mode. Equivalent to -chain=scashregtest.", ArgsManager::ALLOW_ANY, OptionsCategory::CHAINPARAMS);
    argsman.AddArg("-scashtestnet", "Use the scash test chain. Equivalent to -chain=scashtestnet.", ArgsManager::ALLOW_ANY, OptionsCategory::CHAINPARAMS);
    argsman.AddArg("-scash", "Use the scash chain. Equivalent to -chain=scash.", ArgsManager::ALLOW_ANY, OptionsCategory::CHAINPARAMS);
// !SCASH END
    argsman.AddArg("-regtest", "Enter regression test mode, which uses a special chain in which blocks can be solved instantly. "
                 "This is intended for regression testing tools and app development. Equivalent to -chain=regtest.", ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::CHAINPARAMS);
    argsman.AddArg("-testactivationheight=name@height.", "Set the activation height of 'name' (segwit, bip34, dersig, cltv, csv). (regtest-only)", ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::DEBUG_TEST);
    argsman.AddArg("-testnet", "Use the test chain. Equivalent to -chain=test.", ArgsManager::ALLOW_ANY, OptionsCategory::CHAINPARAMS);
    argsman.AddArg("-vbparams=deployment:start:end[:min_activation_height]", "Use given start/end times and min_activation_height for specified version bits deployment (regtest-only)", ArgsManager::ALLOW_ANY | ArgsManager::DEBUG_ONLY, OptionsCategory::CHAINPARAMS);
    argsman.AddArg("-signet", "Use the signet chain. Equivalent to -chain=signet. Note that the network is defined by the -signetchallenge parameter", ArgsManager::ALLOW_ANY, OptionsCategory::CHAINPARAMS);
    argsman.AddArg("-signetchallenge", "Blocks must satisfy the given script to be considered valid (only for signet networks; defaults to the global default signet test network challenge)", ArgsManager::ALLOW_ANY | ArgsManager::DISALLOW_NEGATION, OptionsCategory::CHAINPARAMS);
    argsman.AddArg("-signetseednode", "Specify a seed node for the signet network, in the hostname[:port] format, e.g. sig.net:1234 (may be used multiple times to specify multiple seed nodes; defaults to the global default signet test network seed node(s))", ArgsManager::ALLOW_ANY | ArgsManager::DISALLOW_NEGATION, OptionsCategory::CHAINPARAMS);
}

static std::unique_ptr<CBaseChainParams> globalChainBaseParams;

const CBaseChainParams& BaseParams()
{
    assert(globalChainBaseParams);
    return *globalChainBaseParams;
}

/**
 * Port numbers for incoming Tor connections (8334, 18334, 38334, 18445) have
 * been chosen arbitrarily to keep ranges of used ports tight.
 */
std::unique_ptr<CBaseChainParams> CreateBaseChainParams(const ChainType chain)
{
    switch (chain) {
    // !SCASH
    case ChainType::MAIN:
        return std::make_unique<CBaseChainParams>("btc", 8332, 8334);
    case ChainType::TESTNET:
        return std::make_unique<CBaseChainParams>("btctestnet3", 18332, 18334);
    case ChainType::SIGNET:
        return std::make_unique<CBaseChainParams>("btcsignet", 38332, 38334);
    case ChainType::REGTEST:
        return std::make_unique<CBaseChainParams>("btcregtest", 18443, 18445);
    case ChainType::SCASHMAIN:
        return std::make_unique<CBaseChainParams>("scash", 8342, 8344);
    case ChainType::SCASHTESTNET:
        return std::make_unique<CBaseChainParams>("scashtestnet", 18342, 18344);
    case ChainType::SCASHREGTEST:
        return std::make_unique<CBaseChainParams>("scashregtest", 18453, 18455);
    // !SCASH END
    }
    assert(false);
}

void SelectBaseParams(const ChainType chain)
{
    globalChainBaseParams = CreateBaseChainParams(chain);
    gArgs.SelectConfigNetwork(ChainTypeToString(chain));
}
