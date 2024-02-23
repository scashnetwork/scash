// Copyright (c) 2023 The Bitcoin Core developers
// Copyright (c) 2024 The Scash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <util/chaintype.h>

#include <cassert>
#include <optional>
#include <string>

std::string ChainTypeToString(ChainType chain)
{
    switch (chain) {
    case ChainType::MAIN:
        return "main";
    case ChainType::TESTNET:
        return "test";
    case ChainType::SIGNET:
        return "signet";
    case ChainType::REGTEST:
        return "regtest";
    // !SCASH
    case ChainType::SCASHMAIN:
        return "scash";
    case ChainType::SCASHTESTNET:
        return "scashtestnet";
    case ChainType::SCASHREGTEST:
        return "scashregtest";
    // !SCASH END
    }
    assert(false);
}

std::optional<ChainType> ChainTypeFromString(std::string_view chain)
{
    if (chain == "main") {
        return ChainType::MAIN;
    } else if (chain == "test") {
        return ChainType::TESTNET;
    } else if (chain == "signet") {
        return ChainType::SIGNET;
    } else if (chain == "regtest") {
        return ChainType::REGTEST;
    // !SCASH
    } else if (chain == "scash") {
        return ChainType::SCASHMAIN;
    } else if (chain == "scashtestnet") {
        return ChainType::SCASHTESTNET;
    } else if (chain == "scashregtest") {
        return ChainType::SCASHREGTEST;
    // !SCASH END
    } else {
        return std::nullopt;
    }
}
