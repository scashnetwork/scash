// Copyright (c) 2023 The Bitcoin Core developers
// Copyright (c) 2024 The Scash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_UTIL_CHAINTYPE_H
#define BITCOIN_UTIL_CHAINTYPE_H

#include <optional>
#include <string>

enum class ChainType {
    MAIN,
    TESTNET,
    SIGNET,
    REGTEST,
    // !SCASH
    SCASHMAIN,
    SCASHTESTNET,
    SCASHREGTEST
    // !SCASH END
};

std::string ChainTypeToString(ChainType chain);

std::optional<ChainType> ChainTypeFromString(std::string_view chain);

#endif // BITCOIN_UTIL_CHAINTYPE_H
