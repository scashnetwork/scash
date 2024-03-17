// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2019 The Bitcoin Core developers
// Copyright (c) 2024 The Scash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <primitives/block.h>

#include <hash.h>
#include <tinyformat.h>

// !SCASH
bool g_isRandomX = false;   // global
bool g_isIBDFinished = false;    // global
// !SCASH END

uint256 CBlockHeader::GetHash() const
{
    return (CHashWriter{PROTOCOL_VERSION} << *this).GetHash();
}

std::string CBlock::ToString() const
{
    std::stringstream s;
    // !SCASH
    s << strprintf("CBlock(hash=%s, ver=0x%08x, hashPrevBlock=%s, hashMerkleRoot=%s, nTime=%u, nBits=%08x, nNonce=%u, %svtx=%u)\n",
    // !SCASH END
        GetHash().ToString(),
        nVersion,
        hashPrevBlock.ToString(),
        hashMerkleRoot.ToString(),
        nTime, nBits, nNonce,
        // !SCASH
        g_isRandomX ? "hashRandomX=" + hashRandomX.ToString() + ", " : "",
        // !SCASH END
        vtx.size());
    for (const auto& tx : vtx) {
        s << "  " << tx->ToString() << "\n";
    }
    return s.str();
}
