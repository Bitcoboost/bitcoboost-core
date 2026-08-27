// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <primitives/block.h>

#include <hash.h>
#include <tinyformat.h>

// Bitcoboost: per la nuova mainnet X16RV2 e attivo dal blocco 0.
// Il check temporale BB_X16RV2_ACTIVATION_TIME era usato dalla chain di
// sviluppo per fare un soft fork mid-chain e non e piu necessario.
uint256 CBlockHeader::GetHash() const
{
    const unsigned char* pbegin = reinterpret_cast<const unsigned char*>(&nVersion);
    const unsigned char* pend = reinterpret_cast<const unsigned char*>(&nNonce) + sizeof(nNonce);
    return HashX16RV2(pbegin, pend, hashPrevBlock);
}

std::string CBlock::ToString() const
{
    std::stringstream s;
    s << strprintf("CBlock(hash=%s, ver=0x%08x, hashPrevBlock=%s, hashMerkleRoot=%s, nTime=%u, nBits=%08x, nNonce=%u, vtx=%u)\n",
        GetHash().ToString(),
        nVersion,
        hashPrevBlock.ToString(),
        hashMerkleRoot.ToString(),
        nTime, nBits, nNonce,
        vtx.size());
    for (const auto& tx : vtx) {
        s << "  " << tx->ToString() << "\n";
    }
    return s.str();
}
