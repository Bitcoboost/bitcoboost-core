// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pow.h>

#include <arith_uint256.h>
#include <chain.h>
#include <primitives/block.h>
#include <uint256.h>

// Bitcoboost: helper per il retarget veloce iniziale.
// Restituisce l'intervallo di retarget effettivo a una data altezza:
// - Per i primi nFastRetargetUntilHeight blocchi: nFastRetargetPeriod (es. 144 ~= 1 giorno)
// - Dopo: DifficultyAdjustmentInterval() standard (es. 2016 ~= 2 settimane)
static int64_t BBGetRetargetInterval(int nHeight, const Consensus::Params& params)
{
    if (params.nFastRetargetPeriod > 0 &&
        params.nFastRetargetUntilHeight > 0 &&
        nHeight < params.nFastRetargetUntilHeight) {
        return params.nFastRetargetPeriod;
    }
    return params.DifficultyAdjustmentInterval();
}

// Bitcoboost: helper per il timespan target effettivo a una data altezza.
// Quando il retarget e veloce (es. ogni 144 blocchi invece di 2016),
// il timespan atteso scala proporzionalmente.
static int64_t BBGetTargetTimespan(int nHeight, const Consensus::Params& params)
{
    int64_t interval = BBGetRetargetInterval(nHeight, params);
    return interval * params.nPowTargetSpacing;
}

// --- Bitcoboost LWMA-1 (Zawy): difficolta ricalcolata a ogni blocco su nLwmaWindow blocchi. ---
// Blindata contro il trabocco a 256 bit: se il target calcolato supererebbe powLimit, si fissa powLimit.
static unsigned int LwmaGetNextWorkRequired(const CBlockIndex* pindexLast, const Consensus::Params& params)
{
    const int64_t T = params.nPowTargetSpacing;
    const int64_t N = params.nLwmaWindow;
    const int64_t k = N * (N + 1) * T / 2;
    const int64_t height = pindexLast->nHeight + 1;
    const arith_uint256 powLimit = UintToArith256(params.powLimit);

    if (pindexLast->nHeight < N) return pindexLast->nBits;

    arith_uint256 sum_target;
    int64_t t = 0, j = 0;
    for (int64_t i = height - N; i < height; i++) {
        const CBlockIndex* block = pindexLast->GetAncestor(i);
        const CBlockIndex* blockPrev = pindexLast->GetAncestor(i - 1);
        int64_t solvetime = block->GetBlockTime() - blockPrev->GetBlockTime();
        if (solvetime > 6 * T) solvetime = 6 * T;
        j++;
        t += solvetime * j;
        arith_uint256 target;
        target.SetCompact(block->nBits);
        sum_target += target / (k * N);
    }
    if (t < k / 10) t = k / 10;

    arith_uint256 tt = arith_uint256((uint64_t)t);
    arith_uint256 next_target;
    if (sum_target > powLimit / tt) {
        next_target = powLimit;
    } else {
        next_target = sum_target * tt;
        if (next_target > powLimit) next_target = powLimit;
    }
    return next_target.GetCompact();
}

// Bitcoboost: LWMA e' attivo per il blocco che segue pindexLast?
// A DATA se nLwmaTime e' impostata (median-time-past, robusto ai timestamp singoli);
// altrimenti ad ALTEZZA se nLwmaHeight e' impostata (usata nelle prove).
static bool BBLwmaAttivo(const CBlockIndex* pindexLast, const Consensus::Params& params)
{
    if (params.nLwmaTime > 0) return pindexLast->GetMedianTimePast() >= params.nLwmaTime;
    if (params.nLwmaHeight > 0) return (pindexLast->nHeight + 1) >= params.nLwmaHeight;
    return false;
}

unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params)
{
    assert(pindexLast != nullptr);
    unsigned int nProofOfWorkLimit = UintToArith256(params.powLimit).GetCompact();

    // Bitcoboost: dall'attivazione, difficolta ricalcolata a OGNI blocco (LWMA).
    if (BBLwmaAttivo(pindexLast, params)) {
        return LwmaGetNextWorkRequired(pindexLast, params);
    }

    // Bitcoboost: usa l'intervallo di retarget appropriato (veloce in early launch, normale dopo).
    int64_t nRetargetInterval = BBGetRetargetInterval(pindexLast->nHeight + 1, params);

    // Only change once per difficulty adjustment interval
    if ((pindexLast->nHeight+1) % nRetargetInterval != 0)
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
                while (pindex->pprev && pindex->nHeight % nRetargetInterval != 0 && pindex->nBits == nProofOfWorkLimit)
                    pindex = pindex->pprev;
                return pindex->nBits;
            }
        }
        return pindexLast->nBits;
    }

    // Go back by the retarget interval (1 day in fast mode, 2 weeks in normal)
    int nHeightFirst = pindexLast->nHeight - (nRetargetInterval - 1);
    assert(nHeightFirst >= 0);
    const CBlockIndex* pindexFirst = pindexLast->GetAncestor(nHeightFirst);
    assert(pindexFirst);

    return CalculateNextWorkRequired(pindexLast, pindexFirst->GetBlockTime(), params);
}

unsigned int CalculateNextWorkRequired(const CBlockIndex* pindexLast, int64_t nFirstBlockTime, const Consensus::Params& params)
{
    if (params.fPowNoRetargeting)
        return pindexLast->nBits;

    // Bitcoboost: usa il timespan effettivo per questa altezza.
    int64_t nTargetTimespan = BBGetTargetTimespan(pindexLast->nHeight + 1, params);

    // Limit adjustment step
    int64_t nActualTimespan = pindexLast->GetBlockTime() - nFirstBlockTime;
    if (nActualTimespan < nTargetTimespan/4)
        nActualTimespan = nTargetTimespan/4;
    if (nActualTimespan > nTargetTimespan*4)
        nActualTimespan = nTargetTimespan*4;

    // Retarget
    const arith_uint256 bnPowLimit = UintToArith256(params.powLimit);
    arith_uint256 bnNew;
    bnNew.SetCompact(pindexLast->nBits);
    bnNew *= nActualTimespan;
    bnNew /= nTargetTimespan;

    if (bnNew > bnPowLimit)
        bnNew = bnPowLimit;

    return bnNew.GetCompact();
}

// Check that on difficulty adjustments, the new difficulty does not increase
// or decrease beyond the permitted limits.
bool PermittedDifficultyTransition(const Consensus::Params& params, int64_t height, uint32_t old_nbits, uint32_t new_nbits)
{
    if (params.fPowAllowMinDifficultyBlocks) return true;
    if (params.nLwmaHeight > 0 && height >= params.nLwmaHeight) return true;

    // Bitcoboost: usa intervallo + timespan effettivi a questa altezza.
    int64_t nRetargetInterval = BBGetRetargetInterval((int)height, params);
    int64_t nTargetTimespan = BBGetTargetTimespan((int)height, params);

    if (height % nRetargetInterval == 0) {
        int64_t smallest_timespan = nTargetTimespan/4;
        int64_t largest_timespan = nTargetTimespan*4;

        const arith_uint256 pow_limit = UintToArith256(params.powLimit);
        arith_uint256 observed_new_target;
        observed_new_target.SetCompact(new_nbits);

        // Calculate the largest difficulty value possible:
        arith_uint256 largest_difficulty_target;
        largest_difficulty_target.SetCompact(old_nbits);
        largest_difficulty_target *= largest_timespan;
        largest_difficulty_target /= nTargetTimespan;

        if (largest_difficulty_target > pow_limit) {
            largest_difficulty_target = pow_limit;
        }

        // Round and then compare this new calculated value to what is
        // observed.
        arith_uint256 maximum_new_target;
        maximum_new_target.SetCompact(largest_difficulty_target.GetCompact());
        if (maximum_new_target < observed_new_target) return false;

        // Calculate the smallest difficulty value possible:
        arith_uint256 smallest_difficulty_target;
        smallest_difficulty_target.SetCompact(old_nbits);
        smallest_difficulty_target *= smallest_timespan;
        smallest_difficulty_target /= nTargetTimespan;

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
    // [BB-LAUNCH] Genesis block exception: the genesis is hardcoded and validated
    // via assert() in chainparams.cpp. Skip PoW check when hash == hashGenesisBlock
    // to allow a low-difficulty genesis (Litecoin-style, nBits=0x1f00ffff)
    // while keeping the chain's powLimit at Bitcoin-style 0x00000000ffff... for security.
    if (hash == params.hashGenesisBlock) {
        return true;
    }

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
