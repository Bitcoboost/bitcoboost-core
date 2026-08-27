// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <kernel/chainparams.h>

#include <chainparamsseeds.h>
#include <consensus/amount.h>
#include <consensus/merkle.h>
#include <consensus/params.h>
#include <hash.h>
#include <arith_uint256.h>
#include <kernel/messagestartchars.h>
#include <logging.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <uint256.h>
#include <util/chaintype.h>
#include <util/strencodings.h>

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <type_traits>
#include <memory>

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database.
 *
 * CBlock(hash=000000000019d6, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=4a5e1e, nTime=1231006505, nBits=1d00ffff, nNonce=2083236893, vtx=1)
 *   CTransaction(hash=4a5e1e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73)
 *     CTxOut(nValue=50.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
 *   vMerkleTree: 4a5e1e
 */
static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks";
    const CScript genesisOutputScript = CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

/**
 * Main network on which people trade goods and services.
 */
class CMainParams : public CChainParams {
public:
    CMainParams() {
        m_chain_type = ChainType::MAIN;
        consensus.signet_blocks = false;
        consensus.signet_challenge.clear();
        consensus.nSubsidyHalvingInterval = 210000;
        consensus.script_flag_exceptions.clear();
        // BIP heights: per una chain fresca, attiviamo tutti i fork da subito (height 0/1)
        consensus.BIP34Height = 17;
        consensus.BIP34Hash = uint256();
        consensus.BIP65Height = 1;
        consensus.BIP66Height = 1;
        consensus.CSVHeight = 1;
        consensus.SegwitHeight = 0;
        consensus.MinBIP9WarningHeight = 0;

        // Bitcoboost mainnet: powLimit Bitcoin-style (NON testnet).
        // Garantisce difficolta minima sufficiente a difendere la chain dal 51% attack.
        consensus.powLimit = uint256S("0000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // due settimane
        consensus.nPowTargetSpacing = 10 * 60;            // 10 minuti
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1815;  // 90% di 2016
        consensus.nMinerConfirmationWindow = 2016;

        // Bitcoboost: retarget veloce nei primi blocchi del lancio.
        // Per i primi 2016 blocchi retargetiamo ogni 144 blocchi (~1 giorno)
        // invece dei 2016 standard (~2 settimane). Stabilizza la difficolta in early launch.
        consensus.nFastRetargetPeriod = 144;
        consensus.nFastRetargetUntilHeight = 2016;

        // BIP9 deployments
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].min_activation_height = 0;

        // Taproot: sempre attivo
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].min_activation_height = 0;

        consensus.nMinimumChainWork = uint256();
        consensus.defaultAssumeValid = uint256();

        // Bitcoboost: magic bytes nuovi per la mainnet di lancio.
        // Diversi dalla chain di sviluppo (0xFB 0xC0 0xB0 0x57) per garantire che
        // i nodi della chain vecchia NON si confondano con quelli della nuova.
        pchMessageStart[0] = 0xBB;
        pchMessageStart[1] = 0x16;
        pchMessageStart[2] = 0x06;
        pchMessageStart[3] = 0x26;
        nDefaultPort = 38210;
        nPruneAfterHeight = 100000;
        m_assumed_blockchain_size = 1;
        m_assumed_chain_state_size = 1;

        // ============================================================
        // BITCOBOOST GENESIS BLOCK
        // ============================================================
        // I valori qui sotto sono PLACEHOLDER. Vanno computati al momento della
        // compilazione di lancio con un tool dedicato (gen_genesis.py o equivalente)
        // che faccia loop sul nNonce fino a trovare un hash valido sotto powLimit.
        //
        // Procedura prima del lancio:
        //   1. Aggiornare LAUNCH_TIMESTAMP al momento del lancio reale
        //   2. Eseguire il genesis miner per trovare nNonce valido
        //   3. Aggiornare GENESIS_HASH e GENESIS_MERKLE con i valori computati
        //   4. RIATTIVARE gli assert qui sotto
        // ============================================================
        {
            const char* pszTimestamp = "Bitcoboost fair-launch 2026-05-09 - opportunity for everyone";
            const CScript genesisOutputScript =
                CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f")
                          << OP_CHECKSIG;

            // PLACEHOLDER values - DA SOSTITUIRE prima del lancio
            const uint32_t nTime  = 1778351316;  // 2026-05-09 18:28:36 UTC
            const uint32_t nNonce = 19717;       // 2026-05-09 mining genesis (X16RV2, target 1f00ffff)
            const uint32_t nBits  = 0x1f00ffff;  // genesis-only easy difficulty (Litecoin-style); chain runs at powLimit 00000000ffff... after

            genesis = CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, 1, 50 * COIN);
            consensus.hashGenesisBlock = genesis.GetHash();
            // [BB-LAUNCH] GENESIS MINER - attivato con -DBB_GENESIS_MINER
#ifdef BB_GENESIS_MINER
            if (genesis.nNonce == 0) {
                fprintf(stderr, "\n=== BB-LAUNCH GENESIS MINER ===\n");
                fprintf(stderr, "powLimit (consensus): %s\n", consensus.powLimit.GetHex().c_str());
                arith_uint256 target;
                target.SetCompact(genesis.nBits);
                fprintf(stderr, "target (from nBits %08x): %s\n", genesis.nBits, target.GetHex().c_str());
                fprintf(stderr, "Mining...\n");
                uint32_t nonce = 0;
                uint256 hash;
                time_t start = time(NULL);
                while (true) {
                    genesis.nNonce = nonce;
                    hash = genesis.GetHash();
                    if (UintToArith256(hash) <= target) {
                        time_t elapsed = time(NULL) - start;
                        fprintf(stderr, "\n=== GENESIS FOUND in %ld seconds ===\n", (long)elapsed);
                        fprintf(stderr, "nNonce         = %u\n", nonce);
                        fprintf(stderr, "hashGenesis    = 0x%s\n", hash.ToString().c_str());
                        fprintf(stderr, "hashMerkleRoot = 0x%s\n", genesis.hashMerkleRoot.ToString().c_str());
                        fprintf(stderr, "nTime          = %u\n", genesis.nTime);
                        fprintf(stderr, "==============================\n");
                        std::abort();
                    }
                    nonce++;
                    if ((nonce & 0xFFFFF) == 0) {
                        time_t now = time(NULL);
                        long el = (long)(now - start);
                        double rate = el > 0 ? (double)nonce / (double)el : 0.0;
                        fprintf(stderr, "[mining] nonce=%u, rate=%.0f H/s, elapsed=%lds\n", nonce, rate, el);
                    }
                    if (nonce == 0) {
                        fprintf(stderr, "WARNING: nonce overflow, mining failed!\n");
                        std::abort();
                    }
                }
            }
#endif


            // ============================================================
            // SECURITY ASSERTS - DA RIATTIVARE prima del lancio
            // ============================================================
            // Quando il genesis e stato computato, sostituire i due commenti
            // qui sotto con assert reali tipo:
            //   assert(consensus.hashGenesisBlock == uint256S("0x...computed_hash..."));
            //   assert(genesis.hashMerkleRoot == uint256S("0x...computed_merkle..."));
            //
            // [BB-LAUNCH] SECURITY ASSERTS REENABLED (post-genesis-mining 2026-05-09)
            assert(consensus.hashGenesisBlock == uint256S("0x00008e92cdd72d798964ea9833c612371e93ddbcbb6a8a1ffe71e591f5b017df"));
            assert(genesis.hashMerkleRoot == uint256S("0xec73889053e9e804e45018ca6640a9b00e7378da75b5cc351d25992b762f1105"));
        }

        // DNS seed nodes Bitcoboost.
        // VANNO REGISTRATI prima del lancio con record A puntati a 2-3 VPS attive
        // che eseguono bitcoboostd come full node always-on.
        vSeeds.clear();
        vSeeds.emplace_back("seed1.bitcoboost.com");
        vSeeds.emplace_back("seed2.bitcoboost.com");
        vSeeds.emplace_back("seed3.bitcoboost.com");
        vFixedSeeds.clear();

        // Address prefixes (mantenuti dalla chain precedente per coerenza identita)
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 25);   // 'B'
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 85);
        base58Prefixes[SECRET_KEY]     = std::vector<unsigned char>(1, 153);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0xBB, 0x61, 0xB0};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0xBB, 0x5A, 0xC0};

        bech32_hrp = "bb";

        fDefaultConsistencyChecks = false;
        m_is_mockable_chain = false;

        // Checkpoint vuoti: chain fresca, niente da hard-codare ancora.
        // Si potranno aggiungere checkpoint dopo il lancio man mano che
        // i blocchi consolidati superano migliaia di confirmations.
        // Checkpoint placeholder: solo il genesis (altezza 0).
        // E necessario almeno un checkpoint nella mappa, perche
        // CCheckpointData::GetHeight() fa rbegin()->first che su una
        // mappa vuota e undefined behavior (segfault).
        // Si aggiungeranno checkpoint reali in release future man mano
        // che i blocchi consolidati superano migliaia di confirmations.
        checkpointData = {
            {
                {0, consensus.hashGenesisBlock},
                {840, uint256S("0000002d1874ec0c1374808e01192f62103adfea7ad474526b01c4f7b88cdbf0")},
                {1500, uint256S("0000000041930cc785c8ad4caf8afc026fdc5d179a41f89db294136c38e2cd42")},
                {1640, uint256S("000000003581dd9c41a96d9e500a5a7094cbf0a14bd7923a942edc882eae8fa9")},
                {1880, uint256S("00000000897ebe8e92b482eedf08b40746d40cb896029bda6d5e93c91420c8a0")},
                {2100, uint256S("00000001fed99603b6d750864ff043fd32d67519cee0d80aba676da275521be9")},
                {2660, uint256S("000000009c5a62410be564294a02fb0400ddb0c31bbfe6e103c0965ca3edbc80")},
                {3240, uint256S("000000005f298a3af1a06e3494723ca0043cd5a4f180498cbf103c847f71f852")},
                {3740, uint256S("0000000122b0dd1df2354e0d6ff5820ac1ff826aec2f03275571aaf310685a67")},
                {4040, uint256S("0000000077050b48386d229b3f2172fd4742d6bc98aaa62bd09387577d9dc3fb")},
                {4180, uint256S("0000000009bee0c94ca69ec3acc2b9b70da1ff1b66fb82f0395c3b29598816e6")},
                {4340, uint256S("00000000918646f8dc53022d6f2d0b45cf170ce3bf0b1ca71b9dda14e868b8b3")},
                {4580, uint256S("000000001c42b1750393b63bfc397dcd570245e40a481a6b0c43e9b2a05858dd")},
                {4740, uint256S("000000000dd0a2501141f61e61c89216c849b2790218de06a0905241aa7c395d")},
                {4960, uint256S("000000002aab82b30e62f735b98f61611fb14f02125a55757f491bdac0d5f928")},
                {7540, uint256S("000000004cbcff6c7c1f9330b704b9598c9ede9b3501dff5ac011a13edd6bac0")},
                {8120, uint256S("0000000001d832ca31a03906f340f18a83aa08e99d3001939788a55619efd181")},
                {8260, uint256S("00000000094b5f247c407fa5005ec985bb424e7ab654355f2e219cc4fbebf66a")},
                {8440, uint256S("0000000012214aae2069c36ac3c8355cf4afa95ff8e9f9cda0033d266b86a531")},
                {9340, uint256S("000000001570a17860b7a662c9f2fefe0fd4e593d0b7d0c562927e97658ee0b3")},
                {10100, uint256S("00000000068173ae8bf7588f662efa398041baaa1cec7f8d8a27003797a8697e")},
                {10280, uint256S("000000000666126bd288356eb5a06ba418422307f8ab941ace5177b85fcb80ba")},
                {10380, uint256S("0000000000d84798de81c2a9c7fccde753c70c49d1caaf1b37342623c1a1c878")},
                {10600, uint256S("0000000004288aaf035cc7f0625b2074a7a1d84b04f6cced3d27a70763c893a1")},
                {10800, uint256S("000000000237341d3d3f0172d991a79e6e552e4b53169bfc2142d61273eb9413")},
                {10940, uint256S("00000000040cf12dd4982cc15c0e6516a84ddb6e3b99d7261ec45a501ff38764")},
                {11080, uint256S("0000000003aebbdf2fffe872177d766e8549f46686ca8ae5e866aef615431c2a")},
                {11220, uint256S("000000000558147bbc0a0470d19bd1592cf809af992ec2d2a05a07f1df328889")},
                {11320, uint256S("000000000693770481d9d1c0769c45ccfa61b8d684ffb8c5b8603f566ded8615")},
                {11420, uint256S("0000000000b67a0516a2e675b151809b4fb227aa180c5d79591cd6de0ca5e33f")},
                {11600, uint256S("0000000000952e73d7069c4fb5219747c6a0d07e526f1bbd9cd5cca199c981fa")},
                {11760, uint256S("0000000002cf7ed61b5a69dda712b8112c3d740a8a10bff811d9aef19a1c9422")},
                {11880, uint256S("00000000046fd4d0254808b872e6c553fed52044e9aec469b9c32211be74429d")},
                {11980, uint256S("0000000004d01bc8012a2b6b1f0b960c6e3d406b0ed0dbe564d44f52461fd70d")},
                {12240, uint256S("000000000990083f2ec71b047775dd1431989acd105188494b022c9deaec943d")},
                {12520, uint256S("000000000282e4248efc9bd87827125b383de8c2836e6b07ce2fa29c54ff07f5")},
                {12720, uint256S("000000000868b606f5cc7533446185202b473bb9d8546d6720edda41686a86ce")},
                {12960, uint256S("000000000545150dcfa6f4c9100d2f79c909d5aafefaecfe687d8051174eba25")},
                {13200, uint256S("00000000009ea1baa4c59ad2223f1856b724725866f594214074fcf996516d40")},
                {13500, uint256S("00000000059bdf93b4e7bf588fe0dbea7174c0076d26ad728d92c903e9f3f762")},
                {13660, uint256S("0000000002a11746756bfe7d4977601c8ded7a97f70336ac6995918533043b62")},
                {13980, uint256S("00000000026d405792886e008b616e36edf9bc985cbe80dd14cf27d422202821")},
                {14120, uint256S("00000000058b4201ce26efdb50047f8834c077d4c2592ece4d597b400952e56e")},
                {14260, uint256S("0000000005171fe862bc31c3058b72fdbcc08806c16eeac98565b2c37e400daf")},
                {14360, uint256S("0000000000d55375fc0c7fb2094bcd69089f6e3329e40eee2f6ad7e13126deda")},
                {14460, uint256S("000000000531ee15242cd94ba402a150bc450f8c2fe57f45f9361cd771e0b7ea")},
            }
        };

        m_assumeutxo_data = {
            // Vuoto: non abbiamo ancora UTXO assumevalid da fornire
        };

        // chainTxData: statistiche reali Bitcoboost (azzerato per chain fresca).
        // Verra aggiornato in release future con dati reali della chain.
        chainTxData = ChainTxData{
            .nTime    = 0,
            .nTxCount = 0,
            .dTxRate  = 0.0,
        };
    }
};

/**
 * Testnet (v3): public test network which is reset from time to time.
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        m_chain_type = ChainType::TESTNET;
        consensus.signet_blocks = false;
        consensus.signet_challenge.clear();
        consensus.nSubsidyHalvingInterval = 210000;
        consensus.script_flag_exceptions.emplace( // BIP16 exception
            uint256S("0x00000000dd30457c001f4095d208cc1296b0eed002427aa599874af7a432b105"), SCRIPT_VERIFY_NONE);
        consensus.BIP34Height = 21111;
        consensus.BIP34Hash = uint256S("0x0000000023b3a96d3484e5abb3755c413e7d41500f8e2a5c3f0dd01299cd8ef8");
        consensus.BIP65Height = 581885; // 00000000007f6655f22f98e72ed80d8b06dc761d5da09df0fa1dc4be4f861eb6
        consensus.BIP66Height = 330776; // 000000002104c8c45e99a8853285a3b592602a3ccde2b832481da85e9e4ba182
        consensus.CSVHeight = 770112; // 00000000025e930139bac5c6c31a403776da130831ab85be56578f3fa75369bb
        consensus.SegwitHeight = 834624; // 00000000002b980fcd729daaa248fd9316a5200e9b367f4ff2c42453e84201ca
        consensus.MinBIP9WarningHeight = 836640; // segwit activation height + miner confirmation window
        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1512; // 75% for testchains
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].min_activation_height = 0; // No activation delay

        // Deployment of Taproot (BIPs 340-342)
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartTime = 1619222400; // April 24th, 2021
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nTimeout = 1628640000; // August 11th, 2021
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].min_activation_height = 0; // No activation delay

        consensus.nMinimumChainWork = uint256();
	consensus.defaultAssumeValid = uint256();

        pchMessageStart[0] = 0x0b;
        pchMessageStart[1] = 0x11;
        pchMessageStart[2] = 0x09;
        pchMessageStart[3] = 0x07;
        nDefaultPort = 38210;
        nPruneAfterHeight = 1000;
        m_assumed_blockchain_size = 42;
        m_assumed_chain_state_size = 3;

// ===== Bitcoboost TESTNET genesis =====
// ===== Bitcoboost TESTNET genesis =====
genesis = CreateGenesisBlock(1758070800, 0, 0x207fffff, 1, 50 * COIN);
consensus.hashGenesisBlock = genesis.GetHash();
        // ASSERT DISABLED: /* assert(disabled) */
// ASSERT DISABLED: /* assert(disabled) */

        vFixedSeeds.clear();
        vSeeds.clear();
        vSeeds.emplace_back("testnet-seed.bitcoboost.example");
        // nodes with support for servicebits filtering should be at the top
        // BB: disabled seed: emplace_back("testnet-seed.bitcoin.jonasschnelli.ch.");
        // BB: disabled seed: emplace_back("seed.tbtc.petertodd.net.");
        // BB: disabled seed: emplace_back("seed.testnet.bitcoin.sprovoost.nl.");
        // BB: disabled seed: emplace_back("testnet-seed.bluematt.me."); // Just a static list of stable node(s), only supports x9

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "tb";

        vFixedSeeds = std::vector<uint8_t>(std::begin(chainparams_seed_test), std::end(chainparams_seed_test));

        fDefaultConsistencyChecks = false;
        m_is_mockable_chain = false;

        checkpointData = {
            {
                {546, uint256S("000000002a936ca763904c3c35fce2f3556c559c0214345d31b1bcebf76acb70")},
            }
        };

        m_assumeutxo_data = {
            {
                .height = 2'500'000,
                .hash_serialized = AssumeutxoHash{uint256S("0xf841584909f68e47897952345234e37fcd9128cd818f41ee6c3ca68db8071be7")},
                .nChainTx = 66484552,
                .blockhash = uint256S("0x0000000000000093bcb68c03a9a168ae252572d348a2eaeba2cdf9231d73206f")
            }
        };

        chainTxData = ChainTxData{
            // Data from RPC: getchaintxstats 4096 000000000001323071f38f21ea5aae529ece491eadaccce506a59bcc2d968917
            .nTime    = 1703579240,
            .nTxCount = 67845391,
            .dTxRate  = 1.464436832560951,
        };
    }
};

/**
 * Signet: test network with an additional consensus parameter (see BIP325).
 */
class SigNetParams : public CChainParams {
public:
    explicit SigNetParams(const SigNetOptions& options)
    {
        std::vector<uint8_t> bin;
        vSeeds.clear();
        vSeeds.emplace_back("regtest-seed.bitcoboost.example");

        if (!options.challenge) {
            bin = ParseHex("512103ad5e0edad18cb1f0fc0d28a3d4f1f3e445640337489abb10404f2d1e086be430210359ef5021964fe22d6f8e05b2463c9540ce96883fe3b278760f048f5189f2e6c452ae");
            // BB: disabled seed: emplace_back("seed.signet.bitcoin.sprovoost.nl.");

            // Hardcoded nodes can be removed once there are more DNS seeds
            // BB: disabled seed: emplace_back("178.128.221.177");
            // BB: disabled seed: emplace_back("v7ajjeirttkbnt32wpy3c6w3emwnfr3fkla7hpxcfokr3ysd3kqtzmqd.onion:38333");

            consensus.nMinimumChainWork = uint256();
	    consensus.defaultAssumeValid = uint256();

            m_assumed_blockchain_size = 1;
            m_assumed_chain_state_size = 0;
            chainTxData = ChainTxData{
                // Data from RPC: getchaintxstats 4096 0000000870f15246ba23c16e370a7ffb1fc8a3dcf8cb4492882ed4b0e3d4cd26
                .nTime    = 1706331472,
                .nTxCount = 2425380,
                .dTxRate  = 0.008277759863833788,
            };
        } else {
            bin = *options.challenge;
            consensus.nMinimumChainWork = uint256{};
            consensus.defaultAssumeValid = uint256{};
            m_assumed_blockchain_size = 0;
            m_assumed_chain_state_size = 0;
            chainTxData = ChainTxData{
                0,
                0,
                0,
            };
            LogPrintf("Signet with challenge %s\n", HexStr(bin));
        }

        if (options.seeds) {
            vSeeds = *options.seeds;
        }

        m_chain_type = ChainType::SIGNET;
        consensus.signet_blocks = true;
        consensus.signet_challenge.assign(bin.begin(), bin.end());
        consensus.nSubsidyHalvingInterval = 210000;
        consensus.BIP34Height = 1;
        consensus.BIP34Hash = uint256{};
        consensus.BIP65Height = 1;
        consensus.BIP66Height = 1;
        consensus.CSVHeight = 1;
        consensus.SegwitHeight = 1;
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1815; // 90% of 2016
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.MinBIP9WarningHeight = 0;
        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].min_activation_height = 0; // No activation delay

        // Activation of Taproot (BIPs 340-342)
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].min_activation_height = 0; // No activation delay

        // message start is defined as the first 4 bytes of the sha256d of the block script
        HashWriter h{};
        h << consensus.signet_challenge;
        uint256 hash = h.GetHash();
        std::copy_n(hash.begin(), 4, pchMessageStart.begin());

        nDefaultPort = 38220;
        nPruneAfterHeight = 1000;

        // ===== Bitcoboost SIGNET genesis =====
{
    const char* pszTimestamp = "Bitcoboost mainnet genesis - 2025-11-02";
    const CScript genesisOutputScript =
        CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f")
                  << OP_CHECKSIG;

    const uint32_t nTime  = 1762086000;
    const uint32_t nNonce = 269765;
    const uint32_t nBits  = 0x1f0ffff0;

    genesis = CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, 1, 50 * COIN);
consensus.hashGenesisBlock = genesis.GetHash();
        // [BB2 TEMP] assert merkle disabilitata
// // [BB2 TEMP] assert genesis hash disabilitata
}

// ASSERT DISABLED: /* assert(disabled) */
// ASSERT DISABLED: /* assert(disabled) */


        vFixedSeeds.clear();

        m_assumeutxo_data = {
            {
                .height = 160'000,
                .hash_serialized = AssumeutxoHash{uint256S("0xfe0a44309b74d6b5883d246cb419c6221bcccf0b308c9b59b7d70783dbdf928a")},
                .nChainTx = 2289496,
                .blockhash = uint256S("0x0000003ca3c99aff040f2563c2ad8f8ec88bd0fd6b8f0895cfaf1ef90353a62c")
            }
        };

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "tb";

        fDefaultConsistencyChecks = false;
        m_is_mockable_chain = false;
    }
};

/**
 * Regression test: intended for private networks only. Has minimal difficulty to ensure that
 * blocks can be found instantly.
 */
class CRegTestParams : public CChainParams
{
public:
    explicit CRegTestParams(const RegTestOptions& opts)
    {
        m_chain_type = ChainType::REGTEST;
        consensus.signet_blocks = false;
        consensus.signet_challenge.clear();
        consensus.nSubsidyHalvingInterval = 150;
        consensus.BIP34Height = 1; // Always active unless overridden
        consensus.BIP34Hash = uint256();
        consensus.BIP65Height = 1;  // Always active unless overridden
        consensus.BIP66Height = 1;  // Always active unless overridden
        consensus.CSVHeight = 1;    // Always active unless overridden
        consensus.SegwitHeight = 0; // Always active unless overridden
        consensus.MinBIP9WarningHeight = 0;
        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;
        consensus.nRuleChangeActivationThreshold = 108; // 75% for testchains
        consensus.nMinerConfirmationWindow = 144; // Faster than normal for regtest (144 instead of 2016)

        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].min_activation_height = 0; // No activation delay

        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].min_activation_height = 0; // No activation delay

        consensus.nMinimumChainWork = uint256{};
        consensus.defaultAssumeValid = uint256{};

        pchMessageStart[0] = 0xfa;
        pchMessageStart[1] = 0xbf;
        pchMessageStart[2] = 0xb5;
        pchMessageStart[3] = 0xda;
        nDefaultPort = 38230;
        nPruneAfterHeight = opts.fastprune ? 100 : 1000;
        m_assumed_blockchain_size = 0;
        m_assumed_chain_state_size = 0;

        for (const auto& [dep, height] : opts.activation_heights) {
            switch (dep) {
            case Consensus::BuriedDeployment::DEPLOYMENT_SEGWIT:
                consensus.SegwitHeight = int{height};
                break;
            case Consensus::BuriedDeployment::DEPLOYMENT_HEIGHTINCB:
                consensus.BIP34Height = int{height};
                break;
            case Consensus::BuriedDeployment::DEPLOYMENT_DERSIG:
                consensus.BIP66Height = int{height};
                break;
            case Consensus::BuriedDeployment::DEPLOYMENT_CLTV:
                consensus.BIP65Height = int{height};
                break;
            case Consensus::BuriedDeployment::DEPLOYMENT_CSV:
                consensus.CSVHeight = int{height};
                break;
            }
        }

        for (const auto& [deployment_pos, version_bits_params] : opts.version_bits_parameters) {
            consensus.vDeployments[deployment_pos].nStartTime = version_bits_params.start_time;
            consensus.vDeployments[deployment_pos].nTimeout = version_bits_params.timeout;
            consensus.vDeployments[deployment_pos].min_activation_height = version_bits_params.min_activation_height;
        }

// ===== Bitcoboost REGTEST genesis =====
genesis = CreateGenesisBlock(1296688602, 2, 0x207fffff, 1, 50 * COIN);
consensus.hashGenesisBlock = genesis.GetHash();
        // ASSERT DISABLED: /* assert(disabled) */
// ASSERT DISABLED: /* assert(disabled) */


        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear(); //!< Regtest mode doesn't have any seeds.


        fDefaultConsistencyChecks = true;
        m_is_mockable_chain = true;

        checkpointData = {
    {
        {0, uint256S("0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206")},
    }
};

        m_assumeutxo_data = {
            {
                .height = 110,
                .hash_serialized = AssumeutxoHash{uint256S("0x6657b736d4fe4db0cbc796789e812d5dba7f5c143764b1b6905612f1830609d1")},
                .nChainTx = 111,
                .blockhash = uint256S("0x696e92821f65549c7ee134edceeeeaaa4105647a3c4fd9f298c0aec0ab50425c")
            },
            {
                // For use by test/functional/feature_assumeutxo.py
                .height = 299,
                .hash_serialized = AssumeutxoHash{uint256S("0xa4bf3407ccb2cc0145c49ebba8fa91199f8a3903daf0883875941497d2493c27")},
                .nChainTx = 334,
                .blockhash = uint256S("0x3bb7ce5eba0be48939b7a521ac1ba9316afee2c7bada3a0cca24188e6d7d96c0")
            },
        };

        chainTxData = ChainTxData{
            0,
            0,
            0
        };

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "bcrt";
    }
};

std::unique_ptr<const CChainParams> CChainParams::SigNet(const SigNetOptions& options)
{
    return std::unique_ptr<const CChainParams>(new SigNetParams(options));
}

std::unique_ptr<const CChainParams> CChainParams::RegTest(const RegTestOptions& options)
{
    return std::unique_ptr<const CChainParams>(new CRegTestParams(options));
}

std::unique_ptr<const CChainParams> CChainParams::Main()
{
    return std::unique_ptr<const CChainParams>(new CMainParams());
}

std::unique_ptr<const CChainParams> CChainParams::TestNet() {
    return std::unique_ptr<const CChainParams>(new CTestNetParams());
}






























