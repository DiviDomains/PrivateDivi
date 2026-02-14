// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015-2017 The PIVX Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"
#include "random.h"
#include "utilstrencodings.h"
#include "utiltime.h"
#include <assert.h>

#include <boost/assign/list_of.hpp>

using namespace std;
using namespace boost::assign;

struct SeedSpec6 {
    uint8_t addr[16];
    uint16_t port;
};

#include "chainparamsseeds.h"

/**
 * Main network
 */

bool CheckProofOfWorkGen(uint256 hash, unsigned int nBits)
{
    bool fNegative;
    bool fOverflow;
    uint256 bnTarget;

    //if (Params().SkipProofOfWorkCheck())
    //    return true;

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    // Check range
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > (~uint256(0) >> 20))
        return false;

    // Check proof of work matches claimed amount
    if (hash > bnTarget)
        return false;

    return true;
}

//! Convert the pnSeeds6 array into usable address objects.
static void convertSeed6(std::vector<CAddress>& vSeedsOut, const SeedSpec6* data, unsigned int count)
{
    // It'll only connect to one or two seed nodes because once it connects,
    // it'll get a pile of addresses with newer timestamps.
    // Seed nodes are given a random 'last seen time' of between one and two
    // weeks ago.
    const int64_t nOneWeek = 7 * 24 * 60 * 60;
    for (unsigned int i = 0; i < count; i++) {
        struct in6_addr ip;
        memcpy(&ip, data[i].addr, sizeof(ip));
        CAddress addr(CService(ip, data[i].port));
        addr.nTime = GetTime() - GetRand(nOneWeek) - nOneWeek;
        vSeedsOut.push_back(addr);
    }
}

void MineGenesis(CBlock genesis)
{
    printf("Searching for genesis block...\n");
    // This will figure out a valid hash and Nonce if you're
    // creating a different genesis block:
    uint256 hashTarget = ~uint256(0) >> 20;
    uint256 thash;
    while(true)
    {
        thash = genesis.GetHash();
        if (thash <= hashTarget)
            break;
        if ((genesis.nNonce & 0xFFF) == 0)
        {
            printf("nonce %08X: hash = %s (target = %s)\n", genesis.nNonce, thash.ToString().c_str(), hashTarget.ToString().c_str());
        }
        ++genesis.nNonce;
        if (genesis.nNonce == 0)
        {
            printf("NONCE WRAPPED, incrementing time\n");
            ++genesis.nTime;
        }
    }
    printf("block.nTime = %u \n", genesis.nTime);
    printf("block.nNonce = %u \n", genesis.nNonce);
    printf("block.GetHash = %s\n", genesis.GetHash().ToString().c_str());
    printf("block.merkle = %s\n", genesis.hashMerkleRoot.ToString().c_str());
    std::fflush(stdout);
}

namespace
{

//   What makes a good checkpoint block?
// + Is surrounded by blocks with reasonable timestamps
//   (no blocks before with a timestamp after, none after with
//    timestamp before)
// + Contains no strange transactions
const MapCheckpoints mapCheckpoints =
        boost::assign::map_list_of
        (0, uint256("0x00000395d950c21af917448566b32ba1eba5e736dfa4273da0db7c388b89a314"));

const CCheckpointData data = {
    &mapCheckpoints,
    1537971708, // * UNIX timestamp of last checkpoint block (genesis)
    0,    // * total number of transactions between genesis and last checkpoint
    //   (the tx=... number in the SetBestChain debug.log lines)
    2000        // * estimated number of transactions per day after checkpoint
};

const MapCheckpoints mapCheckpointsTestnet =
        boost::assign::map_list_of(0, uint256("0x00000ae103d7e9a29f7a1e97e6d04857786c7374cae489c44fb18b50e67389ac"));
const CCheckpointData dataTestnet = {
    &mapCheckpointsTestnet,
    1537971708,
    0,
    250};

const MapCheckpoints mapCheckpointsRegtest =
        boost::assign::map_list_of(0, uint256("0x4b66fa19b46819cedf4dd4c3f84229916089e09e693e69d1beab944492b84ce3"));
const CCheckpointData dataRegtest = {
    &mapCheckpointsRegtest,
    1518723178,
    0,
    100};

const CChainParams::MNCollateralMapType mnCollateralsMainnet = {
    {MasternodeTier::COPPER,    100000 * COIN},
    {MasternodeTier::SILVER,    300000 * COIN},
    {MasternodeTier::GOLD,     1000000 * COIN},
    {MasternodeTier::PLATINUM, 3000000 * COIN},
    {MasternodeTier::DIAMOND, 10000000 * COIN},
};

/* Masternode collaterals are significantly cheaper on regtest, so
   that it is easy to generate them in tests without having to
   mine hundreds of blocks.  */
const CChainParams::MNCollateralMapType mnCollateralsRegtest = {
    {MasternodeTier::COPPER,    100 * COIN},
    {MasternodeTier::SILVER,    300 * COIN},
    {MasternodeTier::GOLD,     1000 * COIN},
    {MasternodeTier::PLATINUM, 3000 * COIN},
    {MasternodeTier::DIAMOND, 10000 * COIN},
};

} // anonymous namespace

class CMainParams : public CChainParams
{
public:
    CMainParams()
    {
        networkID = CBaseChainParams::MAIN;
        strNetworkID = "main";
        /**
        * The message start string is designed to be unlikely to occur in normal data.
        * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
        * a large 4-byte int at any alignment.
        */

        pchMessageStart[0] = 0x70;
        pchMessageStart[1] = 0xd1;
        pchMessageStart[2] = 0x76;
        pchMessageStart[3] = 0x11;
        premineAmt = 617222416 * COIN;

        vAlertPubKey = ParseHex("0231c07d17c2d69facd84908434dc402b5a9b9e25e5062d1e65163acc7afd0e3ef");
        nDefaultPort = 52472;
        bnProofOfWorkLimit = ~uint256(0) >> 20;			// DIVI starting difficulty is 1 / 2^12
        nSubsidyHalvingInterval = 60 * 24 * 365;
        nMaxReorganizationDepth = 100;
        nMinerThreads = 0;
        nTargetTimespan = 1 * 60;						// DIVI: 1 day
        nTargetSpacing = 1 * 60;						// DIVI: 1 minute
        nMaturity = 20;
        nMasternodeCountDrift = 20;
        nMaxMoneyOut = 2534320700 * COIN;

        /** Height or Time Based Activations **/
        nLastPOWBlock = 100;

        nLotteryBlockStartBlock = 101;
        nLotteryBlockCycle = 60 * 24 * 7; // one week
        nTreasuryPaymentsStartBlock = 101;
        nTreasuryPaymentsCycle = 60 * 24 * 7 + 1;
        nMinCoinAgeForStaking = 60 * 60;
        mnCollateralMap = &mnCollateralsMainnet;

        /**
        * Build the genesis block. Note that the output of the genesis coinbase cannot
        * be spent as it did not originally exist in the database.
        *
        * CBlock(hash=00000ffd590b14, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=e0028e, nTime=1390095618, nBits=1e0ffff0, nNonce=28917698, vtx=1)
        *   CTransaction(hash=e0028e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
        *     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d01044c5957697265642030392f4a616e2f3230313420546865204772616e64204578706572696d656e7420476f6573204c6976653a204f76657273746f636b2e636f6d204973204e6f7720416363657074696e6720426974636f696e73)
        *     CTxOut(nValue=50.00000000, scriptPubKey=0xA9037BAC7050C479B121CF)
        *   vMerkleTree: e0028e
        */
        const char* pszTimestamp = "February 2026 - PrivateDivi Network Genesis - divi.domains";
        CMutableTransaction txNew;
        txNew.vin.resize(1);
        txNew.vout.resize(1);
        txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew.vout[0].nValue = 50 * COIN;
        txNew.vout[0].scriptPubKey = CScript() << ParseHex("04bcc3ef3417ba00ab55e3de807a776ade43cbd634a7e2cff383fecc6920cf918b2ad427f6b0a3f8d38f5a41d5dcbf35b394521bd08fcb5f40749df5bfe7d42fe2") << OP_CHECKSIG;
        genesis.vtx.push_back(txNew);
        genesis.hashPrevBlock = 0;
        genesis.hashMerkleRoot = genesis.BuildMerkleTree();
        genesis.nVersion = 1;
        genesis.nTime = 1537971708;
        genesis.nBits = 0x1e0ffff0;
        genesis.nNonce = 1392478;
        genesis.payee = txNew.vout[0].scriptPubKey;

        nExtCoinType = 801;

        hashGenesisBlock = genesis.GetHash();


        assert(hashGenesisBlock == uint256("0x00000395d950c21af917448566b32ba1eba5e736dfa4273da0db7c388b89a314"));
        assert(genesis.hashMerkleRoot == uint256("0x4123e9ba36523af0b90b02b26663b76a11e9bf680e6c775d8dd6d7c66f95c4bd"));

        vSeeds.push_back(CDNSSeedData("seeds.divi.domains", "seeds.divi.domains"));
        vSeeds.push_back(CDNSSeedData("15.204.243.46", "15.204.243.46"));

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 30);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 13);
        base58Prefixes[SECRET_KEY] = std::vector<unsigned char>(1, 212);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x02)(0x2D)(0x25)(0x33).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x02)(0x21)(0x31)(0x2B).convert_to_container<std::vector<unsigned char> >();
        // 	BIP44 coin type is from https://github.com/satoshilabs/slips/blob/master/slip-0044.md
        base58Prefixes[EXT_COIN_TYPE] = boost::assign::list_of(0x80)(0x00)(0x00)(0x77).convert_to_container<std::vector<unsigned char> >();

        convertSeed6(vFixedSeeds, pnSeed6_main, ARRAYLEN(pnSeed6_main));

        fRequireRPCPassword = true;
        fMiningRequiresPeers = false;
        fAllowMinDifficultyBlocks = false;
        fDefaultConsistencyChecks = false;
        fDifficultyRetargeting = true;
        fMineBlocksOnDemand = false;
        fHeadersFirstSyncingActive = false;

        nFulfilledRequestExpireTime = 30 * 60; // fulfilled requests expire in 30 minutes
        strSporkKey = "02c1ed5eadcf6793fa22840febfbd667fabbabc48ddd75c2d228662d65e292eb00";
        nStartMasternodePayments = 1533945600; //Wed, 11 Aug 2018 00:00:00 GMT

    }

    const CCheckpointData& Checkpoints() const
    {
        return data;
    }
};
static CMainParams mainParams;

class CBetaParams : public CChainParams
{
public:
    CBetaParams()
    {
        networkID = CBaseChainParams::MAIN;
        strNetworkID = "main";
        /**
        * The message start string is designed to be unlikely to occur in normal data.
        * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
        * a large 4-byte int at any alignment.
        */

        pchMessageStart[0] = 0xdf;
        pchMessageStart[1] = 0xa0;
        pchMessageStart[2] = 0x8d;
        pchMessageStart[3] = 0x8a;
        premineAmt = 2534320700;

        vAlertPubKey = ParseHex("046e70d194b1b6b63b9c5431ea83c7b17d0db8930408b1e7937e41759a799e8fcd22d99ffc0c880094bb07a852a9020f810068417e65d19def8ffbdfa90727b637");
        nDefaultPort = 51472;
        bnProofOfWorkLimit = ~uint256(0) >> 20; // DIVI starting difficulty is 1 / 2^12
        nSubsidyHalvingInterval = 1000;
        nMaxReorganizationDepth = 100;
        nMinerThreads = 0;
        nTargetTimespan = 1 * 60; // DIVI: 1 day
        nTargetSpacing = 1 * 60;  // DIVI: 1 minute
        nMaturity = 1; //byrdset from 100
        nMasternodeCountDrift = 20;
        nMaxMoneyOut = 2535000000 * COIN;

        nLotteryBlockStartBlock = 100;
        nLotteryBlockCycle = 60 * 24 * 7; // one week
        nTreasuryPaymentsStartBlock = 100;
        nTreasuryPaymentsCycle = 50;

        /** Height or Time Based Activations **/
        nLastPOWBlock = 56700;

        /**
        * Build the genesis block. Note that the output of the genesis coinbase cannot
        * be spent as it did not originally exist in the database.
        *
        * CBlock(hash=00000ffd590b14, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=e0028e, nTime=1390095618, nBits=1e0ffff0, nNonce=28917698, vtx=1)
        *   CTransaction(hash=e0028e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
        *     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d01044c5957697265642030392f4a616e2f3230313420546865204772616e64204578706572696d656e7420476f6573204c6976653a204f76657273746f636b2e636f6d204973204e6f7720416363657074696e6720426974636f696e73)
        *     CTxOut(nValue=50.00000000, scriptPubKey=0xA9037BAC7050C479B121CF)
        *   vMerkleTree: e0028e
        */
        const char* pszTimestamp = "February 2026 - PrivateDivi Network Genesis - divi.domains";
        CMutableTransaction txNew;
        txNew.vin.resize(1);
        txNew.vout.resize(1);
        txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew.vout[0].nValue = 8000250 * COIN;
        txNew.vout[0].scriptPubKey = CScript() << ParseHex("04bcc3ef3417ba00ab55e3de807a776ade43cbd634a7e2cff383fecc6920cf918b2ad427f6b0a3f8d38f5a41d5dcbf35b394521bd08fcb5f40749df5bfe7d42fe2") << OP_CHECKSIG;
        genesis.vtx.push_back(txNew);
        genesis.hashPrevBlock = 0;
        genesis.hashMerkleRoot = genesis.BuildMerkleTree();
        genesis.nVersion = 1;
        genesis.nTime = 1537971708;
        genesis.nBits = 0x1e0ffff0;
        genesis.nNonce = 419219300;
        genesis.payee = txNew.vout[0].scriptPubKey;

        nExtCoinType = 1;

        hashGenesisBlock = genesis.GetHash();
        

assert(hashGenesisBlock == uint256("0x00000576a3252ac074d35701c418f1c1032aa97cd15aaaa4afc04a70b06eba4b"));
        assert(genesis.hashMerkleRoot == uint256("0x61a6dd6aa8a547a11aaaaede02cd9a5dae2f2a31a02b903340f14551a1f02adb"));

        //vSeeds.push_back(CDNSSeedData("fuzzbawls.pw", "divi.seed.fuzzbawls.pw"));     // Primary DNS Seeder from Fuzzbawls
        //vSeeds.push_back(CDNSSeedData("fuzzbawls.pw", "divi.seed2.fuzzbawls.pw"));    // Secondary DNS Seeder from Fuzzbawls
        //vSeeds.push_back(CDNSSeedData("coin-server.com", "coin-server.com"));         // Single node address
        //vSeeds.push_back(CDNSSeedData("s3v3nh4cks.ddns.net", "s3v3nh4cks.ddns.net")); // Single node address
        //vSeeds.push_back(CDNSSeedData("178.254.23.111", "178.254.23.111"));           // Single node address
        vSeeds.clear();

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 30);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 13);
        base58Prefixes[SECRET_KEY] = std::vector<unsigned char>(1, 212);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x02)(0x2D)(0x25)(0x33).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x02)(0x21)(0x31)(0x2B).convert_to_container<std::vector<unsigned char> >();
        // 	BIP44 coin type is from https://github.com/satoshilabs/slips/blob/master/slip-0044.md
        base58Prefixes[EXT_COIN_TYPE] = boost::assign::list_of(0x80)(0x00)(0x00)(0x77).convert_to_container<std::vector<unsigned char> >();

        convertSeed6(vFixedSeeds, pnSeed6_main, ARRAYLEN(pnSeed6_main));
        vFixedSeeds.clear();

        fRequireRPCPassword = true;
        fMiningRequiresPeers = true;
        fAllowMinDifficultyBlocks = false;
        fDefaultConsistencyChecks = false;
        fMineBlocksOnDemand = false;
        fHeadersFirstSyncingActive = false;

        nFulfilledRequestExpireTime = 60 * 60; // fulfilled requests expire in 1 hour
        strSporkKey = "04B433E6598390C992F4F022F20D3B4CBBE691652EE7C48243B81701CBDB7CC7D7BF0EE09E154E6FCBF2043D65AF4E9E97B89B5DBAF830D83B9B7F469A6C45A717";
        nStartMasternodePayments = 1533945600; //Wed, 11 Aug 2018 00:00:00 GMT

    }

    const CCheckpointData& Checkpoints() const
    {
        return data;
    }
};
static CBetaParams betaParams;

/**
 * Testnet (v3)
 */
class CTestNetParams : public CMainParams
{
public:
    CTestNetParams()
    {
        networkID = CBaseChainParams::TESTNET;
        strNetworkID = "test";

        pchMessageStart[0] = 0x70;
        pchMessageStart[1] = 0xd1;
        pchMessageStart[2] = 0x76;
        pchMessageStart[3] = 0x12;
        premineAmt = 617222416 * COIN;

        vAlertPubKey = ParseHex("046e70d194b1b6b63b9c5431ea83c7b17d0db8930408b1e7937e41759a799e8fcd22d99ffc0c880094bb07a852a9020f810068417e65d19def8ffbdfa90727b637");
        nDefaultPort = 52474;
        bnProofOfWorkLimit = ~uint256(0) >> 20; // DIVI starting difficulty is 1 / 2^12
        nSubsidyHalvingInterval = 1000;
        nMaxReorganizationDepth = 100;
        nMinerThreads = 0;
        nTargetTimespan = 1 * 60; // DIVI: 1 day
        nTargetSpacing = 1 * 60;  // DIVI: 1 minute
        nMaturity = 1;
        nMasternodeCountDrift = 20;
        nMaxMoneyOut = 2535000000 * COIN;

        /** Height or Time Based Activations **/
        nLastPOWBlock = 100;

        nLotteryBlockStartBlock = 101;
        nLotteryBlockCycle = 200; // one week
        nTreasuryPaymentsStartBlock = 102;
        nTreasuryPaymentsCycle = 201;

        //! Modify the testnet genesis block so the timestamp is valid for a later start.
        genesis.nTime = 1591798387;
        genesis.nNonce = 2109127;

        nExtCoinType = 1;


        hashGenesisBlock = genesis.GetHash();


        assert(hashGenesisBlock == uint256("0x00000ae103d7e9a29f7a1e97e6d04857786c7374cae489c44fb18b50e67389ac"));

        vFixedSeeds.clear();
        vSeeds.clear();
        vSeeds.push_back(CDNSSeedData("testseeds.divi.domains", "testseeds.divi.domains"));
        vSeeds.push_back(CDNSSeedData("15.204.243.46", "15.204.243.46"));

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 139); // Testnet divi addresses start with 'x' or 'y'
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 19);  // Testnet divi script addresses start with '8' or '9'
        base58Prefixes[SECRET_KEY] = std::vector<unsigned char>(1, 239);     // Testnet private keys start with '9' or 'c' (Bitcoin defaults)
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x3a)(0x80)(0x61)(0xa0).convert_to_container<std::vector<unsigned char> >();// Testnet divi BIP32 pubkeys start with 'DRKV'
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x3a)(0x80)(0x58)(0x37).convert_to_container<std::vector<unsigned char> >();// Testnet divi BIP32 prvkeys start with 'DRKP'
        base58Prefixes[EXT_COIN_TYPE] = boost::assign::list_of(0x80)(0x00)(0x00)(0x01).convert_to_container<std::vector<unsigned char> >();//// Testnet divi BIP44 coin type is '1' (All coin's testnet default)

        convertSeed6(vFixedSeeds, pnSeed6_test, ARRAYLEN(pnSeed6_test));

        fRequireRPCPassword = true;
        fMiningRequiresPeers = true;
        fAllowMinDifficultyBlocks = true;
        fDefaultConsistencyChecks = false;
        fMineBlocksOnDemand = false;
        fHeadersFirstSyncingActive = false;

        nFulfilledRequestExpireTime = 5*60; // fulfilled requests expire in 5 minutes
        strSporkKey = "034ffa41e5cffdd009f3b34a3e1482ec82b514bb218b7648948b5858cc5c035adb";
        nStartMasternodePayments = 1533945600; //Fri, 09 Jan 2015 21:05:58 GMT
        // here because we only have a 8 block finalization window on testnet
    }
    const CCheckpointData& Checkpoints() const
    {
        return dataTestnet;
    }
};
static CTestNetParams testNetParams;

/**
 * Regression test
 */
class CRegTestParams : public CTestNetParams
{
public:
    CRegTestParams()
    {
        networkID = CBaseChainParams::REGTEST;
        strNetworkID = "regtest";
        pchMessageStart[0] = 0x70;
        pchMessageStart[1] = 0xd1;
        pchMessageStart[2] = 0x76;
        pchMessageStart[3] = 0x13;

        /* The premine on mainnet needs no tests, as it is "tested" by
           syncing on mainnet anyway.  On regtest, it is easiest to not
           have a special premine, as it makes the generated coins more
           predictable.  */
        premineAmt = 1250 * COIN;

        /* Add back a maturity period for coinbases as on mainnet, so that
           we can test this works as expected.  Testnet uses a shorter
           interval to ease with manual testing, but on regtest one can mine
           blocks quickly anyway if needed.  */
        nMaturity = 20;

        nSubsidyHalvingInterval = 100;
        nMinerThreads = 1;
        nTargetTimespan = 24 * 60 * 60; // Divi: 1 day
        nTargetSpacing = 1 * 60;        // Divi: 1 minutes
        bnProofOfWorkLimit = ~uint256(0) >> 1;
        genesis.nTime = 1537971708;
        genesis.nBits = 0x207fffff;
        genesis.nNonce = 984952;

        nLotteryBlockStartBlock = 101;
        nLotteryBlockCycle = 10; // one week
        nTreasuryPaymentsStartBlock = 102;
        nTreasuryPaymentsCycle = 50;

        /* There is no minimum coin age on regtest, so that we can easily
           generate PoS blocks as needed (and without having to mess
           around with mocktimes of perhaps multiple nodes in sync).  */
        nMinCoinAgeForStaking = 0;

        mnCollateralMap = &mnCollateralsRegtest;

        nExtCoinType = 1;

        hashGenesisBlock = genesis.GetHash();
        nDefaultPort = 52476;
        nFulfilledRequestExpireTime = 5*60; // fulfilled requests expire in 5 minutes



        assert(hashGenesisBlock == uint256("0x4b66fa19b46819cedf4dd4c3f84229916089e09e693e69d1beab944492b84ce3"));

        vFixedSeeds.clear(); //! Testnet mode doesn't have any fixed seeds.
        vSeeds.clear();      //! Testnet mode doesn't have any DNS seeds.

        fRequireRPCPassword = false;
        fMiningRequiresPeers = false;
        fAllowMinDifficultyBlocks = true;
        fDefaultConsistencyChecks = true;
        fDifficultyRetargeting = false;
        fMineBlocksOnDemand = true;
    }
    const CCheckpointData& Checkpoints() const
    {
        return dataRegtest;
    }
};
static CRegTestParams regTestParams;

/**
 * Unit test
 */
class CUnitTestParams : public CMainParams, public CModifiableParams
{
public:
    CUnitTestParams()
    {
        networkID = CBaseChainParams::UNITTEST;
        strNetworkID = "unittest";
        nDefaultPort = 51478;
        vFixedSeeds.clear(); //! Unit test mode doesn't have any fixed seeds.
        vSeeds.clear();      //! Unit test mode doesn't have any DNS seeds.

        fRequireRPCPassword = false;
        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = true;
        fAllowMinDifficultyBlocks = false;
        fDifficultyRetargeting = true;
        fMineBlocksOnDemand = true;
        mnCollateralMap = &mnCollateralsMainnet;
    }

    const CCheckpointData& Checkpoints() const
    {
        // UnitTest share the same checkpoints as MAIN
        return data;
    }

    //! Published setters to allow changing values in unit test cases
    virtual void setSubsidyHalvingInterval(int anSubsidyHalvingInterval) { nSubsidyHalvingInterval = anSubsidyHalvingInterval; }
    virtual void setDefaultConsistencyChecks(bool afDefaultConsistencyChecks) { fDefaultConsistencyChecks = afDefaultConsistencyChecks; }
    virtual void setAllowMinDifficultyBlocks(bool afAllowMinDifficultyBlocks) { fAllowMinDifficultyBlocks = afAllowMinDifficultyBlocks; }
};
static CUnitTestParams unitTestParams;


static CChainParams* pCurrentParams = 0;

CModifiableParams* ModifiableParams()
{
    assert(pCurrentParams);
    assert(pCurrentParams == &unitTestParams);
    return (CModifiableParams*)&unitTestParams;
}

const CChainParams& Params()
{
    assert(pCurrentParams);
    return *pCurrentParams;
}

const CCheckpointData& GetCurrentChainCheckpoints()
{
    return Params().Checkpoints();
}

CChainParams& Params(CBaseChainParams::Network network)
{
    switch (network) {
    case CBaseChainParams::MAIN:
        return mainParams;
    case CBaseChainParams::TESTNET:
        return testNetParams;
    case CBaseChainParams::REGTEST:
        return regTestParams;
    case CBaseChainParams::UNITTEST:
        return unitTestParams;
    case CBaseChainParams::BETATEST:
        return betaParams;
    default:
        assert(false && "Unimplemented network");
        return mainParams;
    }
}

void SelectParams(CBaseChainParams::Network network)
{
    SelectBaseParams(network);
    pCurrentParams = &Params(network);
}

bool SelectParamsFromCommandLine(const Settings& settings)
{
    CBaseChainParams::Network network = NetworkIdFromCommandLine(settings);
    if (network == CBaseChainParams::MAX_NETWORK_TYPES)
        return false;

    SelectParams(network);
    return true;
}
