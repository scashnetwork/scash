#!/usr/bin/env python3
# Copyright (c) 2024 The Scash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test rejection of block with invalid pow """

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

class P2PInvalidBlockPowTest(BitcoinTestFramework):

    def set_test_params(self):
        self.chain = "scashtestnet"
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-dnsseed=0"]]

    def run_test(self):
        node = self.nodes[0]
        assert(node.getblockchaininfo()['chain'] == "scashtestnet")

        # Bad Testnet block 1 with invalid RandomX hash.
        # Commitment meets block target but fails full verification of RandomX hash.
        block1_bad = "00000020824cf2946255fcc00026e6e4bcf109a1dbe029b8d926258e209c741948a93b0e648b626720761450c2ff6d95d473fa00396b8739452901e11bb944cacfb5d548ab05c765ffff7f1e7601000037ccb72769b2428af8b80fc5e443248b1ab527483b70a66db564e7d8b898cd8301010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff025100ffffffff0200f2052a01000000160014d1f5cf8a7aae73c7a39829bcb633fb35648a41d60000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000"
        assert_equal(node.submitblock(block1_bad), 'high-hash')
        assert_equal(node.getblockcount(), 0)

        # Testnet block 1
        block1_good = "00000020824cf2946255fcc00026e6e4bcf109a1dbe029b8d926258e209c741948a93b0e648b626720761450c2ff6d95d473fa00396b8739452901e11bb944cacfb5d548ab05c765ffff7f1e7601000053125a309db1a5b87a2cf7decc557470ab9ea49bc2590b4d1c56a5bdb6d1696501010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff025100ffffffff0200f2052a01000000160014d1f5cf8a7aae73c7a39829bcb633fb35648a41d60000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000"
        assert_equal(node.submitblock(block1_good), None)
        assert_equal(node.getblockcount(), 1)

if __name__ == '__main__':
    P2PInvalidBlockPowTest().main()
