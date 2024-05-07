#!/usr/bin/env python3
# Copyright (c) 2024 The Scash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the -suspiciousreorgdepth feature."""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.test_node import ErrorMatch

class SuspiciousReorgTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 3
        self.chain = "scashregtest"

    def setup_network(self):
        self.setup_nodes()

    def run_test(self):
        node = self.nodes[0]
        assert(node.getblockchaininfo()['chain'] == "scashregtest")

        self.log.info("Mine 80 blocks on Node 0")
        self.generate(self.nodes[0], 80, sync_fun=self.no_op)
        assert_equal(self.nodes[0].getblockcount(), 80)
        besthash_n0 = self.nodes[0].getbestblockhash()

        self.log.info("Mine competing 90 blocks on Node 1")
        self.generate(self.nodes[1], 100, sync_fun=self.no_op)
        assert_equal(self.nodes[1].getblockcount(), 100)

        self.log.info("Connect nodes to reorg Node 0")
        self.connect_nodes(0, 1)
        self.sync_blocks(self.nodes[0:2])
        assert_equal(self.nodes[0].getblockcount(), 100)

        self.log.info("Invalidate a block on Node 0 to reorg back to original chain")
        badhash = self.nodes[1].getblockhash(2)
        self.nodes[0].invalidateblock(badhash)
        assert_equal(self.nodes[0].getblockcount(), 80)
        assert_equal(self.nodes[0].getbestblockhash(), besthash_n0)

        self.log.info("Mine competing 101 blocks on Node 2")
        self.generate(self.nodes[2], 101, sync_fun=self.no_op)
        assert_equal(self.nodes[2].getblockcount(), 101)

        self.log.info("Try to reorg nodes by connecting to Node 2")
        self.connect_nodes(0, 2, wait_for_connect=True)
        self.connect_nodes(1, 2, wait_for_connect=False)

        self.log.info("Node 1 detects suspicious reorg and shuts down")
        self.wait_for_node_exit(1, timeout=30)
        self.nodes[1].stderr.seek(0)
        exp_stderr = self.nodes[1].stderr.read().decode('utf-8').strip()
        self.nodes[1].wait_until_stopped(expect_error=True, expected_stderr=exp_stderr)
        assert(exp_stderr.startswith("Error: Detected suspicious reorg of 100 blocks, local policy allows 99 blocks."))
        assert("current tip @ height 100" in exp_stderr)
        assert("reorg tip @ height 101" in exp_stderr)
        assert("fork point @ height 0" in exp_stderr)
        assert("Error: A fatal internal error occurred, see debug.log for details" in exp_stderr)
        # Error: Detected suspicious reorg of 100 blocks, local policy allows 99 blocks.
        # * current tip @ height 100 (ec7f3948e347deb59247eb739f78be70192e7e7ceb4e6c8fda5a55df4f3053e3)
        # *   reorg tip @ height 101 (7127850432ae30e4a358c68e368e98bcc6d77a9a07cc847c74b6b39d11928b4d)
        # *  fork point @ height 0 (f44d4e3a27c9c0dbd8c6c2596950c782a99ad33f749d296d2a0ab3af84b4cb86)
        #
        # Error: A fatal internal error occurred, see debug.log for details   

        self.log.info("Node 0 is reorged by Node 2")
        self.sync_blocks(nodes=(self.nodes[0], self.nodes[2]))
        besthash_n2 = self.nodes[2].getbestblockhash()
        assert_equal(self.nodes[0].getblockcount(), 101)
        assert_equal(self.nodes[0].getbestblockhash(), besthash_n2)

        self.log.info("Node 1 relaunch fails")
        self.nodes[1].assert_start_raises_init_error(expected_msg="suspicious", match=ErrorMatch.PARTIAL_REGEX)
        self.nodes[1].wait_until_stopped()

        self.log.info("Node 1 relaunch succeeds when disabling -suspiciousreorgdepth")
        self.start_node(1, extra_args=["-suspiciousreorgdepth=0"])
        self.sync_blocks(self.nodes[0:3])
        assert_equal(self.nodes[1].getblockcount(), 101)
        assert_equal(self.nodes[1].getbestblockhash(), besthash_n2)

        self.log.info("Node 1 invalidates Node 2 chain")
        self.nodes[1].invalidateblock(self.nodes[1].getblockhash(1))
        assert_equal(self.nodes[1].getblockcount(), 100)
        self.generate(self.nodes[1], 100, sync_fun=self.no_op)
        assert_equal(self.nodes[1].getblockcount(), 200)
        assert_equal(self.nodes[0].getblockcount(), 101)
        assert_equal(self.nodes[2].getblockcount(), 101)

if __name__ == '__main__':
    SuspiciousReorgTest().main()
