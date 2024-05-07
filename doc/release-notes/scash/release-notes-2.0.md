2.0 Release Notes
==================

Scash versioning is as follows:
```
Scash version v2.x.x-narnia-core-27.0.0
              |        |            |
            SCASH   CODENAME    BITCOIN CORE
```

Please report bugs using the issue tracker at GitHub:

  <https://github.com/scash-project/scash/issues>

How to Upgrade
==============

If you are running an older version, shut it down. Wait until it has completely
shut down (which might take a few minutes in some cases), then run the
installer (on Windows) or just copy over `scashd`/`scashd-qt` (on Linux).

Compatibility
==============

Scash is supported and tested on operating systems using the Linux kernel and Windows 11.
Scash should also work on most other Unix-like systems but is not as frequently tested
on them.  It is not recommended to use Scash on unsupported systems.

Changes
=======
- New difficulty adjustment algorithm (DAA) activates at block 21,000. The old DAA, inherited from Bitcoin (BTC), has been replaced with a new DAA called [ASERT (aserti3-2d)](https://reference.cash/protocol/forks/2020-11-15-asert) used by Bitcoin Cash (BCH). The ASERT DAA is more responsive to fluctuating hashrate and adjusts every block instead of every 2016 blocks.
- New node option `-suspiciousreorgdepth` has been added to help protect against deep reorgs. Upon detection of a suspicious reorg, the node will shut down for safety and a human operator can then decide what to do e.g. allow the reorg, invalidate blocks, upgrade software, etc. By default, a reorg depth of 100 is treated as suspicious. This is the same as coinbase maturity and protects newly spendable coinbase rewards from being invalidated.
- New node option `-adddnsseed` has been added so users can add DNS seeds to query for addresses of nodes via DNS lookup. This option can be specified multiple times to connect to multiple DNS seeds. Hardcoded DNS seeds have been removed.
- Scash upgraded and rebased on Bitcoin Core 27.0. See a list of changes in the [Bitcoin Release Notes](https://github.com/bitcoin/bitcoin/blob/master/doc/release-notes/release-notes-27.0.md).
- Checkpoint added
