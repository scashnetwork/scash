1.0.5 Release Notes
===================

Scash versioning is as follows:
```
Scash version v1.x.x-mithril-core-26.0.0 
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
=============

Scash is built as a new chain type on top of the Bitcoin Core software. Scash
can connect to the Bitcoin network and operate as a Bitcoin client fully compatible
with the current network consensus rules. However, it is not recommended to use Scash
as a Bitcoin client, and instead Bitcoin Core should be used.

Changes
=======

- Fixed a crash which could happen randomly when syncing after launch
- RandomX fast mode now activates after initial block download completes
- Updated copyright in source files
- Checkpoint added
