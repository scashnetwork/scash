2.0 Release Notes
==================

Scash versioning is as follows:
```
Scash version v2.x.x-mithril-core-27.0.0
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

Scash is built as a new chain type on top of the Bitcoin Core software. Scash
can connect to the Bitcoin network and operate as a Bitcoin client fully compatible
with the current network consensus rules. However, it is not recommended to use Scash
as a Bitcoin client, and instead Bitcoin Core should be used.

Changes
=======
- Scash rebased on Bitcoin Core 27.0. See a list of changes in the [Bitcoin Release Notes](https://github.com/bitcoin/bitcoin/blob/master/doc/release-notes/release-notes-27.0.md).
- Checkpoint added
