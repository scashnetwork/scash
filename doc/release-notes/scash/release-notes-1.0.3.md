1.0.3 Release Notes
===================

Scash is built from source. There are no binaries available yet.

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
shut down (which might take a few minutes in some cases) then just copy over
`scashd` (on Linux).

Compatibility
=============

Scash is built as a new chain type on top of the Bitcoin Core software. Scash
can connect to the Bitcoin network and operate as a Bitcoin client fully compatible
with the current network consensus rules. However, it is not recommended to use Scash
as a Bitcoin client, and instead Bitcoin Core should be used.

Changes
=======

- QT GUI app updated to support the Scash chain
- Checkpoint added

