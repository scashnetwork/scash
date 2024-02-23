1.0 Release Notes
==================

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
==============

Scash is built as a new chain type on top of the Bitcoin Core software. Scash
can connect to the Bitcoin network and operate as a Bitcoin client fully compatible with the current network consensus rules. However, it is not recommended to use Scash
as a Bitcoin client, and instead Bitcoin Core should be used.

Notable changes
===============

Proof of work
-------------
- The SHA256 proof of work has been replaced with RandomX.  See the the [Scash Protocol spec](https://github.com/scash-project/sips/blob/main/scash-protocol-spec.md).

Replace-by-fee
-------------- 
- Disabled when running the Scash network

Datacarrier
------------
- Disabled when running the Scash network

Ordinals
--------
- Transactions containing ordinals inscriptions are treated as non-standard when running the Scash network.

New options
-----------

- New chain options `-scash`, `-scashtestnet`, `-scashregtest`

- New proof of work related options `-randomxfastmode` and `-randomxvmcachesize`.
  See the [Scash Protocol spec](https://github.com/scash-project/sips/blob/main/scash-protocol-spec.md).

Updated RPCs
------------

- `getblock` RPC returns new fields `rx_cm`, `rx_hash`, `rx_epoch`

- `getblocktemplate` RPC returns new field `rx_epoch_duration`
