SCASH BUILD NOTES
====================

Scash (s/atoshi/cash) is a fork of Bitcoin Core which adds a new chain option to restore home computer mining.

Technical details are documented in the [Scash Protocol spec](https://github.com/scash-project/sips/blob/main/scash-protocol-spec.md).

Building Scash follows the same instructions as building Bitcoin. The Scash network shares the same features and rules as Bitcoin mainnet, as specified in Bitcoin Core v26.0.

Only the Linux version of the command-line node software is currently supported. The GUI, Windows and MacOS platforms are not yet supported. Note that Windows users can follow the Linux instructions when building in Ubuntu on [Windows Subsystem for Linux (WSL)](https://learn.microsoft.com/en-us/windows/wsl/about).

For more specific instructions on building, see [`build-unix.md`](build-unix.md) in this directory.

Also see the latest [Scash release notes](release-notes/scash/).

Getting started 
---------------------
Update your system and install the following tools required to build software.

```bash
sudo apt update
sudo apt upgrade
sudo apt install build-essential libtool autotools-dev automake pkg-config bsdmainutils curl git cmake bison
```

WSL for Windows
---------------------
Ignore this step if building on native Linux. The following only applies when building in WSL for Windows.

Open the WSL configuration file:
```bash
sudo nano /etc/wsl.conf
```
Add the following lines to the file:
```
[interop]
appendWindowsPath=false
```
Exit WSL and then restart WSL.

Downloading the code
---------------------
Download the latest version of Scash and checkout the version you intend to build. If you want to build a specific version, you can replace `scash_master` with the version tag.

```bash
git clone https://github.com/scash-project/scash.git
cd scash
git checkout scash_master
```

To Build
---------------------

Scash requires building with the depends system.

When calling `make` use `-j N` for N parallel jobs.

```bash
./autogen.sh
make -C depends NO_QT=1
./configure --without-gui --prefix=$PWD/depends/x86_64-pc-linux-gnu --program-transform-name='s/bitcoin/scash/g'
make # binaries named bitcoind, bitcoin-cli...
make install #binaries in depends bin folder named scashd, scash-cli...
```

Config file
---------------------
Scash configuration is the same as bitcoin.conf.

By default, Scash looks for a configuration file here:
`$HOME/.scash/scash.conf`

The following is a sample `scash.conf`.
```
rpcuser=user
rpcpassword=password
chain=scash
daemon=1
debug=1
txindex=1
```

If you intend to use the same configuration file with multiple networks, the config sections are named as follows:
```
[btc]
[btctestnet3]
[btcsignet]
[btcregtest]
[scash]
[scashregtest]
[scashtestnet]
```

Running a node
---------------------
To run the Scash node software:
```bash
scashd
```

To send commands to the Scash node:
```
scash-cli [COMMAND] [PARAMETERS]
```

Testnet and other chains
---------------------
When running executables with the name `bitcoin...` if no chain is configured, the default chain will be Bitcoin mainnet.

When running executables with the name `scash...` if no chain is configured, the default chain will be Scash mainnet.

Option `-chain=` accepts the following values: `scash` `scashtestnet` `scashregtest` and for Bitcoin networks: `main` `test` `signet` `regtest`

Mining Scash
---------------------

Solo mining is possible with the RPC `generatetoaddress`, for example:
```bash
scash-cli createwallet myfirstwallet
scash-cli getnewaddress # the mining address
scash-cli generatetoaddress 1 miningaddress 10000
```

Solo mining with RPC `getblocktemplate` is possible with [cpuminer-scash](https://github.com/scash-project/cpuminer-scash).


Getting Help
---------------------

Please file a Github issue if build problems are not resolved after reviewing the available Scash and Bitcoin documentation.