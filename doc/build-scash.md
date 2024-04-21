# SCASH BUILD NOTES

Scash (s/atoshi/cash) is a fork of Bitcoin Core which adds a new chain option to restore home computer mining.

Technical details are documented in the [Scash Protocol spec](https://github.com/scash-project/sips/blob/main/scash-protocol-spec.md).

Building Scash follows the same instructions as building Bitcoin. The Scash network shares the same features and rules as Bitcoin mainnet, as specified in Bitcoin Core v26.0.

The Linux version of the node `scashd` and GUI app `scash-qt` are both supported, with Windows binaries also  available (cross-compiled on Linux). MacOS is not yet supported. Note that Windows users can build from source by following the Linux instructions when building in Ubuntu on [Windows Subsystem for Linux (WSL)](https://learn.microsoft.com/en-us/windows/wsl/about).

For more specific instructions on building, see [`build-unix.md`](build-unix.md) in this directory.

Also see the latest [Scash release notes](release-notes/scash/).

## Getting started 

Update your system and install the following tools required to build software.

```bash
sudo apt update
sudo apt upgrade
sudo apt install build-essential libtool autotools-dev automake pkg-config bsdmainutils curl git cmake bison
```

## WSL for Windows

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

## Downloading the code

Download the latest version of Scash and checkout the version you intend to build. If you want to build a specific version, you can replace `scash_master` with the version tag.

```bash
git clone https://github.com/scash-project/scash.git
cd scash
git checkout scash_master
```

## Building for Linux

Scash requires building with the depends system.

When calling `make` use `-j N` for N parallel jobs.

### Node software without the GUI

To build just the node software `scashd` and not the QT GUI app:

```bash
./autogen.sh
make -C depends NO_QT=1
./configure --without-gui --prefix=$PWD/depends/x86_64-pc-linux-gnu --program-transform-name='s/bitcoin/scash/g'
make
make install
```

### Node software with the GUI

To build both the node software `scashd` and the QT GUI app `scashd-qt`

```bash
./autogen.sh
make -C depends
./configure --prefix=$PWD/depends/x86_64-pc-linux-gnu --program-transform-name='s/bitcoin/scash/g'
make
make install
```

### Executables
The compiled executables will be found in `depends/x86_64-pc-linux-gnu/bin/` and can be copied to a folder on your path, typically `/usr/local/bin/` or `$HOME/.local/bin/`.


## Building for Windows (by cross-compiling on Linux)

Build on Linux and generate executables which run on Windows.

```
sudo apt install g++-mingw-w64-x86-64-posix 
cd depends/
make HOST=x86_64-w64-mingw32
cd ..
./autogen.sh
./configure --prefix=$PWD/depends/x86_64-w64-mingw32 --program-transform-name='s/bitcoin/scash/g'
make
make install
```

The windows executables will be found in `depends/x86_64-w64-mingw32/bin/`.

To generate a Windows installer:

```
sudo apt install nsis
make deploy
```

## Config file

The Scash configuration file is the same as bitcoin.conf.

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

## Running a node

To run the Scash node:
```bash
scashd
```

To send commands to the Scash node:
```
scash-cli [COMMAND] [PARAMETERS]
```

To run the desktop GUI app:
```bash
scash-qt
```

On WSL for Windows, launching `scash-qt` may require installing the following dependencies. Also see [WSL gui apps](https://learn.microsoft.com/en-us/windows/wsl/tutorials/gui-apps).
```bash
sudo apt install libxcb-* libxkbcommon-x11-0
```

Also note that in WSL for Windows, by default only half of the memory is available to WSL. You can [configure the memory limit](https://learn.microsoft.com/en-us/windows/wsl/wsl-config#main-wsl-settings) by creating `.wslconfig` file in your user folder.
```
[wsl2]
memory=16GB
```

## Connecting to different chains

When running executables with the name `bitcoin...` if no chain is configured, the default chain will be Bitcoin mainnet.

When running executables with the name `scash...` if no chain is configured, the default chain will be Scash mainnet.

Option `-chain=` accepts the following values: `scash` `scashtestnet` `scashregtest` and for Bitcoin networks: `main` `test` `signet` `regtest`

## Mining Scash

There are a few ways to mine Scash.

### Testnet and Regtest chain

Mining takes place inside the Scash node, using the RPC `generatetoaddress` which is single-threaded. For example:
```bash
scash-cli createwallet myfirstwallet
scash-cli getnewaddress
scash-cli generatetoaddress 1 newminingaddress 10000
```

To speed up mining in the Scash node, at the expense of using more memory (at least 2GB more), enable the option `randomxfastmode` by adding to the `scash.conf` configuration file:

```
randomxfastmode=1
```

### Main network and Testnet chain

Mining takes place inside [cpuminer-scash](https://github.com/scash-project/cpuminer-scash) which is dedicated mining software that connects to the Scash node and retrieves mining jobs via RPC `getblocktemplate`. The 'randomxfastmode' configuration option is not required for the Scash node, since mining occurs inside `cpuminer-scash` which always runs in fast mode.

### Mining Pools

Third-party software exists for mining at pools.


Getting Help
---------------------

Please file a Github issue if build problems are not resolved after reviewing the available Scash and Bitcoin documentation.
