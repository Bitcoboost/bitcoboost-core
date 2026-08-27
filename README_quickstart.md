# BitcoBoost — Quick Start (Windows)

## Build (Git Bash)
cd /d/bitcoboost
make -j8

## Avvio nodo (PowerShell)
D:\bitcoboost\src\bitcoind.exe -datadir="D:\bitcoboost\bb_main_boost7" -printtoconsole

## Wallet e bilanci
D:\bitcoboost\src\bitcoin-cli.exe -datadir="D:\bitcoboost\bb_main_boost7" -rpcport=38211 listwallets
D:\bitcoboost\src\bitcoin-cli.exe -datadir="D:\bitcoboost\bb_main_boost7" -rpcport=38211 -rpcwallet=bb_wallet getbalances

## Mining
powershell -ExecutionPolicy Bypass -File D:\bitcoboost\tools\bb-mine.ps1 -N 10
powershell -ExecutionPolicy Bypass -File D:\bitcoboost\tools\bb-mempool.ps1

## Invio
D:\bitcoboost\src\bitcoin-cli.exe -datadir="D:\bitcoboost\bb_main_boost7" -rpcport=38211 -rpcwallet=bb_wallet -named getnewaddress label="" address_type=legacy
D:\bitcoboost\src\bitcoin-cli.exe -datadir="D:\bitcoboost\bb_main_boost7" -rpcport=38211 -rpcwallet=bb_wallet sendtoaddress <INDIRIZZO> 1

## Backup (descriptor + binario)
$ts = Get-Date -Format yyyyMMdd_HHmmss
D:\bitcoboost\src\bitcoin-cli.exe -datadir="D:\bitcoboost\bb_main_boost7" -rpcport=38211 -rpcwallet=bb_wallet listdescriptors true | Out-File D:\bitcoboost\backups\bb_wallet_descriptors_$ts.json -Encoding ascii
D:\bitcoboost\src\bitcoin-cli.exe -datadir="D:\bitcoboost\bb_main_boost7" -rpcport=38211 -rpcwallet=bb_wallet backupwallet D:\bitcoboost\backups\bb_wallet_backup_$ts.dat

## Smoke test (bb-quickcheck.ps1)

Eseguire in **Windows PowerShell** (non Git Bash):

```powershell
powershell -ExecutionPolicy Bypass -File D:\bitcoboost\tools\bb-quickcheck.ps1
powershell -ExecutionPolicy Bypass -File D:\bitcoboost\tools\bb-quickcheck.ps1 -Mine
