# idapatch

IDA plugin to patch IDA in memory.

## Usage

1. Copy `idapatch.plw`, `idapatch.p64` and `idapatch.ini` to your IDA `plugins` directory.
2. Use [DebugView](https://technet.microsoft.com/en-us/sysinternals/debugview.aspx) to see status.

## Configuration

You can add entries to your `idapatch.ini`:

```
[UniSoft (exetools) qstpncpy crash fix (IDA 6.8)]
enabled=1 ; optional (default '1'), set to 0 to disable this patch
module=wll ; optional (default 'wll'), 'wll' will patch ida.wll or ida64.wll, 'exe' will patch idaq.exe or idaq64.exe, anything else will patch a module with that name (clp.dll will patch in clp.dll)
search=03 C8 3B C1 72 14 80 3D ; search pattern, nibble wildcards (so ?? for one wildcard byte)
replace=03 C8 3B C1 72 14 EB 30 ; replace pattern, nibble wildcards
```