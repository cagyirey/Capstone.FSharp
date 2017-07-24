### 0.0.1 - July 17 2017
* Initial release

### 0.0.2 - July 22 2017
* Added a small C helper to retrieve architecture details
* Added support for x86 instruction details

### 0.0.3 - July 23 2017
* Added unit tests
* Removed `createDisassembler` in favor of a constructor for `CapstoneDisassembler`
* Improved project configuration
* Fixed a bug where the disassembler would obtain instruction details when they were disabled
* Changed `X86` and `PowerPC` to `X86Syntax` and `PowerPCSyntax`

### 0.0.4 - July 24 2017
* Changed `X86.OperandInfo.Operand` to `X86.OperandInfo.Value`
* Removed `detailsOn` constructor parameter; use the `Details` property instead
* Added x86-specific unit tests