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

### 0.0.5 - August 10 2017
* Added a `Disassemble` overload for pointer types (e.g. `IntPtr`, `SafeBuffer`)
* Added ARM `InstructionGroup` type
* Split disassembler model and implementation into `capstone.fs` and `disassembler.fs`
* Cleaned up solution configuration

### 0.0.6 - August 19 2017
* Added `CapstoneDisassembler.SkipData`
* Fixed a bug that prevented the last instruction in a sequence from being disassembled.