# Capstone.FSharp

F# bindings for @aquynh's Capstone Engine. Capstone.FSharp currently supports disassembling x86 instructions.

### Installing

Build Capstone.FSharp from the provided .sln file, build.cmd or build.sh. The solution is configured for .NET 4.5 and F# 4.1 by default.

### Usage (WIP)

```fsharp
#r @"Capstone.FSharp"

open System

open Capstone.FSharp
open Capstone.FSharp.X86
open Capstone.FSharp.Disassembler

let shellcode = "\x6A\xFF\x68\x9B\x6C\x74\x01\x64\xA1\x00\x00\x00\x00\x50\x51\x56\x57\xA1\xA0\x98\xC7\x01\x33\xC4\x50\x8D\x44\x24\x10\x64\xA3\x00\x00\x00\x00\x8B\xF1\x89\x74\x24\x0C\x33\xFF\x68\x04\x01\x00\x00\xB9\xA0\xC5\xC9\x01\x89\x7E\x04\xE8\x53\x78\x8C\xFF\x83\xC0\x04\x89\x46\x04\xC7\x40\xFC\x00\x01\x00\x00\x8B\x44\x24\x20\x89\x7C\x24\x18\x89\x3E\x89\x7E\x08\x3D\xFF\xFF\xFF\x7F\x74\x08\x50\x8B\xCE\xE8\xEA\xA0\x96\xFF\x89\x7E\x0C\x89\x7E\x10\x8B\xC6\x8B\x4C\x24\x10\x64\x89\x0D\x00\x00\x00\x00\x59\x5F\x5E\x83\xC4\x10\xC2\x04\x00"B

let disassembler = createDisassembler(X86Mode X86_32)
    
do disassembler.Details <- true

let insns = 
    disassembler.Disassemble(0x1000UL, shellcode)
    
for insn in insns do
    printfn "%A" insn
```

Produces output that looks like:

```fsharp
[| {Opcode = PUSH;
     Address = 4096UL;
     Assembly = [|106uy; 255uy|];
     Mnemonic = "push";
     Operands = "-1";
     Details =
      Some
        {ImplicitReads = [|ESP|];
         ImplicitWrites = [|ESP|];
         Groups = [|NOT64BITMODE|];
         ArchitectureSpecificDetails =
          X86Info {Prefix = [|0uy; 0uy; 0uy; 0uy|];
                   REXPrefix = 0uy;
                   Opcode = [|106uy; 0uy; 0uy; 0uy|];
                   SIB = 0uy;
                   ModRM = 0uy;
                   SSECodeCondition = None;
                   AVXCodeCondition = None;
                   AVXRoundingMode = None;
                   AVXSupressAllException = false;
                   Operands = [|{Operand = Immediate -1L;
                                 Size = 4uy;
                                 AVXBroadcast = None;
                                 AVXZeroOpmask = false;}|];};};};
    {Opcode = PUSH;
     Address = 4098UL;
     Assembly = [|104uy; 155uy; 108uy; 116uy; 1uy|];
     Mnemonic = "push";
     Operands = "0x1746c9b";
     Details =
      Some
        {ImplicitReads = [|ESP|];
         ImplicitWrites = [|ESP|];
         Groups = [|NOT64BITMODE|];
         ArchitectureSpecificDetails =
          X86Info {Prefix = [|0uy; 0uy; 0uy; 0uy|];
                   REXPrefix = 0uy;
                   Opcode = [|104uy; 0uy; 0uy; 0uy|];
                   SIB = 0uy;
                   ModRM = 0uy;
                   SSECodeCondition = None;
                   AVXCodeCondition = None;
                   AVXRoundingMode = None;
                   AVXSupressAllException = false;
                   Operands = [|{Operand = Immediate 24407195L;
                                 Size = 4uy;
                                 AVXBroadcast = None;
                                 AVXZeroOpmask = false;}|];};};};
    {Opcode = MOV;
     Address = 4103UL;
     Assembly = [|100uy; 161uy; 0uy; 0uy; 0uy; 0uy|];
     Mnemonic = "mov";
     Operands = "eax, dword ptr fs:[0]";
     Details =
      Some
        {ImplicitReads = [||];
         ImplicitWrites = [||];
         Groups = [|MODE32|];
         ArchitectureSpecificDetails =
          X86Info
            {Prefix = [|0uy; 0uy; 0uy; 0uy|];
             REXPrefix = 0uy;
             Opcode = [|161uy; 0uy; 0uy; 0uy|];
             SIB = 0uy;
             ModRM = 0uy;
             SSECodeCondition = None;
             AVXCodeCondition = None;
             AVXRoundingMode = None;
             AVXSupressAllException = false;
             Operands =
              [|{Operand = Register EAX;
                 Size = 4uy;
                 AVXBroadcast = None;
                 AVXZeroOpmask = false;};
                {Operand = Memory {Segment = FS;
                                   SIB = {Scale = 1;
                                          Index = None;
                                          Base = None;};
                                   Displacement = 0L;};
                 Size = 4uy;
                 AVXBroadcast = None;
                 AVXZeroOpmask = false;}|];};};};
    ...|]
```