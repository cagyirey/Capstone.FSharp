namespace Capstone.FSharp.NativeInterop

#nowarn "9"

open System

[<AutoOpen>]
[<CompilationRepresentation(CompilationRepresentationFlags.ModuleSuffix)>]
module Disassembler = 

    type Architecture = 
        | Arm = 0
        | Arm64 = 1
        | Mips = 2
        | X86 = 3
        | PowerPC = 4
        | Sparc = 5
        | SystemZ = 6
        | XCore = 7
    
    [<Flags>]
    type Mode = 
        | Default = 0b0
        | LittleEndian = 0b0
        | Arm = 0b0
        | Mode16 = 0b10
        | Mode32 = 0b100
        | Mode64 = 0b1000
        | Thumb = 0b1_0000
        | Micro = 0b1_0000
        | SparcV9 = 0b1_0000
        | MClass = 0b10_0000
        | N64 = 0b10_0000
        | Mips3 = 0b100_0000
        | Mips32R6 = 0b1000_0000
        | MipsGP64 = 0b1_0000_0000
        | BigEndian = 0b1000_0000_0000_0000_0000_0000_0000_0000
    
    type CapstoneOptionKind = 
        | Syntax = 1
        | Details = 2
        | Mode = 3
        | Memory = 4
        | SkipData = 5
      //| SkipDataSetup = 6 // native callbacks not supported

    type CapstoneOptionValue = 
        | Off = 0
        | On = 3
        | DefaultSyntax = 0
        | IntelSyntax = 1
        | ATTSyntax = 2
        | PowerPCShortRegisters = 3

    type CapstoneError = 
        | Ok = 0
        | OutOfMemory = 1
        | InvalidArchitecture = 2
        | InvalidHandle = 3
        | InvalidCsh = 4
        | InvalidMode = 5
        | InvalidOption = 6
        | DetailsOff = 7
        | MemSetup = 8
        | VersionMismatch = 9
        | DietEngine = 10

type internal cs_arch_detail = Capstone.FSharp.NativeInteropHelper.NativeArchitectureDetails

type internal cs_detail = Capstone.FSharp.NativeInteropHelper.NativeInstructionDetail

type internal cs_insn = Capstone.FSharp.NativeInteropHelper.NativeInstruction
        
type internal cs_x86 = Capstone.FSharp.NativeInteropHelper.NativeX86InstructionDetail

type internal x86_op_type = Capstone.FSharp.NativeInteropHelper.NativeX86InstructionOperandValue

type internal x86_op_mem = Capstone.FSharp.NativeInteropHelper.NativeX86InstructionMemoryOperandValue