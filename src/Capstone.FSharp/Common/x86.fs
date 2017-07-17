namespace Capstone.FSharp

open Capstone.FSharp
open Capstone.FSharp.X86

open System.Runtime.InteropServices

[<CompilationRepresentation(CompilationRepresentationFlags.ModuleSuffix)>]
module X86 =

    [<Struct>]
    type ScaleIndexBase = {
        Scale: int32
        Index: Register
        Base: Register }
    
    [<Struct>]
    type MemoryOperand = {
        Segment: Register
        SIB: ScaleIndexBase
        Displacement: int64 }
    
    [<Struct>]
    type Operand = 
        | Register of reg: Register
        | Immediate of imm: int64
        | Float of fp: float
        | Memory of mem: MemoryOperand

    [<Struct>]
    type OperandInfo = {
        Operand: Operand
        Size: uint8
        AVXBroadcast: AVXBroadcastKind
        AVXZeroOpmask: bool }
    
    [<Struct>]
    type InstructionInfo = { 
        Prefix: byte array
        REXPrefix: uint8
        Opcode: byte array
        SIB: uint8
        ModRM: uint8
        SSECodeCondition: SSEConditionCode
        AVXCodeCondition: AVXConditionCode
        AVXRoundingMode: AVXRoundingMode
        AVXSupressAllException: bool
        Operands: OperandInfo array }

    type x86_op_type =
    | Invalid = 0
    | Register = 1
    | Immediate = 2
    | Float = 3
    | Memory = 4

    let makeMemoryOperand (mem: NativeInterop.x86_op_mem) = { 
        Segment = enum<Register> (int mem.SegmentRegister)
        SIB = { 
            Scale = mem.IndexRegisterScale
            Index = enum<Register> (int mem.IndexRegister)
            Base = enum<Register> (int mem.BaseRegister)
        }
        Displacement = mem.Displacement
     }

    let makeOperands (details: NativeInterop.cs_x86) =
        seq { 
            yield details.Operand1; yield details.Operand2; yield details.Operand3; yield details.Operand4
            yield details.Operand5; yield details.Operand6; yield details.Operand7; yield details.Operand8 }
        |> Seq.take (int details.OperandCount)
        |> Seq.map(fun op ->
            let operand = 
                match enum<x86_op_type> op.Type with
                | x86_op_type.Register -> Register (enum<Register> <| int op.Value.Register)
                | x86_op_type.Immediate -> Immediate op.Value.Immediate
                | x86_op_type.Float -> Float op.Value.FloatingPoint
                | x86_op_type.Memory -> Memory(makeMemoryOperand op.Value.Memory)
            { Operand = operand 
              Size = op.Size
              AVXBroadcast = enum<AVXBroadcastKind> op.AvxBroadcast
              AVXZeroOpmask = op.AvxZeroOperationMask
            })
        |> Seq.toArray
            

    let makeInstructionInfo (details: NativeInterop.cs_arch_detail) = 
        {   Prefix = details.X86.ManagedPrefix
            REXPrefix = details.X86.RexPrefix
            Opcode = details.X86.ManagedOpcode
            SIB = details.X86.Sib
            ModRM = details.X86.ModRM
            SSECodeCondition = enum<SSEConditionCode> details.X86.SseCodeCondition 
            AVXCodeCondition = enum<AVXConditionCode> details.X86.AvxCodeCondition
            AVXRoundingMode = enum<AVXRoundingMode> details.X86.AvxRoundingMode
            AVXSupressAllException = details.X86.AvxSuppressAllExceptions
            Operands = makeOperands details.X86 }