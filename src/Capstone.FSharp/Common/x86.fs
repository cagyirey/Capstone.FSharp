namespace Capstone.FSharp.X86

open System.Runtime.InteropServices

open Capstone.FSharp

type internal x86_op_type =
    | Invalid = 0
    | Register = 1
    | Immediate = 2
    | Memory = 3
    | Float = 4

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
    Value: Operand
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

module internal Internal = 
    
    let private makeMemoryOperand (mem: NativeInterop.x86_op_mem) = { 
        Segment = enum<Register> (int mem.SegmentRegister)
        SIB = { 
            Scale = mem.IndexRegisterScale
            Index = enum<Register> (int mem.IndexRegister)
            Base = enum<Register> (int mem.BaseRegister) }
        Displacement = mem.Displacement }

    let private makeOperands (details: NativeInterop.cs_x86) =
        seq { 
            yield details.Operand1; yield details.Operand2; yield details.Operand3; yield details.Operand4
            yield details.Operand5; yield details.Operand6; yield details.Operand7; yield details.Operand8 }
        |> Seq.take (int details.OperandCount)
        |> Seq.map(fun op -> { 
            Size = op.Size
            AVXBroadcast = enum<AVXBroadcastKind> op.AvxBroadcast
            AVXZeroOpmask = op.AvxZeroOperationMask
            Value = 
                match enum<x86_op_type> op.Type with
                | x86_op_type.Register -> Register (enum<Register> <| int op.Value.Register)
                | x86_op_type.Immediate -> Immediate op.Value.Immediate
                | x86_op_type.Memory -> Memory(makeMemoryOperand op.Value.Memory)
                | x86_op_type.Float -> Float op.Value.FloatingPoint
        }) |> Seq.toArray
            
    let internal makeInstructionInfo (instruction: NativeInterop.cs_insn) =
        let details = instruction.NativeX86Detail
        { 
            Prefix = details.ManagedPrefix
            REXPrefix = details.RexPrefix
            Opcode = details.ManagedOpcode
            SIB = details.Sib
            ModRM = details.ModRM
            SSECodeCondition = enum<SSEConditionCode> details.SseCodeCondition 
            AVXCodeCondition = enum<AVXConditionCode> details.AvxCodeCondition
            AVXRoundingMode = enum<AVXRoundingMode> details.AvxRoundingMode
            AVXSupressAllException = details.AvxSuppressAllExceptions
            Operands = makeOperands details 
        }
