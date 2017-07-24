namespace Capstone.FSharp.Tests

open NUnit.Framework
open FsUnit

open Capstone.FSharp
open Capstone.FSharp.Disassembler

[<TestFixture>]
module ``Core disassembler tests`` =

    [<Test>]
    let ``Can instantiate a new disassembler`` () =
        use disassembler = new CapstoneDisassembler(X86Mode X86_32, false)
        disassembler |> should be instanceOfType<CapstoneDisassembler>

    [<Test>]
    let ``Can enable detail disassembly`` () =
        use disassembler = new CapstoneDisassembler(X86Mode X86_32, false)
        disassembler.Details |> should equal false
        disassembler.Details <- true
        disassembler.Details |> should equal true

    [<Test>]
    let ``Can toggle disassembly syntax`` () =
        let intel, att = Some (X86Syntax Intel), Some (X86Syntax ATT)
        use disassembler = new CapstoneDisassembler(X86Mode X86_32, false, Syntax=intel)
        disassembler.Syntax |> should equal intel
        disassembler.Syntax <- att
        disassembler.Syntax |> should equal att

    [<Test>]
    let ``Can disassemble basic x86 instructions`` () =
        let codeBytes = "\x6A\xFF\x68\x9B\x6C\x74\x01\x64\xA1\x00\x00\x00\x00\x00"B
        let disassembly : X86Instruction [] = [| 
            { 
                Opcode = X86.Opcode.PUSH
                Address = 4096UL
                Assembly = [|106uy; 255uy|]
                Mnemonic = "push"
                Operands = "-1" 
                Details = None }
            { 
                Opcode = X86.Opcode.PUSH
                Address = 4098UL
                Assembly = [|104uy; 155uy; 108uy; 116uy; 1uy|]
                Mnemonic = "push"
                Operands = "0x1746c9b"
                Details = None }
            {
                Opcode = X86.Opcode.MOV;
                Address = 4103UL;
                Assembly = [|100uy; 161uy; 0uy; 0uy; 0uy; 0uy; |];
                Mnemonic = "mov";
                Operands = "eax, dword ptr fs:[0]";
                Details = None } |]

        use disassembler = new CapstoneDisassembler(X86Mode X86_32, false)
        disassembler.Disassemble(0x1000UL, codeBytes)
        |> should equal disassembly
 
    // Requires ARM support
    //[<Test>]
    //let ``Can dynamically toggle disassembly mode`` () = 
    //    use disassembler = new CapstoneDisassembler(ArmMode Arm, false)
    //    disassembler.Mode |> should equal (ArmMode Arm)
    //    disassembler.Mode <- ArmMode Thumb
    //    disassembler.Mode |> should equal (ArmMode Thumb)



