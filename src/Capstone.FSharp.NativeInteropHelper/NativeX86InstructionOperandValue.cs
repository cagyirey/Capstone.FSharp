using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace Capstone.FSharp.NativeInteropHelper
{
    /// <summary>
    ///     Native X86 Instruction Operand Value.
    /// </summary>
    [StructLayout(LayoutKind.Explicit)]
    public struct NativeX86InstructionOperandValue
    {
        /// <summary>
        ///     Operand Value's Register Value.
        /// </summary>
        [FieldOffset(0)] public uint Register;

        /// <summary>
        ///     Operand Value's Immediate Value.
        /// </summary>
        [FieldOffset(0)] public long Immediate;

        /// <summary>
        ///     Operand Value's Floating Point Value.
        /// </summary>
        [FieldOffset(0)] public double FloatingPoint;

        /// <summary>
        ///     Operand Value's Memory Value.
        /// </summary>
        [FieldOffset(0)] public NativeX86InstructionMemoryOperandValue Memory;
    }
}
