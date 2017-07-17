using System;
using System.Runtime.InteropServices;

namespace Capstone.FSharp.NativeInteropHelper
{
    [StructLayout(LayoutKind.Sequential)]
    public unsafe struct NativeX86InstructionDetail
    {
        /// <summary>
        ///     Instruction's Prefix.
        /// </summary>
        public fixed byte Prefix[4];

        /// <summary>
        ///     Instruction's Operation Code.
        /// </summary>
        public fixed byte Opcode[4];

        /// <summary>
        ///     Instruction's REX Prefix.
        /// </summary>
        public byte RexPrefix;

        /// <summary>
        ///     Instruction's Address Size.
        /// </summary>
        public byte AddressSize;

        /// <summary>
        ///     Instruction's ModR/M Byte.
        /// </summary>
        public byte ModRM;

        /// <summary>
        ///     Instruction's SIB Value.
        /// </summary>
        public byte Sib;

        /// <summary>
        ///     Instruction's Displacement Value.
        /// </summary>
        public int Displacement;

        /// <summary>
        ///     Instruction's SIB Index Register.
        /// </summary>
        public int SibIndexRegister;

        /// <summary>
        ///     Instruction's SIB Scale.
        /// </summary>
        public byte SibScale;

        /// <summary>
        ///     Instruction's SIB Base Register.
        /// </summary>
        public int SibBaseRegister;

        /// <summary>
        ///     Instruction's SSE Code Condition.
        /// </summary>
        public int SseCodeCondition;

        /// <summary>
        ///     Instruction's AVX Code Condition.
        /// </summary>
        public int AvxCodeCondition;

        /// <summary>
        ///     Instruction's AVX Suppress All Exceptions Flag.
        /// </summary>
        [MarshalAs(UnmanagedType.I1)]
        public bool AvxSuppressAllExceptions;

        /// <summary>
        ///     Instruction's AVX Rounding Mode.
        /// </summary>
        public int AvxRoundingMode;

        /// <summary>
        ///     Number of Instruction's Operands.
        /// </summary>
        public byte OperandCount;

        /// <summary>
        ///     Instruction's First Operand.
        /// </summary>
        public NativeX86InstructionOperand Operand1;

        /// <summary>
        ///     Instruction's Second Operand.
        /// </summary>
        public NativeX86InstructionOperand Operand2;

        /// <summary>
        ///     Instruction's Third Operand.
        /// </summary>
        public NativeX86InstructionOperand Operand3;

        /// <summary>
        ///     Instruction's Fourth Operand.
        /// </summary>
        public NativeX86InstructionOperand Operand4;

        /// <summary>
        ///     Instruction's Fifth Operand.
        /// </summary>
        public NativeX86InstructionOperand Operand5;

        /// <summary>
        ///     Instruction's Sixth Operand.
        /// </summary>
        public NativeX86InstructionOperand Operand6;

        /// <summary>
        ///     Instruction's Seventh Operand.
        /// </summary>
        public NativeX86InstructionOperand Operand7;

        /// <summary>
        ///     Instruction's Eighth Operand.
        /// </summary>
        public NativeX86InstructionOperand Operand8;

        /// <summary>
        ///     Get Instruction's Managed Prefix.
        /// </summary>
        /// <value>
        ///     Convenient property to retrieve the instruction's prefix as a managed collection. This property
        ///     allocates managed memory for a new managed collection and uses direct memory copying to copy the
        ///     collection from unmanaged memory to managed memory every time it is invoked.
        /// </value>
        public byte[] ManagedPrefix
        {
            get
            {
                fixed (byte* pPrefix = this.Prefix)
                {
                    var pPPrefix = new IntPtr(pPrefix);
                    var managedPrefix = new byte[4];

                    Marshal.Copy(pPPrefix, managedPrefix, 0, 4);
                    return managedPrefix;
                }
            }
        }

        /// <summary>
        ///     Get Instruction's Managed Operation Code.
        /// </summary>
        /// <value>
        ///     Convenient property to retrieve the instruction's operation code as a managed collection. This
        ///     property allocates managed memory for a new managed collection and uses direct memory copying to copy
        ///     the collection from unmanaged memory to managed memory every time it is invoked.
        /// </value>
        public byte[] ManagedOpcode
        {
            get
            {
                fixed (byte* pOperationCode = this.Opcode)
                {
                    var pPOperationCode = new IntPtr(pOperationCode);
                    var managedOperationCode = new byte[4];

                    Marshal.Copy(pPOperationCode, managedOperationCode, 0, 4);
                    return managedOperationCode;
                }
            }
        }
    }
}

