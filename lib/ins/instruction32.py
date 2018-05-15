import idaapi
import idc

idaapi.require("lib.ins.instruction")
idaapi.require("lib.ins.operand")

import re
from lib.helper import u_li32
from lib.ins.instruction import Instruction
from lib.ins.operand import InsOperand
from hexdump import hexdump


def call_parser(instruction_data, opcode_id, capstone_instance, d, pc):
    handler = idaapi.get_imagebase() + u_li32(instruction_data[8: 12])
    handler_name = idc.Name(handler)
    if handler_name:
        mnem = "mcall"
        operand1 = InsOperand(handler_name, is_mf_name=True)
        operand2 = None

        i = Instruction32(opcode_id, instruction_data, operand1, operand2, mnem, is_call=True, call_handler=handler)

        return i

    if idc.GetMnem(handler) in Instruction32.branching_mnemonics and idc.GetOpType(handler, 0) == idc.o_mem \
            and idc.Name(idc.GetOperandValue(handler, 0)):
        handler_name = idc.Name(idc.GetOperandValue(handler, 0))
        mnem = "mcall"
        operand1 = InsOperand(handler_name, is_mf_name=True)
        operand2 = None

        i = Instruction32(opcode_id, instruction_data, operand1, operand2, mnem, is_call=True, call_handler=handler)

        return i

    jmp_id = Instruction32.parse_handler(handler, capstone_instance)
    vm_offset = d.find_instruction_by_id(jmp_id)
    if jmp_id and not (vm_offset is None):
        mnem = "vcall"
        operand1 = InsOperand(vm_offset, is_vm_offset=True)
        operand2 = None
        i = Instruction32(opcode_id, instruction_data, operand1, operand2, mnem, is_call=True, call_handler=handler,
                          is_virtual_call=True, virtual_call_id=jmp_id)
        return i

    mnem = "(d|ic; Handler: %s)jmp" % (hex(handler))
    operand1 = InsOperand("<unparesd>", is_clean_str=True)
    operand2 = None
    i = Instruction32(opcode_id, instruction_data, operand1, operand2, mnem, is_bad_instruction=True)
    return i


def exmi_parser(instruction_data, opcode_id, capstone_instance, d, pc):
    mi_size = ord(instruction_data[1])
    mi = instruction_data[4: 4 + mi_size]

    dl = list(capstone_instance.disasm(mi, 0))
    if len(dl) > 1:
        for d in dl:
            print "%s %s" % (str(d.mnemonic), str(d.op_str))
        raise Exception("1")

    if len(dl) == 0:
        print hex(pc)
        hexdump(instruction_data)
        raise Exception("2")
    dl = dl[0]

    mi_str = "%s %s" % (str(dl.mnemonic), str(dl.op_str))
    mnem = "exmi"
    operand1 = InsOperand(mi_str, is_machine_disassm=True)
    operand2 = None

    i = Instruction32(opcode_id, instruction_data, operand1, operand2, mnem, is_machine_code_exec=True)
    return i


def movroimm32_parser(instruction_data, opcode_id, capstone_instance, d, pc):
    mnem = "mov"
    operand1 = InsOperand(0, is_tmp_reg=True)
    operand2 = InsOperand(u_li32(instruction_data[4: 8]), is_const=True)
    i = Instruction32(opcode_id, instruction_data, operand1, operand2, mnem, is_data_transfer=True)
    return i


def pushr0_parser(instruction_data, opcode_id, capstone_instance, d, pc):
    mnem = "push"
    operand1 = InsOperand(0, is_tmp_reg=True)
    operand2 = None
    i = Instruction32(opcode_id, instruction_data, operand1, operand2, mnem)
    return i


def xorr0r0_parser(instruction_data, opcode_id, capstone_instance, d, pc):
    mnem = "xor"
    operand1 = InsOperand(0, is_tmp_reg=True)
    operand2 = InsOperand(0, is_tmp_reg=True)
    i = Instruction32(opcode_id, instruction_data, operand1, operand2, mnem)
    return i


def addr0reg_parser(instruction_data, opcode_id, capstone_instance, d, pc):
    mnem = "add"
    operand1 = InsOperand(0, is_tmp_reg=True)
    r_index = u_li32(instruction_data[4: 8])
    operand2 = InsOperand(r_index, is_reg=True)
    i = Instruction32(opcode_id, instruction_data, operand1, operand2, mnem, is_data_transfer=True)
    return i


def addr0imm32_parser(instruction_data, opcode_id, capstone_instance, d, pc):
    mnem = "add"
    operand1 = InsOperand(0, is_tmp_reg=True)
    operand2 = InsOperand(u_li32(instruction_data[4: 8]), is_const=True)
    i = Instruction32(opcode_id, instruction_data, operand1, operand2, mnem, is_data_transfer=True)
    return i


def movr0refr0_parser(instruction_data, opcode_id, capstone_instance, d, pc):
    mnem = "mov"
    operand1 = InsOperand(0, is_tmp_reg=True)
    operand2 = InsOperand(0, is_ref_tmp_reg=True)
    i = Instruction32(opcode_id, instruction_data, operand1, operand2, mnem, is_data_transfer=True)
    return i


def movregr0_parser(instruction_data, opcode_id, capstone_instance, d, pc):
    mnem = "mov"
    r_index = u_li32(instruction_data[4: 8])
    operand1 = InsOperand(r_index, is_reg=True)
    operand2 = InsOperand(0, is_tmp_reg=True)
    i = Instruction32(opcode_id, instruction_data, operand1, operand2, mnem, is_data_transfer=True)
    return i


def bmovr0reg_parser(instruction_data, opcode_id, capstone_instance, d, pc):
    mnem = "bmov"
    operand1 = InsOperand(0, is_tmp_reg=True)
    r_index = u_li32(instruction_data[4: 8])
    operand2 = InsOperand(r_index, is_reg=True)
    i = Instruction32(opcode_id, instruction_data, operand1, operand2, mnem, is_data_transfer=True)
    return i


def jnz_parser(instruction_data, opcode_id, capstone_instance, d, pc):
    mnem = "rmf.jnz"
    offset = (pc + u_li32(instruction_data[5: 9])) & 0xFFFFFFFF
    operand1 = InsOperand(offset, is_vm_offset=True)
    operand2 = None
    i = Instruction32(opcode_id, instruction_data, operand1, operand2, mnem, is_branch=True, branch_target=offset)
    return i


def movrefr0reg_parser(instruction_data, opcode_id, capstone_instance, d, pc):
    r_index = u_li32(instruction_data[4: 8])
    mnem = "mov"
    operand1 = InsOperand(0, is_ref_tmp_reg=True)
    operand2 = InsOperand(r_index, is_reg=True)
    i = Instruction32(opcode_id, instruction_data, operand1, operand2, mnem, is_data_transfer=True)
    return i


def jz_parser(instruction_data, opcode_id, capstone_instance, d, pc):
    mnem = "rmf.jz"
    offset = (pc + u_li32(instruction_data[5: 9])) & 0xFFFFFFFF
    operand1 = InsOperand(offset, is_vm_offset=True)
    operand2 = None
    i = Instruction32(opcode_id, instruction_data, operand1, operand2, mnem, is_branch=True, branch_target=offset)
    return i


def jmp_parser(instruction_data, opcode_id, capstone_instance, d, pc):
    offset = u_li32(instruction_data[5: 9])
    if offset:
        mnem = "jmp"
        operand1 = InsOperand((offset + pc) & 0xFFFFFFFF, is_vm_offset=True)
        operand2 = None
        i = Instruction32(opcode_id, instruction_data, operand1, operand2, mnem, is_branch=True,
                          branch_target=(offset + pc) & 0xFFFFFFFF)
        return i

    else:
        imm32 = u_li32(instruction_data[9: 13])
        mnem = "cmovnae"
        operand2 = InsOperand(0, is_reg=True)
        operand1 = InsOperand(imm32, is_const=True)
        i = Instruction32(opcode_id, instruction_data, operand1, operand2, mnem)
        return i


def apicall_parser(instruction_data, opcode_id, capstone_instance, d, pc):
    mi_size = ord(instruction_data[1])
    mi = instruction_data[8: 8 + mi_size]
    mi_str = []
    dl = list(capstone_instance.disasm(mi, 0))[0]
    if "0x" in dl.op_str:
        m = re.search("0x([ABCDEFabcdef0-9]+)", str(dl.op_str))
        if m:
            api_offset = idaapi.get_imagebase() + int(m.group(1), 16)
            api_name = idc.Name(api_offset)
            if api_name:
                mnem = "apicall"
                operand1 = InsOperand(api_name, is_mf_name=True)
                operand2 = None
                i = Instruction32(opcode_id, instruction_data, operand1, operand2, mnem)
                return i
    mnem = "apicall"
    operand1 = InsOperand("%s %s" % (str(dl.mnemonic), str(dl.op_str)), is_machine_disassm=True)
    operand2 = None
    i = Instruction32(opcode_id, instruction_data, operand1, operand2, mnem)
    return i


def movr0reg_parser(instruction_data, opcode_id, capstone_instance, d, pc):
    mnem = "mov"
    operand1 = InsOperand(0, is_tmp_reg=True)
    r_index = u_li32(instruction_data[4: 8])
    operand2 = InsOperand(r_index, is_reg=True)
    i = Instruction32(opcode_id, instruction_data, operand1, operand2, mnem, is_data_transfer=True)
    return i


def ja_parser(instruction_data, opcode_id, capstone_instance, d, pc):
    mnem = "rmf.ja"
    offset = (pc + u_li32(instruction_data[5: 9])) & 0xFFFFFFFF
    operand1 = InsOperand(offset, is_vm_offset=True)
    operand2 = None
    i = Instruction32(opcode_id, instruction_data, operand1, operand2, mnem, is_branch=True, branch_target=offset)
    return i


def jbe_parser(instruction_data, opcode_id, capstone_instance, d, pc):
    mnem = "rmf.jbe"
    offset = (pc + u_li32(instruction_data[5: 9])) & 0xFFFFFFFF
    operand1 = InsOperand(offset, is_vm_offset=True)
    operand2 = None
    i = Instruction32(opcode_id, instruction_data, operand1, operand2, mnem, is_branch=True, branch_target=offset)
    return i


def jnb_parser(instruction_data, opcode_id, capstone_instance, d, pc):
    mnem = "rmf.jnb"
    offset = (pc + u_li32(instruction_data[5: 9])) & 0xFFFFFFFF
    operand1 = InsOperand(offset, is_vm_offset=True)
    operand2 = None
    i = Instruction32(opcode_id, instruction_data, operand1, operand2, mnem, is_branch=True, branch_target=offset)
    return i


def jb_parser(instruction_data, opcode_id, capstone_instance, d, pc):
    mnem = "rmf.jb"
    offset = (pc + u_li32(instruction_data[5: 9])) & 0xFFFFFFFF
    operand1 = InsOperand(offset, is_vm_offset=True)
    operand2 = None
    i = Instruction32(opcode_id, instruction_data, operand1, operand2, mnem, is_branch=True, branch_target=offset)
    return i


def shlr0imm8(instruction_data, opcode_id, capstone_instance, d, pc):
    imm8 = u_li32(instruction_data[4: 8]) & 0xff
    mnem = "shl"
    operand1 = InsOperand(0, is_tmp_reg=True)
    operand2 = InsOperand(imm8, is_const=True)
    i = Instruction32(opcode_id, instruction_data, operand1, operand2, mnem)
    return i


def jle_parser(instruction_data, opcode_id, capstone_instance, d, pc):
    mnem = "rmf.jle"
    offset = (pc + u_li32(instruction_data[5: 9])) & 0xFFFFFFFF
    operand1 = InsOperand(offset, is_vm_offset=True)
    operand2 = None
    i = Instruction32(opcode_id, instruction_data, operand1, operand2, mnem, is_branch=True, branch_target=offset)
    return i


def jge_parser(instruction_data, opcode_id, capstone_instance, d, pc):
    mnem = "rmf.jge"
    offset = (pc + u_li32(instruction_data[5: 9])) & 0xFFFFFFFF
    operand1 = InsOperand(offset, is_vm_offset=True)
    operand2 = None
    i = Instruction32(opcode_id, instruction_data, operand1, operand2, mnem, is_branch=True, branch_target=offset)
    return i


def unknown_parser(instruction_data, opcode_id, capstone_instance, d, pc):
    mnem = "Unknown INS: "
    operand1 = InsOperand(hex(ord(instruction_data[0])), is_clean_str=True)
    operand2 = None
    i = Instruction32(opcode_id, instruction_data, operand1, operand2, mnem, is_bad_instruction=True)
    return i


class Instruction32(Instruction):
    ins_parsers = {0x1e: call_parser,
                   0x17: exmi_parser,
                   0x1c: movroimm32_parser,
                   0x07: pushr0_parser,
                   0x08: xorr0r0_parser,
                   0x0b: addr0reg_parser,
                   0x14: addr0imm32_parser,
                   0x1b: movr0refr0_parser,
                   0x12: movregr0_parser,
                   0x1f: bmovr0reg_parser,
                   0x1d: jnz_parser,
                   0x19: movrefr0reg_parser,
                   0x13: jz_parser,
                   0x1a: jmp_parser,
                   0x0e: apicall_parser,
                   0x05: movr0reg_parser,
                   0x0f: ja_parser,
                   0x11: jbe_parser,
                   0x15: jnb_parser,
                   0x20: jb_parser,
                   0x10: shlr0imm8,
                   0x01: jle_parser,
                   0x0d: jge_parser
                   }

    def __init__(self, opcode_id, opcode_data, operand1, operand2, mnemonic, is_branch=False, is_call=False,
                 is_virtual_call=False, virtual_call_id=None, call_handler=None, branch_target=None,
                 is_machine_code_exec=False, is_data_transfer=False, is_bad_instruction=False):
        Instruction.__init__(self, opcode_id, opcode_data, operand1, operand2, mnemonic,
                             is_branch=is_branch,
                             is_call=is_call, is_virtual_call=is_virtual_call,
                             virtual_call_id=virtual_call_id,
                             call_handler=call_handler, branch_target=branch_target,
                             is_machine_code_exec=is_machine_code_exec, is_data_transfer=is_data_transfer,
                             is_bad_instruction=is_bad_instruction)

    @staticmethod
    def from_opcode_data(instruction_data, pc, opcode_id, capstone_instance, handler_table, disassm):
        opcode_number = ord(instruction_data[0])
        for bid in handler_table.keys():
            if opcode_number == bid:
                oid = handler_table[bid]
                if not Instruction32.ins_parsers.get(oid, None):
                    return unknown_parser(instruction_data, opcode_id, capstone_instance, disassm, pc)
                return Instruction32.ins_parsers[oid](instruction_data, opcode_id, capstone_instance, disassm, pc)
        return unknown_parser(instruction_data, opcode_id, capstone_instance, disassm, pc)
