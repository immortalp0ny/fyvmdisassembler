import idaapi
import idc

idaapi.require("lib.ins.instruction")
idaapi.require("lib.ins.operand")

from lib.helper import u_li32
from lib.ins import instruction
from lib.ins.operand import InsOperand
from hexdump import hexdump


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
    operand1 = InsOperand(mi_str, is_machine_disassm=True, mode=64)
    operand2 = None

    i = Instruction64(opcode_id, instruction_data, operand1, operand2, mnem, is_machine_code_exec=True)
    return i


def jmp_parser(instruction_data, opcode_id, capstone_instance, d, pc):
    if not u_li32(instruction_data[5: 9]):
        handler = idaapi.get_imagebase() + u_li32(instruction_data[9: 13])

        jmp_id = Instruction64.parse_handler(handler, capstone_instance)
        vm_offset = d.find_instruction_by_id(jmp_id)
        if jmp_id and not (vm_offset is None):
            mnemonic = "vcall"
            operand1 = InsOperand(vm_offset, is_vm_offset=True, mode=64)
            operand2 = None

            i = Instruction64(opcode_id, instruction_data, operand1, operand2, mnemonic, is_call=True,
                              is_virtual_call=True, call_handler=handler, virtual_call_id=jmp_id)
            return i

    mnemonic = "jmp"
    offset = (pc + u_li32(instruction_data[5: 9])) & 0xFFFFFFFF
    operand1 = InsOperand(offset, is_vm_offset=True, mode=64)
    operand2 = None
    i = Instruction64(opcode_id, instruction_data, operand1, operand2, mnemonic, is_branch=True,
                      branch_target=offset)

    return i


def call_parser(instruction_data, opcode_id, capstone_instance, d, pc):
    handler = idaapi.get_imagebase() + u_li32(instruction_data[8: 12])
    handler_name = idc.Name(handler)
    if handler_name:
        mnem = "mcall"
        operand1 = InsOperand(handler_name, is_mf_name=True, mode=64)
        operand2 = None

        i = Instruction64(opcode_id, instruction_data, operand1, operand2, mnem, is_call=True, call_handler=handler)

        return i

    if idc.GetMnem(handler) in Instruction64.branching_mnemonics and idc.GetOpType(handler, 0) == idc.o_mem \
            and idc.Name(idc.GetOperandValue(handler, 0)):
        handler_name = idc.Name(idc.GetOperandValue(handler, 0))
        mnem = "mcall"
        operand1 = InsOperand(handler_name, is_mf_name=True, mode=64)
        operand2 = None

        i = Instruction64(opcode_id, instruction_data, operand1, operand2, mnem, is_call=True, call_handler=handler)

        return i

    jmp_id = Instruction64.parse_handler(handler, capstone_instance)
    vm_offset = d.find_instruction_by_id(jmp_id)
    if jmp_id and not (vm_offset is None):
        mnem = "vcall"
        operand1 = InsOperand(vm_offset, is_vm_offset=True, mode=64)
        operand2 = None
        i = Instruction64(opcode_id, instruction_data, operand1, operand2, mnem, is_call=True, call_handler=handler,
                          is_virtual_call=True, virtual_call_id=jmp_id)
        return i

    mnem = "(d|ic; Handler: %s)jmp" % (hex(handler))
    operand1 = InsOperand("<unparesd>", is_clean_str=True, mode=64)
    operand2 = None
    i = Instruction64(opcode_id, instruction_data, operand1, operand2, mnem, is_bad_instruction=True)
    return i


def apicall_parser(instruction_data, opcode_id, capstone_instance, d, pc):
    mi_size = ord(instruction_data[1])
    mi = instruction_data[8: 8 + mi_size]
    mi_str = []
    dl = list(capstone_instance.disasm(mi, 0))[0]

    mnem = "apicall"
    operand1 = InsOperand("%s %s" % (str(dl.mnemonic), str(dl.op_str)), is_machine_disassm=True, mode=64)
    operand2 = None
    i = Instruction64(opcode_id, instruction_data, operand1, operand2, mnem)
    return i


def vr0call_parser(instruction_data, opcode_id, capstone_instance, d, pc):
    mnem = "evr0call"
    operand1 = None
    operand2 = None
    i = Instruction64(opcode_id, instruction_data, operand1, operand2, mnem)
    return i


def movr0imm32_parser(instruction_data, opcode_id, capstone_instance, d, pc):
    mnem = "mov"
    operand1 = InsOperand(0, is_tmp_reg=True, mode=64)
    operand2 = InsOperand(u_li32(instruction_data[4: 8]), is_const=True, mode=64)
    i = Instruction64(opcode_id, instruction_data, operand1, operand2, mnem, is_data_transfer=True)
    return i


def movregr0_parser(instruction_data, opcode_id, capstone_instance, d, pc):
    mnem = "mov"
    r_index = u_li32(instruction_data[4: 8]) / 8
    operand1 = InsOperand(r_index, is_reg=True, mode=64)
    operand2 = InsOperand(0, is_tmp_reg=True, mode=64)
    i = Instruction64(opcode_id, instruction_data, operand1, operand2, mnem, is_data_transfer=True)
    return i


def movrefr0reg_parser(instruction_data, opcode_id, capstone_instance, d, pc):
    mnem = "mov"
    r_index = u_li32(instruction_data[4: 8]) / 8
    operand1 = InsOperand(0, is_ref_tmp_reg=True, mode=64)
    operand2 = InsOperand(r_index, is_reg=True, mode=64)
    i = Instruction64(opcode_id, instruction_data, operand1, operand2, mnem, is_data_transfer=True)
    return i


def movregrefr0_parser(instruction_data, opcode_id, capstone_instance, d, pc):
    mnem = "mov"
    r_index = u_li32(instruction_data[4: 8]) / 8
    operand1 = InsOperand(r_index, is_reg=True, mode=64)
    operand2 = InsOperand(0, is_ref_tmp_reg=True, mode=64)
    i = Instruction64(opcode_id, instruction_data, operand1, operand2, mnem, is_data_transfer=True)
    return i


def movrefr0imm32_parser(instruction_data, opcode_id, capstone_instance, d, pc):
    mnem = "mov"
    operand1 = InsOperand(0, is_ref_tmp_reg=True, mode=64)
    operand2 = InsOperand(u_li32(instruction_data[4: 8]), is_const=True, mode=64)
    i = Instruction64(opcode_id, instruction_data, operand1, operand2, mnem, is_data_transfer=True)
    return i


def jnz_parser(instruction_data, opcode_id, capstone_instance, d, pc):
    mnem = "rmf.jnz"
    offset = (pc + u_li32(instruction_data[5: 9])) & 0xFFFFFFFF
    operand1 = InsOperand(offset, is_vm_offset=True, mode=64)
    operand2 = None
    i = Instruction64(opcode_id, instruction_data, operand1, operand2, mnem, is_branch=True, branch_target=offset)
    return i


def jz_parser(instruction_data, opcode_id, capstone_instance, d, pc):
    mnem = "rmf.jz"
    offset = (pc + u_li32(instruction_data[5: 9])) & 0xFFFFFFFF
    operand1 = InsOperand(offset, is_vm_offset=True, mode=64)
    operand2 = None
    i = Instruction64(opcode_id, instruction_data, operand1, operand2, mnem, is_branch=True, branch_target=offset)
    return i


def jb_parser(instruction_data, opcode_id, capstone_instance, d, pc):
    mnem = "rmf.jb"
    offset = (pc + u_li32(instruction_data[5: 9])) & 0xFFFFFFFF
    operand1 = InsOperand(offset, is_vm_offset=True, mode=64)
    operand2 = None
    i = Instruction64(opcode_id, instruction_data, operand1, operand2, mnem, is_branch=True, branch_target=offset)
    return i


def jbe_parser(instruction_data, opcode_id, capstone_instance, d, pc):
    mnem = "rmf.jbe"
    offset = (pc + u_li32(instruction_data[5: 9])) & 0xFFFFFFFF
    operand1 = InsOperand(offset, is_vm_offset=True, mode=64)
    operand2 = None
    i = Instruction64(opcode_id, instruction_data, operand1, operand2, mnem, is_branch=True, branch_target=offset)
    return i


def jle_parser(instruction_data, opcode_id, capstone_instance, d, pc):
    mnem = "rmf.jle"
    offset = (pc + u_li32(instruction_data[5: 9])) & 0xFFFFFFFF
    operand1 = InsOperand(offset, is_vm_offset=True, mode=64)
    operand2 = None
    i = Instruction64(opcode_id, instruction_data, operand1, operand2, mnem, is_branch=True, branch_target=offset)
    return i


def jnb_parser(instruction_data, opcode_id, capstone_instance, d, pc):
    mnem = "rmf.jnb"
    offset = (pc + u_li32(instruction_data[5: 9])) & 0xFFFFFFFF
    operand1 = InsOperand(offset, is_vm_offset=True, mode=64)
    operand2 = None
    i = Instruction64(opcode_id, instruction_data, operand1, operand2, mnem, is_branch=True, branch_target=offset)
    return i


def ja_parser(instruction_data, opcode_id, capstone_instance, d, pc):
    mnem = "rmf.ja"
    offset = (pc + u_li32(instruction_data[5: 9])) & 0xFFFFFFFF
    operand1 = InsOperand(offset, is_vm_offset=True, mode=64)
    operand2 = None
    i = Instruction64(opcode_id, instruction_data, operand1, operand2, mnem, is_branch=True, branch_target=offset)
    return i


def jge_parser(instruction_data, opcode_id, capstone_instance, d, pc):
    mnem = "rmf.jge"
    offset = (pc + u_li32(instruction_data[5: 9])) & 0xFFFFFFFF
    operand1 = InsOperand(offset, is_vm_offset=True, mode=64)
    operand2 = None
    i = Instruction64(opcode_id, instruction_data, operand1, operand2, mnem, is_branch=True, branch_target=offset)
    return i


def jg_parser(instruction_data, opcode_id, capstone_instance, d, pc):
    mnem = "rmf.jg"
    offset = (pc + u_li32(instruction_data[5: 9])) & 0xFFFFFFFF
    operand1 = InsOperand(offset, is_vm_offset=True, mode=64)
    operand2 = None
    i = Instruction64(opcode_id, instruction_data, operand1, operand2, mnem, is_branch=True, branch_target=offset)
    return i


def jno_parser(instruction_data, opcode_id, capstone_instance, d, pc):
    mnem = "rmf.jno"
    offset = (pc + u_li32(instruction_data[5: 9])) & 0xFFFFFFFF
    operand1 = InsOperand(offset, is_vm_offset=True, mode=64)
    operand2 = None
    i = Instruction64(opcode_id, instruction_data, operand1, operand2, mnem, is_branch=True, branch_target=offset)
    return i


def jnp_parser(instruction_data, opcode_id, capstone_instance, d, pc):
    mnem = "rmf.jnp"
    offset = (pc + u_li32(instruction_data[5: 9])) & 0xFFFFFFFF
    operand1 = InsOperand(offset, is_vm_offset=True, mode=64)
    operand2 = None
    i = Instruction64(opcode_id, instruction_data, operand1, operand2, mnem, is_branch=True, branch_target=offset)
    return i


def jns_parser(instruction_data, opcode_id, capstone_instance, d, pc):
    mnem = "rmf.jns"
    offset = (pc + u_li32(instruction_data[5: 9])) & 0xFFFFFFFF
    operand1 = InsOperand(offset, is_vm_offset=True, mode=64)
    operand2 = None
    i = Instruction64(opcode_id, instruction_data, operand1, operand2, mnem, is_branch=True, branch_target=offset)
    return i


def jo_parser(instruction_data, opcode_id, capstone_instance, d, pc):
    mnem = "rmf.jo"
    offset = (pc + u_li32(instruction_data[5: 9])) & 0xFFFFFFFF
    operand1 = InsOperand(offset, is_vm_offset=True, mode=64)
    operand2 = None
    i = Instruction64(opcode_id, instruction_data, operand1, operand2, mnem, is_branch=True, branch_target=offset)
    return i


def jp_parser(instruction_data, opcode_id, capstone_instance, d, pc):
    mnem = "rmf.jp"
    offset = (pc + u_li32(instruction_data[5: 9])) & 0xFFFFFFFF
    operand1 = InsOperand(offset, is_vm_offset=True, mode=64)
    operand2 = None
    i = Instruction64(opcode_id, instruction_data, operand1, operand2, mnem, is_branch=True, branch_target=offset)
    return i


def js_parser(instruction_data, opcode_id, capstone_instance, d, pc):
    mnem = "rmf.js"
    offset = (pc + u_li32(instruction_data[5: 9])) & 0xFFFFFFFF
    operand1 = InsOperand(offset, is_vm_offset=True, mode=64)
    operand2 = None
    i = Instruction64(opcode_id, instruction_data, operand1, operand2, mnem, is_branch=True, branch_target=offset)
    return i


def jl_parser(instruction_data, opcode_id, capstone_instance, d, pc):
    mnem = "rmf.jl"
    offset = (pc + u_li32(instruction_data[5: 9])) & 0xFFFFFFFF
    operand1 = InsOperand(offset, is_vm_offset=True, mode=64)
    operand2 = None
    i = Instruction64(opcode_id, instruction_data, operand1, operand2, mnem, is_branch=True, branch_target=offset)
    return i


def unknown_parser(instruction_data, opcode_id, capstone_instance, d, pc):
    mnem = "Unknown INS: "
    operand1 = InsOperand(hex(ord(instruction_data[0])), is_clean_str=True, mode=64)
    operand2 = None
    i = Instruction64(opcode_id, instruction_data, operand1, operand2, mnem, is_bad_instruction=True)
    return i


class Instruction64(instruction.Instruction):
    ins_parsers = {
                    0x00: jmp_parser,
                    0x02: call_parser,
                    0x03: apicall_parser,
                    0x04: exmi_parser,
                    0x07: vr0call_parser,
                    0x08: movr0imm32_parser,
                    0x09: movregr0_parser,
                    0x0a: movrefr0reg_parser,
                    0x0b: movregrefr0_parser,
                    0x0c: movrefr0imm32_parser,
                    0x11: jb_parser,
                    0x12: jbe_parser,
                    0x13: jl_parser,
                    0x14: jle_parser,
                    0x15: jnb_parser,
                    0x16: ja_parser,
                    0x17: jge_parser,
                    0x18: jg_parser,
                    0x19: jno_parser,
                    0x1a: jnp_parser,
                    0x1b: jns_parser,
                    0x1c: jnz_parser,
                    0x1d: jo_parser,
                    0x1e: jp_parser,
                    0x1f: js_parser,
                    0x20: jz_parser
                   }

    def __init__(self, opcode_id, opcode_data, operand1, operand2, mnemonic, is_branch=False, is_call=False,
                 is_virtual_call=False, virtual_call_id=None, call_handler=None, branch_target=None,
                 is_machine_code_exec=False, is_data_transfer=False, is_bad_instruction=False):
        instruction.Instruction.__init__(self, opcode_id, opcode_data, operand1, operand2, mnemonic,
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
                if not Instruction64.ins_parsers.get(oid, None):
                    return unknown_parser(instruction_data, opcode_id, capstone_instance, disassm, pc)
                return Instruction64.ins_parsers[oid](instruction_data, opcode_id, capstone_instance, disassm, pc)
        return unknown_parser(instruction_data, opcode_id, capstone_instance, disassm, pc)
