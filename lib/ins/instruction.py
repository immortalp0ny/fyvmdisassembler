import idc
import re
from hexdump import hexdump


class Instruction:
    conditional_branching = ["jz", "je", "jnz", "jne", "js", "jns", "jo", "jno", "jpe", "jp", "jpo", "jnp", "jb",
                             "jnae",
                             "jc", "jb", "jnae", "jc", "jnb", "jae", "jnc", "jbe", "jna", "jnbe", "ja", "jl",
                             "jnge",
                             "jnl", "jge", "jle", "jng", "jnle", "jg"]
    unconditional_branching = ["jmp"]
    branching_mnemonics = conditional_branching + unconditional_branching

    max_instruction_size = 15

    def __init__(self, opcode_id, opcode_data, operand1, operand2, mnemonic, is_branch=False, is_call=False,
                 is_virtual_call=False, virtual_call_id=None, call_handler=None, branch_target=None,
                 is_machine_code_exec=False, is_data_transfer=False, is_bad_instruction=False):
        self.opcode_id = opcode_id
        self.opcode_data = opcode_data
        self.operand1 = operand1
        self.operand2 = operand2
        self.mnemonic = mnemonic
        self.is_branch = is_branch
        self.is_call = is_call
        self.is_virtual_call = is_virtual_call
        self.virtual_call_id = virtual_call_id
        self.call_handler = call_handler
        self.branch_target = branch_target
        self.is_machine_code_exec = is_machine_code_exec
        self.is_data_transfer = is_data_transfer
        self.is_bad_instruction = is_bad_instruction

    @staticmethod
    def parse_handler(ea, capstone_instance):
        """
            Search in handler instruction ID
            :param ea: Address of call handler
            :param capstone_instance: Instance of capstone disassembler
            :return: Instruction ID or None

        """
        i = ea
        jmp_id = None
        while True:

            bytes_mi = idc.GetManyBytes(i, Instruction.max_instruction_size)
            mi = list(capstone_instance.disasm(bytes_mi, 0))[0]
            if mi.mnemonic in Instruction.branching_mnemonics:
                break
            elif mi.mnemonic.lower() == "push":
                m = re.search("0x([ABCDEFabcdef0-9]+)", str(mi.op_str))
                if m:
                    if int(m.group(1), 16) > 0xffffff:
                        jmp_id = int(m.group(1), 16)
                        break
            i += mi.size

        return jmp_id

    def get_disassm(self, virtual_reg=True, to_alias=False):
        """
            Get disassembly text of instruction
            :param virtual_reg: Switch mode real registers or virtual
            :param to_alias: Convert instruction operands to aliases
            :return: Disassembly text
        """
        if not self.operand1 and not self.operand2:
            return self.mnemonic

        if not self.operand2:
            return "%s %s" % (self.mnemonic, self.operand1.convert_operand(virtual_reg=virtual_reg, to_alias=to_alias))

        return "%s %s, %s" % (self.mnemonic, self.operand1.convert_operand(virtual_reg=virtual_reg, to_alias=to_alias),
                                               self.operand2.convert_operand(virtual_reg=virtual_reg, to_alias=to_alias))

    @staticmethod
    def from_opcode_data(instruction_data, pc, id, capstone_instance, handler_table, disassm):
        raise NotImplementedError("Abstract method")

