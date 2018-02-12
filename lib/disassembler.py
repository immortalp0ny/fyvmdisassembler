import re

import idaapi
import idautils
import idc

idaapi.require("lib.ins.instruction32")
idaapi.require("lib.ins.instruction64")
idaapi.require("lib.graph")
idaapi.require("lib.function")
idaapi.require("lib.helper")
idaapi.require("lib.sigs.signatures")

from helper import u_li32, ror, p_li32, branching

from capstone import *
from keystone import *

from lib.ins.instruction32 import Instruction32
from lib.ins.instruction64 import Instruction64

from graph import DiGraph
from function import Function
from lib.sigs.signatures import Signature
from lib.devirt.translator import Translator

all_regs_x32 = ["eax", "ecx", "edx", "ebx", "edi", "esi"]


class FinspyDisassembler:
    def __init__(self, trace_data, trace_data_size, decrypt_key, interpretator_base, mode=32):
        self.instructions = {}

        self.call_list = {}
        self.branch_list = {}
        self.functions = {}

        self.handlers_table = {}

        # Append additional data for stopping disassembler cycle :)
        self.trace_data = trace_data + "\x00\x00\x00\x00"
        self.trace_data_size = trace_data_size

        self.decrypt_key = decrypt_key
        self.pc = 0
        self.mode = mode
        self.instruction_size = 0x18
        self.instructions_count = 34 if mode == 32 else 33

        self.interpretator_base = interpretator_base

        if self.mode == 32:
            self.md = Cs(CS_ARCH_X86, CS_MODE_32)
        else:
            self.md = Cs(CS_ARCH_X86, CS_MODE_64)
        self.md.detail = True

        self.devirtualized_functions = {}
        self.sig = Signature(interpretator_base, self.instructions_count, self.md, mode=mode)
        self.handlers_table = None

    def parse_instructions(self):
        """Parse instructions. Main disassembler cycle"""
        self.pc = 0
        while True:
            encrypted_instruction_data = self.trace_data[self.pc: self.pc + self.instruction_size]
            instruction_id = u_li32(encrypted_instruction_data[:4])
            if not instruction_id:
                break
            decrypt_instruction_data = self.decrypt_instruction(encrypted_instruction_data[4:])

            vmins = None
            if self.mode == 32:
                vmins = Instruction32.from_opcode_data(decrypt_instruction_data, self.pc, instruction_id, self.md,
                                                       self.handlers_table, self)
            else:
                vmins = Instruction64.from_opcode_data(decrypt_instruction_data, self.pc, instruction_id, self.md,
                                                       self.handlers_table, self)

            if vmins.is_branch:
                if self.branch_list.get(vmins.branch_target, -1) == -1:
                    self.branch_list[vmins.branch_target] = []
                self.branch_list[vmins.branch_target].append(self.pc)

            if vmins.is_virtual_call:
                if self.call_list.get(vmins.operand1.value, -1) == -1:
                    self.call_list[vmins.operand1.value] = []
                self.call_list[vmins.operand1.value].append(self.pc)

            self.instructions[self.pc] = vmins

            self.pc += self.instruction_size

    def build_functions(self):
        """Create all function which have visible references"""
        for pc, ins in self.instructions.iteritems():
            if ins.is_virtual_call:
                faddr = ins.operand1.value
                if faddr in self.functions.keys():
                    print "[?] Function %s already defined " % hex(faddr).replace("0x", "").replace("L", "")
                    continue

                if self.create_function(faddr, ins.call_handler):
                    print "[+] Function at %s success created" % hex(faddr).replace("0x", "").replace("L", "")

    def start(self):
        """
            Start disassembler

            :return Success status
        """
        if not self.sig.create_handlers_table():
            print "[~] Can't create handlers table"
            return False

        self.handlers_table = self.sig.handlers_table

        print "[+] Parsing start ... "
        self.parse_instructions()
        print "[+] Parse instructions completed"
        print "[+] Analyze"
        self.build_functions()

        return True

    def create_function(self, bea, haddr):
        """
            Create function descriptor from VM IP and address of handler
            :param bea: Begin IP of function in VM disassembler trace
            :param haddr: Address of handler in binary

            :return Success status
        """
        print "[+] Analyzing function by address %s" % hex(bea)
        dg = None
        try:
            dg = DiGraph(bea, self.instruction_size)
            dg.parse(self.instructions)
        except Exception:
            print "[~] Unhandled exception in create graph routine"
            return False

        if dg.is_bad_cfg:
            print "[!] Function at address: %s invalid" % hex(bea).replace("0x", "").replace("L", "")
            return False

        f = Function(bea, dg.get_low_address(), dg, "sub_%s" % hex(bea).replace("0x", "").replace("L", ""), haddr)
        self.functions[bea] = f

        return True

    def find_instruction_by_id(self, ins_id):
        """
            Get VM IP by instruction ID
            :param ins_id: Instruction ID

            :return VM IP value of found instruction or None
        """
        for pos in range(0, self.trace_data_size, 0x18):
            if pos + 4 >= self.trace_data_size:
                return None

            if u_li32(self.trace_data[pos: pos + 4]) == ins_id:
                return pos
        return None

    def decrypt_instruction(self, data):
        """
            Decrypt instruction. Notes: x32 algorithm covers full instruction data.
                                       x64 algorithm covers only first 4 bytes

            :param data: Encrypted instruction data

            :return Decrypted instruction data
        """
        key = self.decrypt_key
        if self.mode == 32:
            decrypt_instruction_data = []
            for b in data:
                decrypt_instruction_data.append((key ^ ord(b)) & 0xff)
                key = ror(key, 8, 32)
            return str(bytearray(decrypt_instruction_data))
        elif self.mode == 64:
            size = (0x18 - 4) >> 2
            dd = u_li32(data[:4])
            while True:
                dd = ((dd ^ self.decrypt_key) - self.decrypt_key) & 0xFFFFFFFF
                size -= 1
                if not size:
                    break
            decrypt_instruction_data = p_li32(dd) + data[4:]
            return decrypt_instruction_data
