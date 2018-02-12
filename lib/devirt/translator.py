import idc
import idaapi
import idautils

import re

from keystone import *

from lib.helper import branching


class Translator:
    def __init__(self, vmd):
        self.md = vmd.md
        self.instruction_size = vmd.instruction_size
        self.functions = vmd.functions
        self.instructions = vmd.instructions
        self.mode = vmd.mode
        self.machine_word_size = self.machine_word_size = 4 if self.mode == 32 else 8

        self.search_spoiled_regs32 = ["eax", "ecx", "edx", "ebx", "edi", "esi"]
        self.search_spoiled_regs64 = ["rax", "rcx", "rdx", "rbx", "rdi", "rsi"]
        self.devirtualized_functions = {}

    def get_stacksize_of_real_function(self, ea):
        """
            For x32 search in call handler instruction sub esp, <val>
            :param ea: Address of call handler
            :return: Stack size if found or None
        """
        i = ea
        stack_size = None
        while True:

            bytes_mi = idc.GetManyBytes(i, 15)
            mi = list(self.md.disasm(bytes_mi, 0))[0]
            spreg = "esp"
            if mi.mnemonic in branching:
                break

            elif mi.mnemonic.lower() == "sub" and spreg in mi.op_str:
                m = re.search("0x([ABCDEFabcdef0-9]+)", str(mi.op_str))
                if m:
                    stack_size = int(m.group(1), 16)
                    break
            i += mi.size

        return stack_size

    def get_spoiled_registers_by_block(self, func_ins):
        """
            Search spoiled registers by block of VM instructions
            :param func_ins: Function instructions
            :return: List names of spoiled registers
        """
        regs = []
        search_spoiled_regs = self.search_spoiled_regs32 if self.mode == 32 else self.search_spoiled_regs64
        for ins in func_ins:
            if ins.is_data_transfer:
                if ins.operand1.is_reg:
                    spoil_regname = ins.operand1.get_reg_name()
                    if spoil_regname not in regs:
                        regs.append(spoil_regname)

                if ins.operand2.is_reg:
                    spoil_regname = ins.operand2.get_reg_name()
                    if spoil_regname not in regs:
                        regs.append(spoil_regname)

            if ins.is_machine_code_exec:
                for regname in search_spoiled_regs:
                    if regname in ins.operand1.value and regname not in regs:
                        regs.append(regname)

        return regs

    def get_vr0blocks(self, func_ins):
        """
            Split function on blocks of used registers
            :param func_ins: Function instruction
            :return: Function registers block descriptors
        """
        vr0x86_blocks = {}
        f_addresses = sorted(func_ins.keys())

        c_block_begin = f_addresses[0]
        c_block_end = f_addresses[-1]
        block_iter = c_block_end

        search_spoiled_regs = self.search_spoiled_regs32 if self.mode == 32 else self.search_spoiled_regs64
        while True:
            spoiled_registers_block = self.get_spoiled_registers_by_block([func_ins[x]
                                                                           for x in range(c_block_begin, block_iter,
                                                                                          self.instruction_size)])
            for i, v in enumerate(spoiled_registers_block):
                if v[0] == "e" and v.replace("e", "r") not in spoiled_registers_block:
                    spoiled_registers_block.append(v.replace("e", "r"))

            for regname in search_spoiled_regs:
                if regname not in spoiled_registers_block:
                    vr0x86_blocks[c_block_begin] = (regname, block_iter - self.instruction_size)
                    # print "blockiter %s" % hex(block_iter)
                    if block_iter == c_block_end:
                        return vr0x86_blocks
                    c_block_begin = block_iter
                    block_iter = c_block_end
                    continue

            if block_iter == c_block_begin:
                return None

            block_iter -= self.instruction_size

    def _asm_creator_x86(self, ins_list, labels, vr0x86_blocks, machine_handler, is_recursive_mode=False,
                         fixupfile=None):
        """
            Create native assembler listing for x32
            :param ins_list: Function instructions
            :param labels: Lables of nodes in graph
            :param vr0x86_blocks: Registers blocks
            :param machine_handler: Call handler of function
            :param is_recursive_mode: Enable recursive mode
            :param fixupfile: Path to fixup file
            :return: Assembler listing
        """
        fixup_addresses = []
        if fixupfile:
            fd = open(fixupfile, "r")
            fixup_addresses = [int(x.replace("\r", "").replace("0x", ""), 16) for x in fd.read().split("\n")]
            fd.close()

        f_ins_addrs = sorted(ins_list.keys())
        f_begin = f_ins_addrs[0]
        c_vr0 = None
        c_end_vr0_block = None

        asm_text = ""
        # Reserve memory for registers save load
        search_spoiled_regs = self.search_spoiled_regs32 if self.mode == 32 else self.search_spoiled_regs64
        for regname in search_spoiled_regs:
            if regname[0] != "e":
                continue
            asm_text += "dd_save_%s:\n" % regname
            asm_text += "dd 0\n"
            asm_text += "db ff\n"  # keystone bug ?

        # Empirical observation all handlers in obfuscated code contains with prologue
        asm_text += "mov edi, edi\n"
        asm_text += "push ebp\n"
        asm_text += "mov ebp, esp\n"

        stack_size = self.get_stacksize_of_real_function(machine_handler)
        if stack_size:
            asm_text += "sub esp, %s\n" % hex(stack_size).replace("L", "")
        else:
            print "[!] Warning. Can't determinate stack size for function (%s)" % hex(f_ins_addrs[0]).replace("L", "")

        asm_text += "f_begin_l:\n"

        is_first_block = True
        for pc in f_ins_addrs:
            ins = ins_list[pc]

            # First block in begin of function save value of register
            if vr0x86_blocks.get(pc, None):
                c_vr0, c_end_vr0_block = vr0x86_blocks[pc]
                if is_first_block:
                    asm_text += "mov dword ptr [%s], %s\n" % ("dd_save_%s" % c_vr0, c_vr0)

            # Have VM IP label?
            if labels.get(pc, None):
                asm_text += "%s: \n" % labels[pc]

            if ins.is_machine_code_exec:
                asm_text += "%s \n" % ins.operand1.value
            elif ins.is_branch:
                asm_text += "%s %s\n" % (ins.mnemonic.replace("rmf.", ""), labels[ins.operand1.value])
            elif ins.is_call:
                call_addr = ins.call_handler

                # Recursion protect
                if ins.operand1.value == f_begin:
                    asm_text += "call f_begin_l\n"
                    continue

                if is_recursive_mode and ins.is_virtual_call:
                    if ins.operand1.value in self.devirtualized_functions.keys():
                        call_addr, _ = self.devirtualized_functions[ins.operand1.value]
                    else:
                        call_addr = self.__to_native(self.functions[ins.operand1.value],
                                                     is_recursive_mode=is_recursive_mode,
                                                     fixupfile=fixupfile)

                asm_text += "mov %s, %s \ncall %s\n" % (c_vr0, hex(call_addr).replace("L", ""), c_vr0)
            elif ins.mnemonic == "apicall":
                if ins.operand1.is_machine_disassm:
                    asm_text += "%s \n" % ins.operand1.value.replace("jmp", "call")
                else:
                    api_addr = idc.LocByName(ins.operand1.value)
                    asm_text += "mov %s, %s\n" % (c_vr0, hex(api_addr).replace("L", ""))
                    asm_text += "call %s\n" % c_vr0
            else:
                # Very dirty but ...
                if ins.mnemonic == "add" and ins.operand2.is_const and ins.operand1.is_tmp_reg \
                        and (ins.operand2.value & 0x80000000):
                    asm_line = "sub %s, %s\n" % (
                        "vr0", hex(((0x80000000 - ins.operand2.value) & 0x7fffffff)).replace("L", ""))
                    asm_line = asm_line.replace("vr0", c_vr0).replace("bmov", "mov")
                else:
                    asm_line = "%s \n" % ins.get_disassm(virtual_reg=False).replace("vr0", c_vr0).replace("bmov", "mov")
                if ins.operand2 and ins.operand2.value in fixup_addresses:
                    r = hex(ins.operand2.value + idaapi.get_imagebase()).replace("L", "")
                    asm_line = asm_line.replace(ins.operand2.convert_operand(virtual_reg=False), r)

                asm_text += asm_line

            # End of registers block
            #   - Save next block VR0
            #   - Move value of current VR0 to next block VR0
            #   - Restore saved value of VR0
            if pc == c_end_vr0_block:
                next_ins_addr = pc + self.instruction_size
                if vr0x86_blocks.get(next_ins_addr, None):
                    next_block_vr0, _ = vr0x86_blocks[pc + self.instruction_size]
                    asm_text += "mov dword ptr [%s], %s\n" % ("dd_save_%s" % next_block_vr0, next_block_vr0)
                    asm_text += "mov %s, %s\n" % (next_block_vr0, c_vr0)
                    asm_text += "mov %s, dword ptr [%s]\n" % (c_vr0, "dd_save_%s" % c_vr0)
                else:
                    asm_text += "mov %s, dword ptr [%s]\n" % (c_vr0, "dd_save_%s" % c_vr0)

        return asm_text

    def _asm_creator_x64(self, ins_list, labels, vr0x86_blocks, machine_handler, is_recursive_mode=False,
                         fixupfile=None):
        """
            Create native assembler listing for x64
            :param ins_list: Function instructions
            :param labels: Lables of nodes in graph
            :param vr0x86_blocks: Registers blocks
            :param machine_handler: Call handler of function
            :param is_recursive_mode: Enable recursive mode
            :param fixupfile: Path to fixup file
            :return: Assembler listing
        """

        fixup_addresses = []
        if fixupfile:
            fd = open(fixupfile, "r")
            fixup_addresses = [int(x.replace("\r", "").replace("0x", ""), 16) for x in fd.read().split("\n")]
            fd.close()

        f_ins_addrs = sorted(ins_list.keys())
        f_begin = f_ins_addrs[0]
        c_vr0 = None
        c_end_vr0_block = None

        asm_text = ""
        search_spoiled_regs = self.search_spoiled_regs32 if self.mode == 32 else self.search_spoiled_regs64
        for regname in search_spoiled_regs:
            if regname[0] != "r":
                continue
            asm_text += "dq_save_%s:\n" % regname
            asm_text += "dq 0\n"
            asm_text += "dq ff\n"  # keystone bug ?

        asm_text += "f_begin_l:\n"

        is_first_block = True
        for pc in f_ins_addrs:
            ins = ins_list[pc]

            if vr0x86_blocks.get(pc, None):
                c_vr0, c_end_vr0_block = vr0x86_blocks[pc]
                if is_first_block:
                    asm_text += "mov qword ptr [%s], %s\n" % ("dq_save_%s" % c_vr0, c_vr0)

            if labels.get(pc, None):
                asm_text += "%s: \n" % labels[pc]

            if ins.is_machine_code_exec:
                asm_text += "%s \n" % ins.operand1.value
            elif ins.is_branch:
                asm_text += "%s %s\n" % (ins.mnemonic.replace("rmf.", ""), labels[ins.operand1.value])
            elif ins.is_call:
                call_addr = ins.call_handler

                if ins.operand1.value == f_begin:
                    asm_text += "call f_begin_l\n"
                    continue

                if is_recursive_mode and ins.is_virtual_call:
                    if ins.operand1.value in self.devirtualized_functions.keys():
                        call_addr, _ = self.devirtualized_functions[ins.operand1.value]
                    else:
                        call_addr = self.__to_native(self.functions[ins.operand1.value],
                                                     is_recursive_mode=is_recursive_mode,
                                                     fixupfile=fixupfile)

                asm_text += "mov %s, %s \ncall %s\n" % (c_vr0, hex(call_addr).replace("L", ""), c_vr0)
            elif ins.mnemonic == "apicall":
                asm_text += "%s \n" % ins.operand1.value.replace("push", "call")
            elif ins.mnemonic == "evr0call":
                asm_text += "call %s\n" % c_vr0
            else:
                if ins.mnemonic == "mov" and ins.operand1.is_tmp_reg \
                        and ins_list[pc + self.instruction_size].mnemonic == "evr0call":
                    asm_line = "mov %s, %s\n" % (c_vr0, hex(ins.operand2.value + idaapi.get_imagebase()).replace("L", ""))
                else:
                    asm_line = "%s \n" % ins.get_disassm(virtual_reg=False).replace("vr0", c_vr0)

                if ins.operand2 and ins.operand2.value in fixup_addresses:
                    r = hex(ins.operand2.value + idaapi.get_imagebase()).replace("L", "")
                    asm_line = asm_line.replace(ins.operand2.convert_operand(virtual_reg=False), r)

                asm_text += asm_line

            if pc == c_end_vr0_block:
                next_ins_addr = pc + self.instruction_size
                if vr0x86_blocks.get(next_ins_addr, None):
                    next_block_vr0, _ = vr0x86_blocks[pc + self.instruction_size]
                    asm_text += "mov qword ptr [%s], %s\n" % ("dq_save_%s" % next_block_vr0, next_block_vr0)
                    asm_text += "mov %s, %s\n" % (next_block_vr0, c_vr0)
                    asm_text += "mov %s, qword ptr [%s]\n" % (c_vr0, "dq_save_%s" % c_vr0)
                else:
                    asm_text += "mov %s, qword ptr [%s]\n" % (c_vr0, "dq_save_%s" % c_vr0)

        return asm_text

    def __to_native(self, function, is_recursive_mode=False, fixupfile=None):
        """
            Process translating VM byte code to native machine code
            :param function: Function descriptor
            :param is_recursive_mode: Enable recursive mode
            :param fixupfile: Path to fixup file
            :return:  Address of new segment where were native code wrote
        """
        print "[+] Translate begin. Function %s" % hex(function.begin_ea)
        ks = None

        if self.mode == 32:
            ks = Ks(KS_ARCH_X86, KS_MODE_32)
        else:
            ks = Ks(KS_ARCH_X86, KS_MODE_64)

        locs = {function.graph.nodes[na].begin_ea for na in function.graph.nodes}
        func_addresses = []
        for x in function.graph.nodes:
            for y in range(function.graph.nodes[x].begin_ea, function.graph.nodes[x].end_ea + self.instruction_size,
                           self.instruction_size):
                func_addresses.append(y)

        func_ins = {x: self.instructions[x] for x in func_addresses}

        vr0x86_blocks = self.get_vr0blocks(func_ins)

        print "[+] Blocks for %s" % hex(function.begin_ea).replace("L", "")
        i = 0
        for pc in vr0x86_blocks.keys():
            c_vr0, c_end_vr0_block = vr0x86_blocks[pc]
            print "----BLOCK %s----" % i
            print "   -> [?] Block begin: %s" % hex(pc).replace("L", "")
            print "   -> [?] Block end: %s" % hex(c_end_vr0_block).replace("L", "")
            print "   -> [?] Block vr0: %s" % c_vr0
            i += 1

        labels = {}
        li = 0
        for loc in locs:
            labels[loc] = "label_%s" % li
            li += 1

        function_real_base = function.machine_handler
        print "[+] Real function base: %s" % hex(function_real_base).replace("L", "")

        if self.mode == 32:
            asm_text = self._asm_creator_x86(func_ins, labels, vr0x86_blocks, function.machine_handler,
                                             is_recursive_mode=is_recursive_mode,
                                             fixupfile=fixupfile)
        else:
            asm_text = self._asm_creator_x64(func_ins, labels, vr0x86_blocks, function.machine_handler,
                                             is_recursive_mode=is_recursive_mode,
                                             fixupfile=fixupfile)

        print asm_text

        segs = list(idautils.Segments())
        last_seg_ea = idc.SegEnd(segs[len(segs) - 1])

        encoding, count = ks.asm(asm_text, addr=last_seg_ea)

        seg_name = ".devirt_%s" % function.name
        seg_size = len(encoding) + self.machine_word_size
        if not idc.AddSeg(last_seg_ea, last_seg_ea + seg_size, 0, 1, 0, idaapi.scPub):
            print "[~] Can't create segment at address %s" % hex(last_seg_ea)
            return

        if not idc.RenameSeg(last_seg_ea, seg_name):
            print "[!] Failed rename segment. Segment name %s" % seg_name

        if not idc.SetSegClass(last_seg_ea, 'CODE'):
            print "[!] Failed set CODE class. Segment name %s" % seg_name

        if not idc.SegAlign(last_seg_ea, idc.saRelPara):
            print "[!] Failed set align. Segment name %s" % seg_name

        bitness = 1
        if self.mode == 64:
            bitness = 2

        if not idc.SetSegAddressing(last_seg_ea, bitness):
            print "[!] Failed set bitness. Segment name %s" % seg_name

        if self.mode == 32:
            idc.PatchDword(last_seg_ea, 0)
        else:
            idc.PatchQword(last_seg_ea, 0)

        last_seg_ea += self.machine_word_size

        waddr = last_seg_ea
        for b in encoding:
            idc.PatchByte(waddr, b)
            waddr += 1

        print "[+] Write binary to: %s" % hex(last_seg_ea).replace("L", "")
        self.devirtualized_functions[function.begin_ea] = (last_seg_ea, len(encoding) + 4)
        return last_seg_ea

    def to_x86(self, function, is_recursive_mode=False, fixupfile=None):
        """
            Wrapper for x32 VM byte code translator
            :param function: Function descriptor
            :param is_recursive_mode: Enable recursive mode
            :param fixupfile: Path to fixup file
            :return:  Address of new segment where were native code wrote
        """
        return self.__to_native(function, is_recursive_mode=is_recursive_mode, fixupfile=fixupfile)

    def to_x64(self, function, is_recursive_mode=False, fixupfile=None):
        """
            Wrapper for x64 VM byte code translator
            :param function: Function descriptor
            :param is_recursive_mode: Enable recursive mode
            :param fixupfile: Path to fixup file
            :return:  Address of new segment where were native code wrote
        """
        return self.__to_native(function, is_recursive_mode=is_recursive_mode, fixupfile=fixupfile)
