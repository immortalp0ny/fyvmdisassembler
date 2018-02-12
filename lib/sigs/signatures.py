import idc
import idaapi
import re
from binascii import hexlify

idaapi.require("lib.helper")
idaapi.require("lib.sigs.handlers32")
idaapi.require("lib.sigs.hadnlers64")

from lib.helper import conditional_branching
from lib.sigs.handlers32 import x32_signatures
from lib.sigs.hadnlers64 import x64_signatures


class Signature:
    def __init__(self, interpretator_base, instructions_count, capstone_instance, mode=32):
        self.mode = mode
        self.machine_word_size = 4 if mode == 32 else 8
        self.interpretator_base = interpretator_base
        self.md = capstone_instance
        self.instructions_count = instructions_count
        self.handlers_table = None

    def read_machine_word_array(self, a, count):
        """
            Simple function read DWORDS or QWORDS array from IDA depending on arch of VM
            :param a: Start array address
            :param count: Length of array (in elements)
            :return: Read array

        """
        return [idc.Dword(x) for x in range(a, a + count * self.machine_word_size, self.machine_word_size)]

    def find_instructions_handlers(self):
        """
            Walker for obfuscated VM interpreter. Search JMP dispatcher and address of handlers table
            :return: Address of handlers table
        """
        addr = self.interpretator_base

        i_interpretator = []

        offset_to_handlers_table = None

        while True:
            fy_useful_ins = []
            rb = idc.GetManyBytes(addr, 0x40)
            fy_block = list(self.md.disasm(rb, 0))
            if len(fy_block) < 3:
                print "[~] Invalid fy block at %s" % hex(addr)
                return None

            if fy_block[0].mnemonic == "jmp":
                back = len(i_interpretator) - 1 if self.mode == 32 else len(i_interpretator) - 3

                o_addr, ins = i_interpretator[back][0]
                print "[+] Dispatcher jump found. Address: %s" % hex(addr).replace("L", "")
                print ins.mnemonic
                print ins.op_str
                m = re.search("0x([ABCDEFabcdef0123456789]+)", ins.op_str)
                if not m:
                    print "[+] Can't calculated handlers table adddress"
                    return None
                if self.mode == 32:
                    offset_to_handlers_table += int(m.group(1), 16)
                else:
                    offset_to_handlers_table = int(m.group(1), 16) + ins.size + o_addr

                print "[+] Address of handlers table: %s" % hex(offset_to_handlers_table).replace("L", "")
                break

            if fy_block[0].mnemonic == "call" and int(fy_block[0].op_str, 16) == 5:
                offset_to_handlers_table = addr + fy_block[0].size

            obf_blocks = []
            for i, ins in enumerate(fy_block):
                if ins.mnemonic in conditional_branching:
                    obf_blocks = fy_block[i:]
                    break

                fy_useful_ins.append((addr, ins))

            if len(obf_blocks) < 2 and len(fy_useful_ins) > 1:
                print "[~] Invalid obf block on address %s" % hex(addr)

            obf_branch_1 = obf_blocks[0]
            # obf_branch_2 = obf_blocks[2]

            j_operand = int(obf_branch_1.op_str, 16)
            if j_operand & 0x80000000:
                j_operand = (0 - (~j_operand + 1))
            addr = (addr + j_operand) & 0xffffffff

            i_interpretator.append(fy_useful_ins)

        return offset_to_handlers_table

    def crawl_signature_from_handler(self, handler_address):
        """
            Walker for obfuscated VM INS handler and crawl signature for it
            :param handler_address: Address of handler
            :return: Handler signature
        """
        addr = handler_address

        signature = ""

        while True:
            fy_useful_ins = []
            rb = idc.GetManyBytes(addr, 0x40 if self.mode == 32 else 0x80)
            fy_block = list(self.md.disasm(rb, 0))
            if len(fy_block) < 2:
                print "[~] Invalid fy block at %s" % hex(addr)
                return None

            if fy_block[0].mnemonic == "jmp":
                signature += fy_block[0].bytes
                break

            obf_blocks = []
            for i, ins in enumerate(fy_block):
                if ins.mnemonic in conditional_branching:
                    obf_blocks = fy_block[i:]
                    break

                fy_useful_ins.append((addr, ins))

            if len(obf_blocks) < 2 and len(fy_useful_ins) > 1:
                print "[~] Invalid obf block on address %s" % hex(addr)

            obf_branch_1 = obf_blocks[0]
            obf_branch_2 = obf_blocks[1]

            if int(obf_branch_1.op_str, 16) != int(obf_branch_2.op_str, 16):
                signature += str(bytearray([ord(x) for x in obf_branch_1.mnemonic]))
                j_operand = int(obf_branch_1.op_str, 16)
                if j_operand & 0x80000000:
                    j_operand = (0 - (~j_operand + 1))
                signature += self.crawl_signature_from_handler((addr + j_operand) & 0xffffffff)

            c_addr = addr

            j_operand = int(obf_branch_2.op_str, 16)
            if j_operand & 0x80000000:
                j_operand = (0 - (~j_operand + 1))
            addr = (addr + j_operand) & 0xffffffff

            ts = ""
            for _, uins in fy_useful_ins:
                if uins.mnemonic == "lea":
                    continue
                signature += uins.bytes
                ts += uins.bytes
                print "[+] Block (address - sig part): %s - %s" % (hex(c_addr), hexlify(ts))

        return signature

    def resolve_instructions_handlers(self, table_address):
        """
            Process mapping between hardcoded signatures and crawled signatures. Create mapping handlers table.
            :param table_address:  Address of handlers table
            :return: Handlers mapped table
        """
        addresses = self.read_machine_word_array(table_address, self.instructions_count)
        if self.mode == 64:
            addresses = [x + table_address for x in addresses]

        handler_table = {}
        for i, handler_address in enumerate(addresses):
            print "[+] Analyze handler with number %s and address %s" % (hex(i), hex(handler_address))
            h_signature = self.crawl_signature_from_handler(handler_address)
            print "[+] Signature: %s - id: %s" % (hexlify(h_signature), hex(i))
            sigs = x32_signatures if self.mode == 32 else x64_signatures
            for number, hid, signature in sigs:
                if hexlify(h_signature) == signature:
                    handler_table[i] = number
                    print "[+] Mapping instruction: OID [ %s ] -> BID [ %s ]" % (hex(number), hex(i))
        return handler_table

    def create_handlers_table(self):
        """
            Find instruction handlers and create mapping handlers table
            :return: Success status
        """
        print "[+] Start finding instruction handlers"
        handlers_table_offset = self.find_instructions_handlers()
        if not handlers_table_offset:
            return False

        self.handlers_table = self.resolve_instructions_handlers(handlers_table_offset)

        if len(self.handlers_table):
            return True

        return False