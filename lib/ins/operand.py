

class InsOperand:
    def __init__(self, value, is_reg=False, is_ref_reg=False, is_const=False, is_machine_disassm=False,
                 is_vm_offset=False, is_mf_name=False, is_clean_str=False, is_tmp_reg=False, is_ref_tmp_reg=False,
                 mode=32):
        self.value = value
        self.is_reg = is_reg
        self.is_const = is_const
        self.is_machine_disassm = is_machine_disassm
        self.is_vm_offset = is_vm_offset
        self.is_mf_name = is_mf_name
        self.is_clean_str = is_clean_str
        self.is_tmp_reg = is_tmp_reg
        self.is_ref_tmp_reg = is_ref_tmp_reg
        self.is_ref_reg = is_ref_reg

        self.__mode = mode

        self.operand_value_alias = ""

        self.__reg_convert_table32 = {
                                           7: {"V": "vr2", "R": "edi"},
                                           6: {"V": "vr3", "R": "esi"},
                                           5: {"V": "vr4", "R": "ebp"},
                                           4: {"V": "vr5", "R": "esp"},
                                           3: {"V": "vr6", "R": "ebx"},
                                           2: {"V": "vr7", "R": "edx"},
                                           1: {"V": "vr8", "R": "ecx"},
                                           0: {"V": "vr9", "R": "eax"}
                                }

        self.__reg_convert_table64 = {
                                      1:  {"V": "evr2", "R": "r15"},
                                      2:  {"V": "evr3", "R": "r14"},
                                      3:  {"V": "evr4", "R": "r13"},
                                      4:  {"V": "evr5", "R": "r12"},
                                      5:  {"V": "evr6", "R": "r11"},
                                      6:  {"V": "evr7", "R": "r10"},
                                      7:  {"V": "evr8", "R": "r9"},
                                      8:  {"V": "evr9", "R": "r8"},
                                      9:  {"V": "evr10", "R": "rdi"},
                                      10: {"V": "evr11", "R": "rsi"},
                                      11: {"V": "evr12", "R": "rbp"},
                                      12: {"V": "evr13", "R": "rsp"},
                                      13: {"V": "evr14", "R": "rbx"},
                                      14: {"V": "evr15", "R": "rdx"},
                                      15: {"V": "evr16", "R": "rcx"},
                                      16: {"V": "evr17", "R": "rax"}
        }

    def get_reg_name(self):
        """
            Get register name
            :return: Register name or None if operand not a register
        """
        if self.is_reg:
            return self.__reg_convert_table32[self.value]["R"] if self.__mode == 32 \
                else self.__reg_convert_table64[self.value]["R"]

        return None

    def convert_operand(self, virtual_reg=True, to_alias=False):
        """
            Convert operand for disassembler output
            :param virtual_reg: Switch mode real registers or virtual
            :param to_alias: Convert operand to alias
            :return: Friendly view value of operand
        """
        if to_alias:
            return self.operand_value_alias

        if self.is_reg:
            if virtual_reg:
                return self.__reg_convert_table32[self.value]["V"] if self.__mode == 32 \
                    else self.__reg_convert_table64[self.value]["V"]
            else:
                return self.__reg_convert_table32[self.value]["R"] if self.__mode == 32 \
                    else self.__reg_convert_table64[self.value]["R"]
        elif self.is_const:
            return hex(self.value).replace("L", "")
        elif self.is_machine_disassm:
            return "{ %s }" % self.value
        elif self.is_mf_name:
            return "<&%s>" % self.value
        elif self.is_clean_str:
            return self.value
        elif self.is_vm_offset:
            return "%s" % hex(self.value).replace("L", "")
        elif self.is_tmp_reg:
            return "vr0"
        elif self.is_ref_tmp_reg:
            return "[vr0]"
        else:
            return "InvalidArg"

