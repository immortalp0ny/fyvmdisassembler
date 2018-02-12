import json
import os
import random
import string
import traceback

import idaapi

idaapi.require("lib.disassembler")
idaapi.require("lib.dline")
idaapi.require("lib.helper")
idaapi.require("lib.forms.dialogs")
idaapi.require("lib.forms.graph")
idaapi.require("lib.devirt.translator")


from disassembler import FinspyDisassembler
from lib.devirt.translator import Translator

from dline import DisassemblerViewLine
from lib.forms.dialogs import JumpByForm, CommentForm, FunctionRenameForm, DefineFunctionForm, ToNativeForm
from lib.forms.graph import FunctionGraphView

from helper import data_hexlify


__d_version__ = "1.2.2"


class DisassemblerView(idaapi.simplecustviewer_t):
    def Create(self, fn, ep_id, decrypt_key, interpreter_base, additional_window_name="", vmd=None, ep=None,
               lines=None, lines_by_index=None, j_addr=None, mode=32, show_opcode=False, show_id=False, is_virtual_reg=False):

        self.disasm_padding = 16
        self.auto_comment_padding = self.disasm_padding
        self.sub_padding = 10

        self.fn = fn
        self.ep_id = ep_id
        self.decrypt_key = decrypt_key
        self.mode = mode
        self.interpreter_base = interpreter_base
        self.show_opcode = show_opcode
        self.show_id = show_id

        self.lines = {} if not lines else lines
        self.lines_by_index = {} if not lines_by_index else lines_by_index
        self.comments = {}

        self.is_virtual_reg = is_virtual_reg

        if show_opcode:
            self.sub_padding += 37
            self.auto_comment_padding += 47

        if show_id:
            self.sub_padding += 14
            self.auto_comment_padding += 10

        window_id = ""
        if additional_window_name:
            window_id = "Window: %s" % additional_window_name

        # Create the customview
        if not idaapi.simplecustviewer_t.Create(self, "Disasm file - %s EP: %s Mode x%s %s" % (os.path.basename(fn),
                                                                                                   hex(
                                                                                                       self.ep_id),
                                                                                                   mode, window_id)):
                return False

        if not vmd:
            fd = open(fn, 'rb')
            self.trace_data = fd.read()
            self.trace_data_size = len(self.trace_data)
            fd.close()

            self.vmd = FinspyDisassembler(self.trace_data, self.trace_data_size, self.decrypt_key,
                                          self.interpreter_base, mode=mode)

            self.ep = self.vmd.find_instruction_by_id(self.ep_id)
            if not self.ep:
                print "[~] Can't find VM EntryPoint"
                return False

            try:
                status = self.vmd.start()
            except Exception as ex:
                print ex.message
                print ex.args
                print traceback.print_exc()
                status = False

            if not status:
                print "[!] Disassembler error"
                return False

        else:
            self.ep = ep
            self.vmd = vmd

        if not self.lines:
            self._fill_view(comments=self.comments)
        else:
            for _, line in self.lines_by_index.iteritems():
                self.AddLine(line.text)

        self.pm_save_db = self.AddPopupMenu("Save db")
        self.pm_load_db = self.AddPopupMenu("Load db")
        self.pm_jump_by_address = self.AddPopupMenu("Jump by address")
        self.pm_jump_to_in_new_window = self.AddPopupMenu("Jump by address in new window")
        self.pm_rename_function = self.AddPopupMenu("Rename function")
        self.pm_show_function_graph = self.AddPopupMenu("View function graph")
        self.pm_function_define = self.AddPopupMenu("Define function")
        self.pm_add_comment_to_line = self.AddPopupMenu("Add comment")

        if mode == 32:
            self.pm_convert_to_x86 = self.AddPopupMenu("To X86")
        else:
            self.pm_convert_to_x64 = self.AddPopupMenu("To X64")

        if not j_addr:
            self._jump_by_addr(self.ep)
            print "[+] VM EntryPoint Found! $pc = %s" % hex(self.ep).replace("L", "")
        else:
            self._jump_by_addr(j_addr)

        return True
 
    def get_xref(self, address):
        if self.vmd.branch_list.get(address, None):
            return self.vmd.branch_list[address]

        if self.vmd.call_list.get(address, None):
            return self.vmd.call_list[address]

        return None

    def get_function_by_line_index(self, line_index):
        line = self.lines_by_index[line_index]
        if not line.function:
            print "[!] Line doesn't associated with function. Choose another line (example: line with instruction)"
            return None
        return line.function

    def _fill_view(self, comments=None):
        self.ClearLines()
        instructions = self.vmd.instructions

        sorted_pc = sorted(instructions.keys())
        line_index = 0
        current_function = None
        for pc in sorted_pc:
            comment = comments.get(pc, "") if comments else ""
            self.lines[pc] = []
            if pc == self.ep:
                self.create_empty_line(line_index, pc, comment)
                line_index += 1

                self.create_ep_comment_line(line_index, pc)
                line_index += 1

                self.create_empty_line(line_index, pc, comment)
                line_index += 1

            if self.vmd.functions.get(pc, None):
                current_function = self.vmd.functions[pc]

                self.create_empty_line(line_index, pc, comment)
                line_index += 1

                self.create_function_name_line(line_index, current_function, pc, is_begin=True)
                line_index += 1

                self.create_empty_line(line_index, pc, comment)
                line_index += 1

            xrefs = self.get_xref(pc)
            if xrefs:
                self.create_loc_line(line_index, pc, current_function)
                line_index += 1

                for xref in xrefs:
                    self.create_code_xref_line(line_index, pc, xref)
                    line_index += 1

            ins = instructions[pc]

            opcode_data = "" if not self.show_opcode else "[%s]" % data_hexlify(ins.opcode_data)
            ins_id = "" if not self.show_id else "[%s]" % hex(ins.opcode_id).replace("L", "")

            if ins.is_virtual_call:
                comment = "// Handler: %s" % hex(ins.call_handler).replace("0x", "").replace("L", "")
                ins.operand1.operand_value_alias = self.vmd.functions[ins.operand1.value].name
                dtext = ins.get_disassm(virtual_reg=self.is_virtual_reg, to_alias=True)
            else:
                dtext = ins.get_disassm(virtual_reg=self.is_virtual_reg)

            if not self.creaete_instruction_line(line_index, pc, opcode_data, ins_id, dtext, comment, current_function,
                                                 ins):
                print "[~] Error appending line at $pc = %s" % hex(pc)
            else:
                line_index += 1

            if current_function and pc == current_function.end_ea:
                self.create_empty_line(line_index, pc, comment)
                line_index += 1

                self.create_function_name_line(line_index, current_function, pc, is_begin=False)
                line_index += 1

                self.create_empty_line(line_index, pc, comment)
                line_index += 1
                current_function = None

        self.Refresh()

    def _jump_by_addr(self, addr):
        if not self.lines.get(addr, None):
            print "[!] Can't jump by %s" % hex(addr).replace("L", "")
            return False
        dlines = self.lines[addr]
        for dline in dlines:
            if not dline.is_empty:
                self.Jump(dline.line_index)
                return True

        self.Jump(dlines[0].line_index)
        return True

    def _convert_ida_word_function(self, word):
        cf = None
        for ep, f in self.vmd.functions.iteritems():
            if f.name == word:
                cf = f
                break
        if cf:
            return cf

    def _convert_ida_word_to_addr(self, word):
        if not word:
            return False

        cf = self._convert_ida_word_function(word)
        if cf:
            return cf.begin_ea

        prepared_word = None
        word = word.replace(":", "")
        if isinstance(word, str) or isinstance(word, unicode):
            if len(word) > 0:
                if len(word) >= 3 and "0" == word[0] and "x" in word[1]:
                    word = word.replace("0x", "")
                if all(c in string.hexdigits for c in word):
                    prepared_word = int(word, 16)
                else:
                    return None
            else:
                return None
        else:
            return None

        return prepared_word
    
# Colorize lines in custom view
    def as_directive(self, s):
        return idaapi.COLSTR(s, idaapi.SCOLOR_KEYWORD)

    def as_loc(self, s):
        return idaapi.COLSTR(s, idaapi.SCOLOR_LOCNAME)

# helpers for creating lines
    def create_line(self, line_index, ins, function, pc, text, comment, is_empty=False):
        if not self.AddLine(text):
            return False

        l = DisassemblerViewLine(line_index, ins, function, pc, text, comment, is_empty=is_empty)
        self.lines[pc].append(l)
        self.lines_by_index[line_index] = l

        return True

    def create_empty_line(self, line_index, pc, comment):
        return self.create_line(line_index, None, None, pc, "", comment, is_empty=True)

    def create_ep_comment_line(self, line_index, pc):
        return self.create_line(line_index, None, None, pc, "%s:%s //This is EntryPoint of virtualized code" %
                         (hex(pc), " " * self.disasm_padding), "", is_empty=True)

    def create_function_name_line(self, line_index, func, pc, is_begin=True):
        if is_begin:
            text = " %s%s %s" % (" " * self.sub_padding, func.name, self.as_directive("proc begin"))
        else:
            text = " %s%s %s" % (" " * self.sub_padding, func.name, self.as_directive("proc end"))

        return self.create_line(line_index, None, func, pc, text, "")

    def create_loc_line(self, line_index, pc, func):
        text = "%s:%s %s: " % (hex(pc), " " * self.auto_comment_padding, self.as_directive("loc_%s" % hex(pc)))
        return self.create_line(line_index, None, func, pc, text, "")

    def create_code_xref_line(self, line_index, pc, xref):
        text = "%s:%s //%s: " % (hex(pc), " " * self.auto_comment_padding,
                                 "CODE XREF FROM: %s" % self.as_directive(hex(xref)))
        return self.create_line(line_index, None, None, pc, text, "")

    def creaete_instruction_line(self, line_index, pc, opcode_data, opcode_id, dins, comment, func, ins):
        text = "%s:%s%s %s%s %s" % (hex(pc), opcode_data, opcode_id, " " * self.disasm_padding,
                             self.as_directive(dins), self.as_loc(comment) if comment else "")
        return self.create_line(line_index, ins, func, pc, text, comment)
    
# IDA Custom view event handlers
    def OnDblClick(self, shift):
        sel = self.GetCurrentWord()

        prepared_sel = self._convert_ida_word_to_addr(sel)
        if not prepared_sel:
            print "[!] Can't convert selected ida word to addr"
            return False

        if self._jump_by_addr(prepared_sel):
            return True
        return False

    def OnPopupMenu(self, menu_id):
        if menu_id == self.pm_jump_by_address:
            return self._handle_pm_jump_by_address()
        elif menu_id == self.pm_rename_function:
            return self._handle_pm_rename_function()
        elif menu_id == self.pm_save_db:
            return self._handle_pm_save_db()
        elif menu_id == self.pm_load_db:
            return self._handle_pm_load_db()
        elif menu_id == self.pm_show_function_graph:
            return self._handle_pm_show_function_graph()
        elif menu_id == self.pm_jump_to_in_new_window:
            return self._handle_pm_jump_to_in_new_window()
        elif menu_id == self.pm_add_comment_to_line:
            return self._handle_pm_add_comment_to_line()
        elif menu_id == self.pm_function_define:
            return self._handle_pm_function_define()

        if self.mode == 32 and menu_id == self.pm_convert_to_x86:
            return self._handle_pm_convert_to_x86()

        if self.mode == 64 and menu_id == self.pm_convert_to_x64:
            return self._handle_pm_convert_to_x64()


# Handlers for PopupMenu

    def _handle_pm_convert_to_x64(self):
        line_index = self.GetLineNo()
        func_obj = self.get_function_by_line_index(line_index)
        if not func_obj:
            print "[!] Can't convert to x86"
            return False

        tx86f = ToNativeForm()
        tx86f.Compile()
        ok = tx86f.Execute()

        fixupFile = None
        if ok:
            recursive_mode = tx86f.rRecirsiveMode.checked
            fixup_file = tx86f.iFileOpen.value if tx86f.iFileOpen.value else None

            tr = Translator(self.vmd)

            tr.to_x64(func_obj, is_recursive_mode=recursive_mode, fixupfile=fixup_file)

            return True

        return False

    def _handle_pm_convert_to_x86(self):
        line_index = self.GetLineNo()
        func_obj = self.get_function_by_line_index(line_index)
        if not func_obj:
            print "[!] Can't convert to x86"
            return False

        tx86f = ToNativeForm()
        tx86f.Compile()
        ok = tx86f.Execute()


        fixupFile = None
        if ok:
            recursive_mode = tx86f.rRecirsiveMode.checked
            fixup_file = tx86f.iFileOpen.value if tx86f.iFileOpen.value else None

            tr = Translator(self.vmd)

            tr.to_x86(func_obj, is_recursive_mode=recursive_mode, fixupfile=fixup_file)

            return True

        return False

    def _handle_pm_function_define(self):
        dff = DefineFunctionForm()
        dff.Compile()
        ok = dff.Execute()
        if ok:
            bea = dff.iBAddr.value
            haddr = dff.iHandlerAddr.value
            if not haddr:
                print "[~] Handler must be set"
                return False
            if not self.vmd.create_function(bea, haddr):
                print "[+] Error creating function"
                return False

            self._fill_view(comments=self.comments)

            return True
        return False

    def _handle_pm_add_comment_to_line(self):
        cf = CommentForm()
        cf.Compile()
        ok = cf.Execute()
        if ok:
            cmt = cf.iCommentText.value
            if not cmt:
                print "[!] Invalid comment text"
                return False

            line_index = self.GetLineNo()
            l = self.lines_by_index[line_index]
            self.comments[l.pc] = "// %s" % cmt
            self._fill_view(comments=self.comments)

    def _handle_pm_load_db(self):
        basename_f = os.path.basename(self.fn)
        fd = None
        try:
            fd = open("%s.fydb.json" % basename_f, 'r')
        except:
            print "[!] DB file not found"
            return False

        data = fd.read()
        db = json.loads(data)

        self.comments = db["comments"]
        for k, v in db["functions_info"].iteritems():
            k = int(k)
            if not self.vmd.functions.get(k, None):
                self.vmd.create_function(k)

            self.vmd.functions[int(k)].name = str(v)

        self._fill_view(comments=self.comments)

    def _handle_pm_save_db(self):
        basename_f = os.path.basename(self.fn)

        db = {}
        db_functions = {}
        for k, v in self.vmd.functions.iteritems():
            db_functions[k] = v.name

        db["functions_info"] = db_functions

        db_comments = {}
        for k, v in self.comments.iteritems():
            db_comments[k] = v

        db["comments"] = db_comments

        dbs = json.dumps(db)
        fd = open("%s.fydb.json" % basename_f, 'w')
        fd.write(dbs)
        fd.close()
        return True

    def _handle_pm_rename_function(self):
        word = self.GetCurrentWord()
        func_obj = self._convert_ida_word_function(word)
        if not func_obj:
            print "[!] Can't rename function"
            return False
        sf = FunctionRenameForm()
        sf.Compile()
        ok = sf.Execute()
        if ok:
            name = sf.iSymbol.value
            if not name:
                print "[!] Can't rename function"
                return False
            self.vmd.functions[func_obj.begin_ea].name = name
            self._fill_view(comments=self.comments)

    def _handle_pm_show_function_graph(self):
        line_index = self.GetLineNo()
        func_obj = self.get_function_by_line_index(line_index)
        if not func_obj:
            print "[!] Can't show function graph"
            return False

        fgv = FunctionGraphView(func_obj, self.vmd.functions, virtual_reg=self.is_virtual_reg)
        fgv.Show()

        return True

    def _handle_pm_jump_to_in_new_window(self):
        sel = self.GetCurrentWord()

        prepared_sel = self._convert_ida_word_to_addr(sel)
        if not prepared_sel:
            print "[!] Can't convert selected ida word to addr"
            return False

        aview = DisassemblerView()
        if not aview.Create(self.fn, self.ep_id, self.decrypt_key, self.interpreter_base, additional_window_name=random.randint(0, 0xFFFFFFFF),
                            vmd=self.vmd, j_addr=prepared_sel, mode=self.mode, show_id=self.show_id, lines=self.lines,
                            lines_by_index=self.lines_by_index, show_opcode=self.show_opcode,
                            is_virtual_reg=self.is_virtual_reg, ep=self.ep):
            print "[~] Error open additional window"
            return False

        aview.Show()
        return True

    def _handle_pm_jump_by_address(self):
        sf = JumpByForm()
        sf.Compile()
        ok = sf.Execute()
        if ok:
            addr = sf.iJumpByAddr.value
            if not addr:
                print "[~] Can't jump"
                return False
            self._jump_by_addr(addr)

