
class DisassemblerViewLine:
    def __init__(self, line_index, instruction, function, pc, text, comment, is_empty=False):
        self.line_index = line_index
        self.instruction = instruction
        self.function = function
        self.pc = pc
        self.text = text
        self.comment = comment
        self.is_empty = is_empty
