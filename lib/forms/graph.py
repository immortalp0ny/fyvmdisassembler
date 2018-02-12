import ida_graph
import idaapi


class FunctionGraphView(ida_graph.GraphViewer):
    def __init__(self, function_instance, functions, virtual_reg=True):
        self.title = "DiGraph of function %s" % function_instance.name
        self.funcname = function_instance.name
        self.function_instance = function_instance
        ida_graph.GraphViewer.__init__(self, self.title)
        self.ida_nodes = {}
        self.functions = functions
        self.virtual_reg = virtual_reg

    def as_directive(self, s):
        return idaapi.COLSTR(s, idaapi.SCOLOR_KEYWORD)

    def as_loc(self, s):
        return idaapi.COLSTR(s, idaapi.SCOLOR_LOCNAME)

    def OnRefresh(self):
        self.Clear()
        print "[+] Append nodes"
        print "[+] Nodes count %s" % len(self.function_instance.graph.nodes)
        if not self.function_instance.graph:
            print "[~] Function doesn't contain graph"
            return False

        for addr, node in self.function_instance.graph.nodes.iteritems():
            self.ida_nodes[addr] = self.AddNode(node)

        print "[+] Append edges"
        for addr, node_id in self.ida_nodes.iteritems():
            instruction = self.function_instance.graph.nodes[addr]
            for s in instruction.successors:
                # print s
                self.AddEdge(node_id, self.ida_nodes[s])

        print "[+] Graph created !"
        return True

    def OnGetText(self, node_id):
        node = self[node_id]
        bb_text = self.as_loc("loc_%s\r\n" % hex(node.begin_ea).replace("0x", "").replace("L", ""))
        for addr, ins in node.ins_list:
            if ins.is_virtual_call:
                ins.operand1.operand_value_alias = self.functions[ins.operand1.value].name
                dtext = ins.get_disassm(virtual_reg=self.virtual_reg, to_alias=True)
            else:
                dtext = ins.get_disassm(virtual_reg=self.virtual_reg)
            bb_text += "  %s\r\n" % self.as_directive(dtext)
        return bb_text


