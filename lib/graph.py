import random
import re


class DiGraphNode:
    def __init__(self, successors, predcessors, ins_list, bea, eea):
        self.begin_ea = bea
        self.end_ea = eea
        self.successors = successors
        self.predcessors = predcessors
        self.ins_list = ins_list


class DiGraph:
    def __init__(self, start_vea, i_size):
        self.__start_ea = start_vea
        self.__end_vea = None
        self.__graph = {}
        self.__i_size = i_size
        self.is_bad_cfg = False

    def parse(self, trace):
        """
            Create graph from instruction list. Instruction list must describe one function
            :param trace: Function instructions

        """
        self._dfs(self.__start_ea, trace)

    def check_in_node(self, addr):
        """
            Check if addr contains in some graph node
            :param addr: Tested address
            :return: Address of begin node or None if node can't be found
        """
        for ea, node in self.__graph.iteritems():
            for iea, ins in node.ins_list:
                if iea == addr:
                    return ea
        return None

    def set_spliting(self, addr, node_ea):
        """
            Split node by address
            :param addr: Address for spliting. Must be in node/
            :param node_ea: Address of begin node

        """
        node = self.__graph[node_ea]

        node_b_ea = node.begin_ea
        block_up_ins = []
        block_down_ins = []
        block_up_end_ea = 0
        for iea, ins in node.ins_list:
            if iea < addr:
                block_up_ins.append((iea, ins))
                block_up_end_ea = iea
            else:
                block_down_ins.append((iea, ins))

        dgn_up = DiGraphNode([addr],
                             node.predcessors, block_up_ins, node.begin_ea, block_up_end_ea)
        dgn_down = DiGraphNode(node.successors,
                               [addr], block_down_ins, addr, node.end_ea)
        del self.__graph[node_ea]

        self.__graph[node_b_ea] = dgn_up
        self.__graph[addr] = dgn_down

    def _dfs(self, ea, trace, predcessors=None):
        """
            Deep first search for function
            :param ea: Address of begin function
            :param trace: Function instructions
            :param predcessors: Recursive argument describe predcessors nodes of parent node

        """
        bea = ea
        instruction_list = []

        if self.is_bad_cfg:
            return

        # Have you already been here?
        if any(x for _, x in self.__graph.iteritems() if x.begin_ea == bea):
            for p in predcessors:
                self.__graph[bea].predcessors.append(p)
            return

        while True:
            ins = trace.get(ea, None)
            if ins is None:
                self.is_bad_cfg = True
                print "[!] Warning at '%s' trace not contain this key. " % hex(ea)
                return

            # Are we begin rewrite already exists block ?
            if self.__graph.get(ea, None):
                dgn = DiGraphNode([ea], [] if predcessors is None else predcessors,
                                  instruction_list, bea, ea - self.__i_size)
                self.__graph[bea] = dgn
                return

            instruction_list.append((ea, ins))
            # print self.__graph
            dgn = None
            if ins.is_branch and ins.branch_target:
                vm_offset = ins.branch_target

                # Different process for conditional and unconditional branching
                if ins.mnemonic != "jmp":
                    dgn = DiGraphNode([vm_offset, ea + self.__i_size], [] if predcessors is None else predcessors,
                                      instruction_list, bea, ea)
                    self.__graph[bea] = dgn
                    if not self.__graph.get(vm_offset, None):
                        inner_node_ea = self.check_in_node(vm_offset)
                        if inner_node_ea:
                            # Branch to existed node not in her begin
                            self.set_spliting(vm_offset, inner_node_ea)
                        else:
                            # New node
                            self._dfs(vm_offset, trace, predcessors=[bea])

                    if not self.__graph.get(ea + self.__i_size, None):
                        inner_node_ea = self.check_in_node(ea + self.__i_size)
                        if inner_node_ea:
                            # Branch to existed node not in her begin
                            self.set_spliting(ea + self.__i_size, inner_node_ea)
                        else:
                            # New node
                            self._dfs(ea + self.__i_size, trace, predcessors=[bea])

                else:
                    dgn = DiGraphNode([ins.branch_target],
                                      [] if predcessors is None else predcessors,
                                      instruction_list, bea, ea)
                    self.__graph[bea] = dgn

                    if not self.__graph.get(vm_offset, None):
                        inner_node_ea = self.check_in_node(vm_offset)
                        if inner_node_ea:
                            self.set_spliting(vm_offset, inner_node_ea)
                        else:
                            self._dfs(vm_offset, trace, predcessors=[bea])
                        # self._dfs(vm_offset, trace, predcessors=[bea])

                return

            # All functions end by RET
            if "ret" in ins.get_disassm():
                dgn = DiGraphNode([], predcessors, instruction_list, bea, ea)
                self.__graph[bea] = dgn
                self.__end_vea = ea
                return

            ea += self.__i_size

    @property
    def nodes(self):
        return self.__graph

    def get_low_address(self):
        return self.__end_vea

    def get_high_address(self):
        return self.__start_ea
