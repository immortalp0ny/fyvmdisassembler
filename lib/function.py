class Function:
    def __init__(self, begin_ea, end_ea, graph, name, machine_handler):
        self.name = name
        self.begin_ea = begin_ea
        self.end_ea = end_ea
        self.graph = graph
        self.machine_handler = machine_handler