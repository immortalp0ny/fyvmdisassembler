import idaapi

idaapi.require("lib.disassembler")

from lib.disassembler import FinspyDisassembler


fd = open("Q:\\Tasks\\samples\\FinFisher\\x32Driver\\payload_decompressed_trace.bin", 'rb')
pcode_data = fd.read()
fd.close()

d = FinspyDisassembler(pcode_data, len(pcode_data), 0x873D0D44, 0x104B0)
d.start()

#d.create_function(0xb298, 0x0001A52a)
#d.to_x86(d.functions[0xb298], is_recursive_mode=True)

d.create_function(0xc2e8, 0x0001A676)
d.to_x86(d.functions[0xc2e8], is_recursive_mode=True)