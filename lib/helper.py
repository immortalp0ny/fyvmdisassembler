from struct import pack, unpack

rol = lambda val, r_bits, max_bits: \
    (val << r_bits % max_bits) & (2 ** max_bits - 1) | \
    ((val & (2 ** max_bits - 1)) >> (max_bits - (r_bits % max_bits)))

# Rotate right: 0b1001 --> 0b1100
ror = lambda val, r_bits, max_bits: \
    ((val & (2 ** max_bits - 1)) >> r_bits % max_bits) | \
    (val << (max_bits - (r_bits % max_bits)) & (2 ** max_bits - 1))


def u_li32(val):
    return unpack("<I", val)[0]


def p_li32(val):
    return pack("<I", val)

conditional_branching = ["jz", "je", "jnz", "jne", "js", "jns", "jo", "jno", "jpe", "jp", "jpo", "jnp", "jb",
                             "jnae",
                             "jc", "jb", "jnae", "jc", "jnb", "jae", "jnc", "jbe", "jna", "jnbe", "ja", "jl",
                             "jnge",
                             "jnl", "jge", "jle", "jng", "jnle", "jg"]
unconditional_branching = ["jmp"]

branching = conditional_branching + unconditional_branching


def data_hexlify(s):
    return " ".join("{:02x}".format(ord(c)) for c in s)
