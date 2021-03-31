export bpf_insn, bpf_program

struct bpf_insn
    code::Cushort
    jt::Cuchar
    jf::Cuchar
    k::Clong
end

struct bpf_program
    bf_len::Cuint
    bf_insns::Ptr{bpf_insn}
end
