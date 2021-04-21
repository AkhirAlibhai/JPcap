include("./ethernetHdr.jl")

export Ipv4Hdr

struct Ipv4Hdr
    version_ihl::UInt8              # Version = 0-3, IHL = 4-7
    dscp_ecn::UInt8                 # DSCP = 0-5, ECN = 6-7
    length::UInt16
    identification::UInt16
    flags_fragment_offset::UInt16   # Flags = 0-2, Fragment Offset - 3-15
    time_to_live::UInt8
    protocol::UInt8
    header_checksum::UInt16
    src_ip::UInt32                  # IPv4
    dest_ip::UInt32                 # IPv4
    options::AbstractString         # TODO: Think of better way to represent
    function Ipv4Hdr(packet::Ptr{UInt8})::Ipv4Hdr
        unsafe_load(Ptr{Ipv4Hdr}(packet + sizeof(EtherHdr)))
    end
end
