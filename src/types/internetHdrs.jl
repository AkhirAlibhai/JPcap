export Ipv4Hdr

struct Ipv4Hdr
    version::UInt8
    ihl::UInt8
    dscp::UInt8
    ecn::UInt8
    total_length::UInt16
    identification::UInt16
    flags::UInt8
    fragment_offset::UInt16
    time_to_live::UInt8
    protocol::UInt8
    header_checksum::UInt16
    source_ip::AbstractString # IPv4
    destination_ip::AbstractString # IPv4
    options::AbstractString # Perform more research on this value
end
