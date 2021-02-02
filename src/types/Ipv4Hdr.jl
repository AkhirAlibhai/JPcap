export Ipv4Hdr

struct Ipv4Hdr
    version::UInt8
    ihl::UInt8
    dscp::UInt8
    ecn::UInt8
    totalLength::UInt16
    identification::UInt16
    flags::UInt8
    fragmentOffset::UInt16
    timeToLive::UInt8
    protocol::UInt8
    headerChecksum::UInt16
    sourceIp::AbstractString # IPv4
    destinationIp::AbstractString # IPv4
    options::AbstractString # Perform more research on this value
end
