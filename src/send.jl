include("types/pcapHdr.jl")
include("types/pcapT.jl")
include("errors.jl")

export pcap_inject, pcap_sendpacket

"""
    Transmit a packet
"""
function pcap_inject(p::Ptr{Pcap_t}, buf::Ptr{Cvoid}, size::UInt)::Int32
    ccall((:pcap_inject, "libpcap"), Int32, (Ptr{Pcap_t}, Ref{Cvoid}, Csize_t),
                                                p, buf, size)
end

"""
    Transmit a packet
"""
function pcap_sendpacket(p::Ptr{Pcap_t}, buf::Ptr{UInt8}, size::Int64)::Int32
    ccall((:pcap_sendpacket, "libpcap"), Int32, (Ptr{Pcap_t}, Ptr{Cvoid}, Int32),
                                                p, buf, size)
end
