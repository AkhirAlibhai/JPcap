include("types/pcapHdr.jl")
include("types/pcapT.jl")

export pcap_next, pcap_next_ex

"""
    Read the next packet from a Pcap_t
"""
function pcap_next(p::Ptr{Pcap_t}, h::Ref{pcap_pkthdr})::Ptr{UInt8}
    val = ccall((:pcap_next, "libpcap"), Ptr{Cuchar}, (Ptr{Pcap_t}, Ref{pcap_pkthdr}), p, h)

    if val == C_NULL
        throw(PcapPacketCaptureTimeoutError())
    end
    val
end

"""
    Read the next packet from a Pcap_t
"""
function pcap_next_ex(p::Ptr{Pcap_t}, pkt_header::Ref{pcap_pkthdr}, pkt_data::Ref{UInt8})::Int32
    ccall((:pcap_next_ex, "libpcap"), Int32, (Ptr{Pcap_t}, Ref{pcap_pkthdr},
                                                Ref{UInt8}), p, pkt_header, pkt_data)
end
