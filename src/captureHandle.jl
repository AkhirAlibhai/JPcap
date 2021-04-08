include("types/pcapT.jl")
include("errors.jl")

export pcap_create,
        pcap_activate, pcap_close,
        pcap_open_live, pcap_open_dead

"""
    Create a live capture handle for the given interface
"""
function pcap_create(source::String)::Ptr{Pcap_t}
    err = Vector{UInt8}(undef, PCAP_ERRBUF_SIZE)

    handle = ccall((:pcap_create, "libpcap"), Ptr{Pcap_t}, (Cstring, Ptr{UInt8}), source, err)

    loaded_handle = unsafe_load(handle)
    if loaded_handle == C_NULL
        throw(PcapCreateHandleError(unsafe_string(pointer(err))))
    end
    handle
end

"""
    Activate a capture handle
"""
function pcap_activate(p::Ptr{Pcap_t})::Int32
    ccall((:pcap_activate, "libpcap"), Int32, (Ptr{Pcap_t},), p)
end

"""
    Close the capture device
"""
function pcap_close(p::Ptr{Pcap_t})::Nothing
    ccall((:pcap_close, "libpcap"), Cvoid, (Ptr{Pcap_t},), p)
end

"""
    Open a device for capturing
"""
function pcap_open_live(device::String, snaplen::Int64, promisc::Int64, to_ms::Int64)::Ptr{Pcap_t}
    err = Vector{UInt8}(undef, PCAP_ERRBUF_SIZE)

    handle = ccall((:pcap_open_live, "libpcap"), Ptr{Pcap_t}, (Cstring, Int32, Int32, Int32,
                                        Ptr{UInt8}), device, snaplen, promisc, to_ms, err)

    if handle == C_NULL
        throw(PcapCreateHandleError(unsafe_string(pointer(err))))
    end
    handle
end

#=
    Link-layer header type codes
=#
export DLT_NULL, DLT_EN10MB, DLT_EN3MB, DLT_AX25,
        DLT_PRONET, DLT_CHAOS, DLT_IEEE802, DLT_ARCNET,
        DLT_SLIP, DLT_PPP, DLT_FDDI
@enum Pcap_linktype begin
    DLT_NULL =      0   # BSD loopback encapsulation
    DLT_EN10MB =    1   # Ethernet (10Mb)
    DLT_EN3MB =     2   # Experimental Ethernet (3Mb)
    DLT_AX25 =      3   # Amateur Radio AX.25
    DLT_PRONET =    4   # Proteon ProNET Token Ring
    DLT_CHAOS =     5   # Chaos
    DLT_IEEE802 =   6   # 802.5 Token Ring
    DLT_ARCNET =    7   # ARCNET, with BSD-style header
    DLT_SLIP =      8   # Serial Line IP
    DLT_PPP =       9   # Point-to-point Protocol
    DLT_FDDI =      10  # FDDI
end

"""
    Open a fake Pcap_t for compiling filters or opening a capture for output
"""
function pcap_open_dead(linktype::Union{Pcap_linktype, Int64}, snaplen::Int64)::Ptr{Pcap_t}
    ccall((:pcap_open_dead, "libpcap"), Ptr{Pcap_t}, (Int32, Int32),
                                                        linktype, snaplen)
end
