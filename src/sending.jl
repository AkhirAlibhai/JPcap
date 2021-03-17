include("types/pktHdrs.jl")

export pcap_create, pcap_activate,
        pcap_close,
        pcap_geterr, pcap_perror,
        pcap_open_live, pcap_open_dead,
        pcap_next

mutable struct pcap_t
end

"""
    Creates a live capture handle for the given interface
"""
function pcap_create(source::String)::Ptr{pcap_t}
    err = Vector{UInt8}(undef, PCAP_ERRBUF_SIZE)

    handle = ccall((:pcap_create, "libpcap"), Ptr{pcap_t}, (Cstring, Ptr{UInt8}), source, err)

    loaded_handle = unsafe_load(handle)
    if loaded_handle == C_NULL
        println("Error occured when attempting to create live capture handle: ",
                unsafe_string(pointer(err)))
        return nothing
    end
    handle
end

#=
    Error codes for the pcap API
=#
const PCAP_ERROR_ACTIVATED =        -4  # the operation can't be performed on already activated captures
const PCAP_ERROR_NO_SUCH_DEVICE =   -5	# no such device exists
const PCAP_ERROR_RFMON_NOTSUP =     -6	# this device doesn't support rfmon (monitor) mode
const PCAP_ERROR_PERM_DENIED =      -8	# no permission to open the device
const PCAP_ERROR_IFACE_NOT_UP =     -9  # interface isn't up

#=
    Warning codes for the pcap API
=#
const PCAP_WARNING_PROMISC_NOTSUP = 2	# this device doesn't support promiscuous mode

"""
    Activates a capture handle
"""
function pcap_activate(p::Ptr{pcap_t})::Int32
    ccall((:pcap_activate, "libpcap"), Int32, (Ptr{pcap_t},), p)
end

"""
    Closes the capture device
"""
function pcap_close(p::Ptr{pcap_t})::Nothing
    ccall((:pcap_close, "libpcap"), Cvoid, (Ptr{pcap_t},), p)
end

"""
    Gets the error message for the given Ptr{pcap_t}
"""
function pcap_geterr(p::Ptr{pcap_t})::String
    unsafe_string(ccall((:pcap_geterr, "libpcap"), Ptr{Int8}, (Ptr{pcap_t},), p))
end

function pcap_perror(p::Ptr{pcap_t})::Nothing
    # Prints the error message for the given Ptr{pcap_t}
    println(pcap_geterr(p))
end

"""
    Opens a device for capturing
"""
function pcap_open_live(device::String, snaplen::Int64, promisc::Int64, to_ms::Int64)::Union{Ptr{pcap_t}, Nothing}
    err = Vector{UInt8}(undef, PCAP_ERRBUF_SIZE)

    handle = ccall((:pcap_open_live, "libpcap"), Ptr{pcap_t}, (Cstring, Int32, Int32, Int32,
                                        Ptr{UInt8}), device, snaplen, promisc, to_ms, err)

    if handle == C_NULL
        println("Error occured when attempting to create live capture handle: ",
                unsafe_string(pointer(err)))
        return nothing
    end
    handle
end

#=
    Link-layer header type codes
    TODO: Move this into another file when it makes sense to
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
    Opens a fake pcap_t for compiling filters or opening a capture for output
"""
function pcap_open_dead(linktype::Union{Pcap_linktype, Int64}, snaplen::Int64)::Union{Ptr{pcap_t}, Nothing}
    ccall((:pcap_open_dead, "libpcap"), Ptr{pcap_t}, (Int32, Int32),
                                                        linktype, snaplen)
end

"""
    Reads the next packet from a pcap_t
"""
function pcap_next(p::Ptr{pcap_t}, h::Ref{pcap_pkthdr})
    val = ccall((:pcap_next, "libpcap"), Ptr{Cuchar}, (Ptr{pcap_t}, Ref{pcap_pkthdr}), p, h)

    if val == C_NULL
        println("An error occured, or no packets were read from the live capture device")
    end
end
