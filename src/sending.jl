include("types/pktHdrs.jl")
include("errors.jl")

export pcap_create, pcap_activate,
        pcap_close,
        pcap_geterr, pcap_perror,
        pcap_open_live, pcap_open_dead,
        pcap_next, pcap_next_ex,
        pcap_handler,
        pcap_loop, pcap_dispatch,
        pcap_breakloop,
        pcap_setnonblock, pcap_getnonblock

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
        throw(PcapCreateHandleError(unsafe_string(pointer(err))))
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

"""
    Prints the error message for the given Ptr{pcap_t}
"""
function pcap_perror(p::Ptr{pcap_t})::Nothing
    println(pcap_geterr(p))
end

"""
    Opens a device for capturing
"""
function pcap_open_live(device::String, snaplen::Int64, promisc::Int64, to_ms::Int64)::Ptr{pcap_t}
    err = Vector{UInt8}(undef, PCAP_ERRBUF_SIZE)

    handle = ccall((:pcap_open_live, "libpcap"), Ptr{pcap_t}, (Cstring, Int32, Int32, Int32,
                                        Ptr{UInt8}), device, snaplen, promisc, to_ms, err)

    if handle == C_NULL
        throw(PcapCreateHandleError(unsafe_string(pointer(err))))
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
function pcap_open_dead(linktype::Union{Pcap_linktype, Int64}, snaplen::Int64)::Ptr{pcap_t}
    ccall((:pcap_open_dead, "libpcap"), Ptr{pcap_t}, (Int32, Int32),
                                                        linktype, snaplen)
end

"""
    Reads the next packet from a pcap_t
"""
function pcap_next(p::Ptr{pcap_t}, h::Ref{pcap_pkthdr})::Ptr{UInt8}
    val = ccall((:pcap_next, "libpcap"), Ptr{Cuchar}, (Ptr{pcap_t}, Ref{pcap_pkthdr}), p, h)

    if val == C_NULL
        throw(PcapPacketCaptureTimeoutError())
    end
    val
end

"""
    Reads the next packet from a pcap_t
"""
function pcap_next_ex(p::Ptr{pcap_t}, pkt_header::Ref{pcap_pkthdr}, pkt_data::Ref{UInt8})::Int32
    ccall((:pcap_next_ex, "libpcap"), Int32, (Ptr{pcap_t}, Ref{pcap_pkthdr},
                                                Ref{UInt8}), p, pkt_header, pkt_data)
end

# callback type for pcap_loop
abstract type pcap_handler_def{T1, T2, T3, S}
end

const pcap_handler = pcap_handler_def{UInt8, Ptr{pcap_pkthdr}, Ptr{UInt8}, Cvoid}

"""
    Process packets from a live capture or savefile
"""
function pcap_loop(p::Ptr{pcap_t}, cnt::Int64, callback::Type{<:pcap_handler}, user::UInt8)::Int32
    callback_c =  @cfunction($callback, Cvoid, (UInt8, Ptr{pcap_pkthdr}, Ptr{UInt8}))
    pcap_loop(p, cnt, callback_c, user)
end

"""
    Process packets from a live capture or savefile
"""
function pcap_loop(p::Ptr{pcap_t}, cnt::Int64, callback::Function, user::UInt8)::Int32
    if ~hasmethod(callback, Tuple{UInt8, Ptr{pcap_pkthdr}, Ptr{UInt8}})
        throw(PcapCallbackInvalidParametersError())
    end

    callback_c =  @cfunction($callback, Cvoid, (UInt8, Ptr{pcap_pkthdr}, Ptr{UInt8}))
    pcap_loop(p, cnt, callback_c, user)
end

"""
    Process packets from a live capture or savefile
"""
function pcap_loop(p::Ptr{pcap_t}, cnt::Int64, callback::Union{Ptr{Cvoid}, Base.CFunction}, user::UInt8)::Int32
    ccall((:pcap_loop, "libpcap"), Int32, (Ptr{pcap_t}, Int32, Ptr{Cvoid}, Cuchar), 
                                                p, cnt, callback, user)
end

"""
    Process packets from a live capture or savefile
"""
function pcap_dispatch(p::Ptr{pcap_t}, cnt::Int64, callback::Type{<:pcap_handler}, user::UInt8)::Int32
    callback_c =  @cfunction($callback, Cvoid, (UInt8, Ptr{pcap_pkthdr}, Ptr{UInt8}))
    pcap_dispatch(p, cnt, callback_c, user)
end

"""
    Process packets from a live capture or savefile
"""
function pcap_dispatch(p::Ptr{pcap_t}, cnt::Int64, callback::Function, user::UInt8)::Int32
    if ~hasmethod(callback, Tuple{UInt8, Ptr{pcap_pkthdr}, Ptr{UInt8}})
        throw(PcapCallbackInvalidParametersError())
    end

    callback_c =  @cfunction($callback, Cvoid, (UInt8, Ptr{pcap_pkthdr}, Ptr{UInt8}))
    pcap_dispatch(p, cnt, callback_c, user)
end

"""
    Process packets from a live capture or savefile
"""
function pcap_dispatch(p::Ptr{pcap_t}, cnt::Int64, callback::Union{Ptr{Cvoid}, Base.CFunction}, user::UInt8)::Int32
    ccall((:pcap_dispatch, "libpcap"), Int32, (Ptr{pcap_t}, Int32, Ptr{Cvoid}, Cuchar),
                                                p, cnt, callback, user)
end

"""
    Force a pcap_dispatch() or pcap_loop() call to return
"""
function pcap_breakloop(p::Ptr{pcap_t})::Nothing
    ccall((:pcap_breakloop, "libpcap"), Cvoid, (Ptr{pcap_t},), p)
end

"""
    Set the state of non-blocking mode on a capture device
"""
function pcap_setnonblock(p::Ptr{pcap_t}, nonblock::Int64)
    err = Vector{UInt8}(undef, PCAP_ERRBUF_SIZE)

    val = ccall((:pcap_setnonblock, "libpcap"), Int32,
                (Ptr{pcap_t}, Cint, Ptr{UInt8}), p, nonblock, err)

    if val == -1
       throw(PcapSetNonBlockError(err))
    end
    val
end

"""
    Get the state of non-blocking mode on a capture device
"""
function pcap_getnonblock(p::Ptr{pcap_t})
    err = Vector{UInt8}(undef, PCAP_ERRBUF_SIZE)

    val = ccall((:pcap_getnonblock, "libpcap"), Int32,
                (Ptr{pcap_t}, Ptr{UInt8}), p, err)

    if val == -1
       throw(PcapGetNonBlockError(err))
    end
    val
end
