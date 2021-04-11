include("types/pcapHdr.jl")
include("types/pcapT.jl")

export pcap_next, pcap_next_ex,
        pcap_handler,
        pcap_loop, pcap_dispatch,
        pcap_breakloop,
        pcap_setnonblock, pcap_getnonblock,
        pcap_compile, pcap_setfilter,
        pcap_freecode, pcap_setdirection,
        Pcap_dumper_t,
        pcap_dump_open, pcap_dump_close

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

# callback type for pcap_loop
abstract type pcap_handler_def{T1, T2, T3, S}
end

const pcap_handler = pcap_handler_def{UInt8, Ptr{pcap_pkthdr}, Ptr{UInt8}, Cvoid}

"""
    Process packets from a live capture or savefile
"""
function pcap_loop(p::Ptr{Pcap_t}, cnt::Int64, callback::Type{<:pcap_handler}, user::Union{UInt8, Ptr{Nothing}})::Int32
    callback_c =  @cfunction($callback, Cvoid, (UInt8, Ptr{pcap_pkthdr}, Ptr{UInt8}))
    pcap_loop(p, cnt, callback_c, user)
end

"""
    Process packets from a live capture or savefile
"""
function pcap_loop(p::Ptr{Pcap_t}, cnt::Int64, callback::Function, user::Union{UInt8, Ptr{Nothing}})::Int32
    if !hasmethod(callback, Tuple{UInt8, Ptr{pcap_pkthdr}, Ptr{UInt8}})
        throw(PcapCallbackInvalidParametersError())
    end
    pcap_loop(p,
                cnt,
                @cfunction($callback, Cvoid, (UInt8, Ptr{pcap_pkthdr}, Ptr{UInt8})),
                user)
end

"""
    Process packets from a live capture or savefile
"""
function pcap_loop(p::Ptr{Pcap_t}, cnt::Int64, callback::Union{Ptr{Cvoid}, Base.CFunction}, user::Union{UInt8, Ptr{Nothing}})::Int32
    ccall((:pcap_loop, "libpcap"), Int32, (Ptr{Pcap_t}, Int32, Ptr{Cvoid}, Cuchar), 
                                                p, cnt, callback, user)
end

"""
    Process packets from a live capture or savefile
"""
function pcap_dispatch(p::Ptr{Pcap_t}, cnt::Int64, callback::Type{<:pcap_handler}, user::Union{UInt8, Ptr{Nothing}})::Int32
    callback_c =  @cfunction($callback, Cvoid, (UInt8, Ptr{pcap_pkthdr}, Ptr{UInt8}))
    pcap_dispatch(p, cnt, callback_c, user)
end

"""
    Process packets from a live capture or savefile
"""
function pcap_dispatch(p::Ptr{Pcap_t}, cnt::Int64, callback::Function, user::Union{UInt8, Ptr{Nothing}})::Int32
    if !hasmethod(callback, Tuple{UInt8, Ptr{pcap_pkthdr}, Ptr{UInt8}})
        throw(PcapCallbackInvalidParametersError())
    end
    pcap_dispatch(p,
                    cnt,
                    @cfunction($callback, Cvoid, (UInt8, Ptr{pcap_pkthdr}, Ptr{UInt8})),
                    user)
end

"""
    Process packets from a live capture or savefile
"""
function pcap_dispatch(p::Ptr{Pcap_t}, cnt::Int64, callback::Union{Ptr{Cvoid}, Base.CFunction}, user::Union{UInt8, Ptr{Nothing}})::Int32
    ccall((:pcap_dispatch, "libpcap"), Int32, (Ptr{Pcap_t}, Int32, Ptr{Cvoid}, Cuchar),
                                                p, cnt, callback, user)
end

"""
    Force a pcap_dispatch() or pcap_loop() call to return
"""
function pcap_breakloop(p::Ptr{Pcap_t})::Nothing
    ccall((:pcap_breakloop, "libpcap"), Cvoid, (Ptr{Pcap_t},), p)
end

"""
    Set the state of non-blocking mode on a capture device
"""
function pcap_setnonblock(p::Ptr{Pcap_t}, nonblock::Int64)::Int32
    err = Vector{UInt8}(undef, PCAP_ERRBUF_SIZE)

    val = ccall((:pcap_setnonblock, "libpcap"), Int32,
                (Ptr{Pcap_t}, Cint, Ptr{UInt8}), p, nonblock, err)

    if val == -1
       throw(PcapSetNonBlockError(err))
    end
    val
end

"""
    Get the state of non-blocking mode on a capture device
"""
function pcap_getnonblock(p::Ptr{Pcap_t})::Int32
    err = Vector{UInt8}(undef, PCAP_ERRBUF_SIZE)

    val = ccall((:pcap_getnonblock, "libpcap"), Int32,
                (Ptr{Pcap_t}, Ptr{UInt8}), p, err)

    if val == -1
       throw(PcapGetNonBlockError(err))
    end
    val
end

"""
    Compile a filter expression
"""
function pcap_compile(p::Ptr{Pcap_t}, fp::Ref{bpf_program}, str::String, optimize::Int64, netmask::UInt32)::Int32
    ccall((:pcap_compile, "libpcap"), Int32, (Ptr{Pcap_t}, Ref{bpf_program},
                                                Cstring, Int32, Cuint),
                                                p, fp, str, optimize, netmask)
end

"""
    Set the filter
"""
function pcap_setfilter(p::Ptr{Pcap_t}, fp::Ref{bpf_program})::Int32
    ccall((:pcap_setfilter, "libpcap"), Int32, (Ptr{Pcap_t}, Ref{bpf_program}), p, fp)
end

"""
    Free a BPF program
"""
function pcap_freecode(fp::Ref{bpf_program})::Cvoid
    ccall((:pcap_freecode, "libpcap"), Cvoid, (Ref{bpf_program},), fp)
end

#=
    Direction that packets will be captured from
=#
export PCAP_D_INOUT, PCAP_D_IN, PCAP_D_OUT
@enum Pcap_direction_t begin
    PCAP_D_INOUT =  0   # Capture packets received or sent by the device
    PCAP_D_IN =     1   # Capture packets received by the device
    PCAP_D_OUT =    2   # Capture packets sent by the device
end

"""
    Set the direction for which packets will be captured
"""
function pcap_setdirection(p::Ptr{Pcap_t}, d::Union{Pcap_direction_t, Int64})::Int32
    ccall((:pcap_setdirection, "libpcap"), Int32, (Ptr{Pcap_t}, Int32), p, d)
end

mutable struct Pcap_dumper_t
end

function pcap_dump_open(p::Ptr{Pcap_t}, fname::String)::Ptr{Pcap_dumper_t}
    ccall((:pcap_dump_open, "libpcap"), Ptr{Pcap_dumper_t}, (Ptr{Pcap_t}, Cstring), p, fname)
end

function pcap_dump_close(p::Ptr{Pcap_dumper_t})::Cvoid
    ccall((:pcap_dump_close, "libpcap"), Cvoid, (Ptr{Pcap_dumper_t}, ), p)
end
