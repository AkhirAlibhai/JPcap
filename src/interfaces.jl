include("constants.jl")
include("errors.jl")

export pcap_lookupdev,
        sockaddr, pcap_addr, pcap_if_t,
        pcap_findalldevs, pcap_freealldevs,
        j_pcap_if_t, j_pcap_addr, j_sockaddr

"""
    Return the name of the default device, if it exists
"""
function pcap_lookupdev()::String
    err = Vector{UInt8}(undef, PCAP_ERRBUF_SIZE)

    dev = ccall((:pcap_lookupdev, "libpcap"), Ptr{Int8}, (Ptr{UInt8},), err)

    if dev == C_NULL
        throw(PcapDeviceError(unsafe_string(pointer(err))))
    end
    unsafe_string(dev)
end

struct sockaddr
    sa_family::Cushort
    sa_data::Ptr{UInt8} # TODO: Do not access, needs to be cast into the right kind of sockaddr
    sockaddr() = new(0, Base.unsafe_convert(Cstring, ""))
end

struct j_sockaddr
    sa_familiy::UInt16 # TODO: Map the sockaddrs to their type here
    sa_data::Nothing # See TODO in sockaddr
    function j_sockaddr(sockaddr::Ptr{sockaddr})
        if (sockaddr == C_NULL)
            return nothing
        end
        new(unsafe_load(sockaddr).sa_family,
            nothing)
    end
end

"""
    Julia struct of pcap_addr
    Reference to what it copies can be found here:
    https://github.com/the-tcpdump-group/libpcap/blob/master/pcap/pcap.h
"""
struct pcap_addr
    next::Ptr{pcap_addr}
    addr::Ptr{sockaddr}
    netmask::Ptr{sockaddr}
    broadaddr::Ptr{sockaddr}
    dstaddr::Ptr{sockaddr}
    pcap_addr() = new(Ptr{pcap_addr}(),
                        Ptr{sockaddr}(),
                        Ptr{sockaddr}(),
                        Ptr{sockaddr}(),
                        Ptr{sockaddr}())
end

"""
    Julia version of pcap_addr
    Load the values from a Ptr{pcap_addr} to make it easier for a user to work with
    Stores a reference to the original pointer, which can be used in pcap functions
"""
struct j_pcap_addr
    addr::Union{j_sockaddr, Nothing}
    netmask::Union{j_sockaddr, Nothing}
    broadaddr::Union{j_sockaddr, Nothing}
    dstaddr::Union{j_sockaddr, Nothing}
    ptr::Ptr{pcap_addr}
    function j_pcap_addr(pcap_addr::Ptr{pcap_addr})
        loaded_pcap_addr = unsafe_load(pcap_addr)

        new(j_sockaddr(loaded_pcap_addr.addr),
            j_sockaddr(loaded_pcap_addr.netmask),
            j_sockaddr(loaded_pcap_addr.broadaddr),
            j_sockaddr(loaded_pcap_addr.dstaddr),
            pcap_addr
            )
    end
end

"""
    Julia struct of pcap_if_t
    Reference to what it copies can be found here:
    https://github.com/the-tcpdump-group/libpcap/blob/master/pcap/pcap.h
"""
struct pcap_if_t
    next::Ptr{pcap_if_t}
    name::Cstring
    description::Cstring
    addresses::Ptr{pcap_addr}
    flags::Cuint
    pcap_if_t() = new(Ptr{pcap_if_t}(),
                        "",
                        "",
                        Ptr{pcap_addr}(),
                        0)
end

"""
    Julia version of pcap_if_t
    Load the values from a Ptr{pcap_if_t} to make it easier for a user to work with
    Stores a reference to the original pointer, which can be used in pcap functions
"""
struct j_pcap_if_t
    name::String
    description::String
    addresses::Array{j_pcap_addr}
    flags::UInt32
    ptr::Ptr{pcap_if_t}
    function j_pcap_if_t(pcap_if_t::Ptr{pcap_if_t})
        loaded_pcap_if_t = unsafe_load(pcap_if_t)

        addresses = j_pcap_addr[]
        head = loaded_pcap_if_t.addresses
        while head != C_NULL
            push!(addresses, j_pcap_addr(head))
            head = unsafe_load(head).next
        end

        new(loaded_pcap_if_t.name == C_NULL ? "" : unsafe_string(loaded_pcap_if_t.name),
            loaded_pcap_if_t.description == C_NULL ? "" : unsafe_string(loaded_pcap_if_t.description),
            addresses,
            loaded_pcap_if_t.flags,
            pcap_if_t
            )
    end
end

"""
    Return a list of all devices
"""
function pcap_findalldevs()::Array{j_pcap_if_t}
    devs = Ref{Ref{pcap_if_t}}(Ref{pcap_if_t}())
    err = Vector{UInt8}(undef, PCAP_ERRBUF_SIZE)

    val = ccall((:pcap_findalldevs, "libpcap"), Int8, (Ref{Ref{pcap_if_t}}, Ptr{UInt8}), devs, err)

    if val == PCAP_ERROR.PCAP_ERROR
        throw(PcapDeviceError(unsafe_string(pointer(err))))
    end

    devs_array = j_pcap_if_t[]
    head = devs[][].next
    while head != C_NULL
        push!(devs_array, j_pcap_if_t(head))
        head = unsafe_load(head).next
    end

    devs_array
end

"""
    Free the memory allocated to the Ptr{pcap_if_t}
"""
function pcap_freealldevs(devs::Ptr{pcap_if_t})::Nothing
    ccall((:pcap_freealldevs, "libpcap"), Cvoid, (Ptr{pcap_if_t}, ), devs)
end

function pcap_freealldevs(devs::j_pcap_if_t)::Nothing
    ccall((:pcap_freealldevs, "libpcap"), Cvoid, (Ptr{pcap_if_t}, ), devs.ptr)
end

function pcap_freealldevs(devs::Array{j_pcap_if_t})::Nothing
    if length(devs) > 0
        ccall((:pcap_freealldevs, "libpcap"), Cvoid, (Ptr{pcap_if_t}, ), devs[1].ptr)
    end
end
