include("constants.jl")
include("errors.jl")

export pcap_lookupdev,
        sockaddr, pcap_addr, pcap_if_t,
        pcap_findalldevs, pcap_freealldevs,
        j_pcap_if_t, j_pcap_addr, j_sockaddr

"""
    Returns the name of the default device, if it exists
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

struct j_pcap_addr
    ptr::Ptr{Union{pcap_addr, Nothing}}
    next::Union{j_pcap_addr, Nothing}
    addr::Union{j_sockaddr, Nothing}
    netmask::Union{j_sockaddr, Nothing}
    broadaddr::Union{j_sockaddr, Nothing}
    dstaddr::Union{j_sockaddr, Nothing}
    function j_pcap_addr(pcap_addr::Ptr{pcap_addr})
        if pcap_addr == C_NULL
            return nothing
        end

        loaded_pcap_addr = unsafe_load(pcap_addr)

        new(pcap_addr,
            j_pcap_addr(loaded_pcap_addr.next),
            j_sockaddr(loaded_pcap_addr.addr),
            j_sockaddr(loaded_pcap_addr.netmask),
            j_sockaddr(loaded_pcap_addr.broadaddr),
            j_sockaddr(loaded_pcap_addr.dstaddr))
    end
end

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

struct j_pcap_if_t
    ptr::Ptr{Union{pcap_if_t, Nothing}}
    next::Union{j_pcap_if_t, Nothing}
    name::String
    description::String
    addresses::Union{j_pcap_addr, Nothing}
    flags::UInt32
    function j_pcap_if_t(pcap_if_t::Ptr{pcap_if_t})
        if pcap_if_t == C_NULL
            return new(C_NULL,
                        nothing,
                        "",
                        "",
                        nothing,
                        0)
        end

        loaded_pcap_if_t = unsafe_load(pcap_if_t)
        tmp_name = if (loaded_pcap_if_t.name == C_NULL) ""
        else unsafe_string(loaded_pcap_if_t.name)
        end
        tmp_description = if (loaded_pcap_if_t.description == C_NULL) ""
        else unsafe_string(loaded_pcap_if_t.description)
        end

        new(pcap_if_t,
            j_pcap_if_t(loaded_pcap_if_t.next),
            tmp_name,
            tmp_description,
            j_pcap_addr(loaded_pcap_if_t.addresses),
            loaded_pcap_if_t.flags)
    end
end

"""
    Returns a list of all devices
"""
function pcap_findalldevs()::Ptr{pcap_if_t}
    devs = Ref{pcap_if_t}()
    err = Vector{UInt8}(undef, PCAP_ERRBUF_SIZE)

    val = ccall((:pcap_findalldevs, "libpcap"), Int8, (Ref{pcap_if_t}, Ptr{UInt8}), devs, err)

    if val == PCAP_ERROR
        throw(PcapDeviceError(unsafe_string(pointer(err))))
    end
    devs[].next # Call unsafe_load on it to access
end

"""
    Frees the memory allocated to the Ptr{pcap_if_t}
"""
function pcap_freealldevs(alldevs::Ptr{pcap_if_t})::Nothing
    ccall((:pcap_freealldevs, "libpcap"), Cvoid, (Ptr{pcap_if_t}, ), alldevs)
end
