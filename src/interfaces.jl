export pcap_lookupdev,
        sockaddr, pcap_addr, pcap_if_t,
        pcap_findalldevs, pcap_freealldevs

function pcap_lookupdev()::String
    # Returns the name of the default device, if it exists
    err = Ptr{Int8}()

    dev = ccall((:pcap_lookupdev, "libpcap"), Ptr{Int8}, (Ptr{Int8},), err)

    if dev == C_NULL
        print("Could not find default device: ", unsafe_string(err))
        return nothing
    end
    unsafe_string(dev)
end

struct sockaddr
    sa_family::Cushort
    sa_data::Ptr{UInt8} # TODO: Do not access, needs to be cast into the right kind of sockaddr
    sockaddr() = new(0, Base.unsafe_convert(Cstring, ""))
end

struct pcap_addr
    next::Ptr{pcap_addr}
    addr::Ptr{sockaddr}
    netmask::Ptr{sockaddr}
    broadaddr::Ptr{sockaddr}
    dstaddr::Ptr{sockaddr}
    pcap_addr() = new(Ptr{pcap_addr}(), Ptr{sockaddr}(), Ptr{sockaddr}(),
                                        Ptr{sockaddr}(), Ptr{sockaddr}())
end

struct pcap_if_t
    next::Ptr{pcap_if_t}
    name::Cstring
    description::Cstring
    addresses::Ptr{pcap_addr}
    flags::UInt
    pcap_if_t() = new(Ptr{pcap_if_t}(), Base.unsafe_convert(Cstring, ""),
                    Base.unsafe_convert(Cstring, ""), Ptr{pcap_addr}(),
                    0)
end

const PCAP_ERROR = -1

function pcap_findalldevs()::Ptr{pcap_if_t}
    # Returns a list of all devices
    devs = Ref{pcap_if_t}()
    err = Ptr{Int8}()

    val = ccall((:pcap_findalldevs, "libpcap"), Int8, (Ref{pcap_if_t}, Ptr{Int8}), devs, err)

    if val == PCAP_ERROR
        print("Error occured when looking up all devices: ", unsafe_string(err))
        return nothing
    end
    devs[].next # Call unsafe_load on it to access
end

function pcap_freealldevs(alldevs::Ptr{pcap_if_t})::nothing
    # Frees the memory allocated to the Ptr{pcap_if_t}
    ccall((:pcap_freealldevs, "libpcap"), Cvoid, (Ptr{pcap_if_t}, ), alldevs)
end
