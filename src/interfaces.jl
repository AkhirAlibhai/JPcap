export pcap_lookupdev,
        sockaddr, pcap_addr, pcap_if

function pcap_lookupdev()
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
    se_data::Cstring
    sockaddr() = new(0, Base.unsafe_convert(Cstring, ""))
end

struct pcap_addr
    next::Ptr{pcap_addr}
    addr::Ref{sockaddr}
    netmask::Ref{sockaddr}
    broadaddr::Ref{sockaddr}
    dstaddr::Ref{sockaddr}
    pcap_addr() = new(Ptr{pcap_addr}(), Ref(sockaddr()), Ref(sockaddr()),
                                        Ref(sockaddr()), Ref(sockaddr()))
end

struct pcap_if
    next::Ptr{pcap_if}
    name::Cstring
    description::Cstring
    addresses::Ref{pcap_addr}
    flags::UInt
    pcap_if() = new(Ptr{pcap_if}(), Base.unsafe_convert(Cstring, ""),
                    Base.unsafe_convert(Cstring, ""), Ref(pcap_addr()),
                    0)
end
