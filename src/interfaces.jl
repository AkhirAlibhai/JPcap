export pcap_lookupdev,
        sockaddr

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
