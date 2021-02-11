export pcap_lookupdev

function pcap_lookupdev()
    err = Ptr{Int8}()
    dev = ccall((:pcap_lookupdev, "libpcap"), Ptr{Int8}, (Ptr{Int8},), err)
    if dev == C_NULL
        print("Could not find default device: ", unsafe_string(err))
        return nothing
    end
    return unsafe_string(dev)
end
