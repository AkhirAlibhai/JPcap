export pcap_create

mutable struct pcap_t
end

function pcap_create(source::String)::pcap_t
    # Creates a live capture handle for the given interface
    err = Ptr{Int8}()

    val = ccall((:pcap_create, "libpcap"), Ptr{pcap_t}, (Cstring, Ptr{Int8}), Base.cconvert(Cstring, source), err)

    loaded_pcap_t = unsafe_load(val)
    if loaded_pcap_t == C_NULL
        print("Error occured when attempting to create live capture handle: ", unsafe_string(err))
        return nothing
    end
    loaded_pcap_t
end
