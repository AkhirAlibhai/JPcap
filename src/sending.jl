export pcap_create

mutable struct pcap_t
end

function pcap_create(source::String)::pcap_t
    # Creates a live capture handle for the given interface
    err = Ptr{Int8}()

    handle = ccall((:pcap_create, "libpcap"), Ptr{pcap_t}, (Cstring, Ptr{Int8}), Base.cconvert(Cstring, source), err)

    loaded_handle = unsafe_load(handle)
    if loaded_handle == C_NULL
        print("Error occured when attempting to create live capture handle: ", unsafe_string(err))
        return nothing
    end
    loaded_handle
end
