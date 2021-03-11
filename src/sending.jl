export pcap_create, pcap_activate,
        pcap_close,
        pcap_geterr, pcap_perror,
        pcap_open_live

mutable struct pcap_t
end

function pcap_create(source::String)::Ptr{pcap_t}
    # Creates a live capture handle for the given interface
    err = Vector{UInt8}(undef, PCAP_ERRBUF_SIZE)

    handle = ccall((:pcap_create, "libpcap"), Ptr{pcap_t}, (Cstring, Ptr{UInt8}), source, err)

    loaded_handle = unsafe_load(handle)
    if loaded_handle == C_NULL
        println("Error occured when attempting to create live capture handle: ",
                unsafe_string(pointer(err)))
        return nothing
    end
    handle
end

const PCAP_ERROR_ACTIVATED =        -4  # the operation can't be performed on already activated captures
const PCAP_ERROR_NO_SUCH_DEVICE =   -5	# no such device exists
const PCAP_ERROR_RFMON_NOTSUP =     -6	# this device doesn't support rfmon (monitor) mode
const PCAP_ERROR_PERM_DENIED =      -8	# no permission to open the device
const PCAP_ERROR_IFACE_NOT_UP =     -9  # interface isn't up

const PCAP_WARNING_PROMISC_NOTSUP = 2	# this device doesn't support promiscuous mode

function pcap_activate(p::Ptr{pcap_t})::Int32
    # Activates a capture handle
    ccall((:pcap_activate, "libpcap"), Int32, (Ptr{pcap_t},), p)
end

function pcap_close(p::Ptr{pcap_t})::Nothing
    # Closes the capture device
    ccall((:pcap_close, "libpcap"), Cvoid, (Ptr{pcap_t},), p)
end

function pcap_geterr(p::Ptr{pcap_t})::String
    # Gets the error message for the given Ptr{pcap_t}
    unsafe_string(ccall((:pcap_geterr, "libpcap"), Ptr{Int8}, (Ptr{pcap_t},), p))
end

function pcap_perror(p::Ptr{pcap_t})::Nothing
    # Prints the error message for the given Ptr{pcap_t}
    println(pcap_geterr(p))
end

function pcap_open_live(device::String, snaplen::Int64, promisc::Int64, to_ms::Int64)::Union{Ptr{pcap_t}, Nothing}
    # Opens a device for capturing
    err = Vector{UInt8}(undef, PCAP_ERRBUF_SIZE)

    handle = ccall((:pcap_open_live, "libpcap"), Ptr{pcap_t}, (Cstring, Int32, Int32, Int32,
                                        Ptr{UInt8}), device, snaplen, promisc, to_ms, err)

    if handle == C_NULL
        println("Error occured when attempting to create live capture handle: ",
                unsafe_string(pointer(err)))
        return nothing
    end
    handle
end
