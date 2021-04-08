include("types/pcapT.jl")

export pcap_geterr, pcap_perror,
        pcap_statustostr, pcap_strerror

"""
Get the error message for the given Ptr{Pcap_t}
"""
function pcap_geterr(p::Ptr{Pcap_t})::String
unsafe_string(ccall((:pcap_geterr, "libpcap"), Ptr{Int8}, (Ptr{Pcap_t},), p))
end

"""
Print the error message for the given Ptr{Pcap_t}
"""
function pcap_perror(p::Ptr{Pcap_t})::Nothing
println(pcap_geterr(p))
end

"""
    Convert a PCAP_ERROR_ or PCAP_WARNING_ value to a string
"""
function pcap_statustostr(error::Int64)::String
    unsafe_string(ccall((:pcap_statustostr, "libpcap"), Cstring, (Int32,), error))
end

"""
    Convert an errno value to a string
"""
function pcap_strerror(error::Int64)::String
    unsafe_string(ccall((:pcap_strerror, "libpcap"), Cstring, (Int32,), error))
end
