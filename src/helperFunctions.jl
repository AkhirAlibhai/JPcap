export htons, inet_to_uint32

function htons(hostshort::Int64)::Cushort
    ccall(:htons, Cushort, (Cushort,), convert(UInt16, hostshort))
end

struct in_addr
    s_addr::Cuint
end

function inet_to_uint32(string::String)::UInt32
    addr = Ref{in_addr}()

    if ccall(:inet_aton, Int32, (Cstring, Ref{in_addr}), string, addr) == 0
        throw(error(string, " is not a valid IP address"))
    end

    addr[].s_addr
end
