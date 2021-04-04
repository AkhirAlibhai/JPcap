export htons

function htons(hostshort::Int64)::Cushort
    ccall(:htons, Cushort, (Cushort,), convert(UInt16, hostshort))
end
