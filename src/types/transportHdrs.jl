export TcpHdr, UdpHdr

struct TcpHdr
    source_port::UInt16
    destination_port::UInt16
    sequence_number::UInt32
    acknowledgment_number::UInt32
    data_offset::UInt8 # 4 bits
    reserved::UInt8 # 3 bits
    flags::UInt8 # 9 bits
    # TODO: Find a way to get the right bits, could use bitmasks?
    window_size::UInt16
    checksum::UInt16
    urgent_pointer::UInt16
    options::Vector{UInt32}
end

struct UdpHdr
    source_port::UInt16
    destination_port::UInt16
    length::UInt16
    checksum::UInt16
    data::Vector{UInt8}
end
