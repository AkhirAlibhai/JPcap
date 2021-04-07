export ArpHdr

struct ArpHdr
    hardware_type::UInt16
    protocol_type::UInt16
    hardware_address_length::UInt8
    protocol_address_length::UInt8
    operation::UInt16
#     sender_hardware_address::UInt32 # 24 bits
#     sender_protocol_address::UInt16
#     target_hardware_address::UInt32 # 24 bits
#     target_protocol_address::UInt16
#     # TODO: Potentially do the same bitmask thing in transportHdrs.jl
end
