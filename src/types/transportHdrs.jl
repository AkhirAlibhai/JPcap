export TcpHdr, UdpHdr

struct TcpHdr
    src_port::UInt16
    dest_port::UInt16
    sequence_number::UInt32
    acknowledgment_number::UInt32
    # data_offset::UInt8 # 4 bits
    # reserved::UInt8 # 3 bits
    # flags::UInt8 # 9 bits
    data_offset_reserved_flags::UInt16
    window_size::UInt16
    checksum::UInt16
    urgent_pointer::UInt16
    options::Vector{UInt32}
    # function TcpHdr(new_src_port::UInt16,
    #                 new_dest_port::UInt16,
    #                 new_sequence_number::UInt32,
    #                 new_acknowledgment_number::UInt32,
    #                 new_data_offset_flags::UInt16,
    #                 new_window_size::UInt16,
    #                 new_checksum::UInt16,
    #                 new_urgent_pointer::UInt16,
    #                 new_options::Vector{UInt32})
    #     data_offset_mask = 0b1111000000000000
    #     reserved_mask = 0b0000111000000000
    #     flags_mask = 0b0000000111111111

    #     new(new_src_port,
    #         new_dest_port,
    #         new_sequence_number,
    #         new_acknowledgment_number,
    #         (new_data_offset_flags & data_offset_mask) >> 12,
    #         (new_data_offset_flags & reserved_mask) >> 9,
    #         (new_data_offset_flags & flags_mask),
    #         new_window_size,
    #         new_checksum,
    #         new_urgent_pointer,
    #         new_options,
    #     )
    # end

end

struct UdpHdr
    src_port::UInt16
    dest_port::UInt16
    length::UInt16
    checksum::UInt16
    data::Vector{UInt8}
end
