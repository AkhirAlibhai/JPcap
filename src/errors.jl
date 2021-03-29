export PcapDeviceError, PcapCreateHandleError,
        PcapPacketCaptureError, PcapPacketCaptureTimeoutError,
        PcapCallbackInvalidParametersError,
        PcapSetNonBlockError, PcapGetNonBlockError

struct PcapDeviceError <: Exception
    var::String
end

Base.showerror(io::IO, e::PcapDeviceError) = print(io, "Device error occured: ", e.var)

struct PcapCreateHandleError <: Exception
    var::String
end

Base.showerror(io::IO, e::PcapCreateHandleError) = print(io, "Error occured when creating capture handle: ", e.var)

struct PcapPacketCaptureError <: Exception
end

Base.showerror(io::IO, e::PcapPacketCaptureError) = print(io, "Error occured when capturing packets")

struct PcapPacketCaptureTimeoutError <: Exception
end

Base.showerror(io::IO, e::PcapPacketCaptureTimeoutError) = print(io, "Error occured when capturing packets or no packets were read from the live capture device")

struct PcapCallbackInvalidParametersError <: Exception
end

Base.showerror(io::IO, e::PcapCallbackInvalidParametersError) = print(io, "Callback function has incorrect parameters. The correct parameters are (UInt8, Ptr{pcap_pkthdr}, Ptr{UInt8})")

struct PcapSetNonBlockError <: Exception
    var::String
end

Base.showerror(io::IO, e::PcapSetNonBlockError) = print(io, "Error when setting non-blocking mode on capture device: ", e.var)

struct PcapGetNonBlockError <: Exception
    var::String
end

Base.showerror(io::IO, e::PcapGetNonBlockError) = print(io, "Error when getting non-blocking mode on capture device: ", e.var)
