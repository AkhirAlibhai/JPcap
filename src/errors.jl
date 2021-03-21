export PcapDeviceError, PcapCreateHandleError,
        PcapPacketCaptureError, PcapPacketCaptureTimeoutError

struct PcapDeviceError <: Exception
    var::String
end

Base.showerror(io::IO, e::PcapDeviceError) = print(io, "Device error occured: ", e.var)

struct PcapCreateHandleError <: Exception
    var::string
end

Base.showerror(io::IO, e::PcapCreateHandleError) = print(io, "Error occured when creating capture handle: ", e.var)

struct PcapPacketCaptureError <: Exception
end

Base.showerror(io::IO, e::PcapCreateHandleError) = print(io, "Error occured when capturing packets")

struct PcapPacketCaptureTimeoutError <: PcapPacketCaptureError
end

Base.showerror(io::IO, e::PcapPacketCaptureTimeoutError) = print(io, "Error occured when capturing packets or no packets were read from the live capture device")
