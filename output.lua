ICMP_protocol = Proto("ourICMP", "ICMPProtocol")

types =ProtoField.int32("ICMP_protocol.types", "Type", base.DEC)
code =ProtoField.int32("ICMP_protocol.code", "Code", base.DEC)
checksum =ProtoField.uint8("ICMP_protocol.checksum", "Checksum", base.HEX)
ident =ProtoField.int32("ICMP_protocol.ident", "Identifier", base.DEC)
seqnum =ProtoField.int32("ICMP_protocol.seqnum", "Sequence Number", base.DEC)
timestamp =ProtoField.absolute_time("ICMP_protocol.timestamp", "Time Stamp", base.TIME)
ICMP_protocol.fields = {types, code, checksum, ident, seqnum, timestamp}

function ICMP_protocol.dissector(buffer, pinfo, tree)
 length = buffer:len()

 if length ==0 then return end
pinfo.cols.protocol = ICMP_protocol.name
local subtree = tree:add(ICMP_protocol, buffer(), "ICMPProtocol data ")

subtree:add_le(types, buffer(0,1))
subtree:add_le(code, buffer(1,1))
subtree:add(checksum, buffer(2,2))
subtree:add(ident, buffer(4,2))
subtree:add(seqnum, buffer(6,2))
subtree:add(timestamp, buffer(8,8))
end
porttable = DissectorTable.get("ip.proto")
porttable:add(1, ICMP_protocol)
