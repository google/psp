-- Wireshark plugin to dissect PSP protocol and display on Wireshark and tshark
-- tools.
--
-- Usage:
--  wireshark \
--      -X lua_script:net/hostdatapath/tools/wireshark/plugins/psp.lua \
--      <dump_file>
--
--  tshark \
--      -X lua_script:net/hostdatapath/tools/wireshark/plugins/psp.lua \
--      -r <dump_file>
--  1   0.000000 10.157.132.25 -> 10.157.132.26 PSP 1526 NxtHdr: IPv4  SPI: 0x101  SecToken: 0x87654321  VirtKey: 0x8000000a
--  2   0.000000 10.157.132.25 -> 10.157.132.26 PSP 154 NxtHdr: IPv4  SPI: 0x101  SecToken: 0x87654321  VirtKey: 0x8000000a
--  3   1.000050 10.157.132.25 -> 10.157.132.26 PSP 1526 NxtHdr: IPv4  SPI: 0x101  SecToken: 0x87654321  VirtKey: 0x8000000a
--  4   1.000050 10.157.132.25 -> 10.157.132.26 PSP 154 NxtHdr: IPv4  SPI: 0x101  SecToken: 0x87654321  VirtKey: 0x8000000a
--
-- Reference:
--  1. https://wiki.wireshark.org/Lua
--  2. https://wiki.wireshark.org/LuaAPI
--  3. https://www.wireshark.org/docs/wsdg_html_chunked/index.html

-- Create PSP fields to display in the PSP protocol tree.
-- Next Header
local next_header_values = {
    [4] = "IPv4",
    [41] = "IPv6",
    [17] = "UDP",
    [6] = "TCP",
    [132] = "SCTP",
}
next_header_pf = ProtoField.uint8(
    "psp.nexthdr", "Next Header", base.DEC, next_header_values, nil,
    "IPPROTO value describing the payload of PSP")

-- Header Extension Length
hdrextlen_pf = ProtoField.uint8(
    "psp.hdrextlen", "Header Extension Length", base.DEC, nil, nil,
    "Header length in units of 8 bytes excluding the first 8 bytes")

-- Crypt Offset and Reserved field
cryptoffset_byte_pf = ProtoField.string(
    "psp.cryptoffset_byte", "Crypt Offset")
cryptoffset_pf = ProtoField.uint8("psp.cryptoffset", "Crypt Offset", base.DEC,
    nil, 0x3f, "Number of 4-byte words not encrypted after IV")
reserved0_pf = ProtoField.uint8(
    "psp.reserved0", "Reserved", base.DEC, nil, 0xc0)

-- Version and flags
version_byte_pf = ProtoField.string("psp.version_byte", "Version")
version_pf = ProtoField.uint8(
    "psp.version", "Version", base.DEC, nil, 0x3c, "PSP version")
reserved1_pf = ProtoField.uint8(
    "psp.reserved1", "Reserved", base.DEC, nil, 0xc0)
is_virt_pf = ProtoField.bool(
    "psp.is_virt", "V bit", 8, nil, 0x2,
    "Bit indicating if virtualization cookie is present")
always_one_pf = ProtoField.bool("psp.one_bit", "One bit", 8, nil, 0x1)

-- Security Parameters Index
spi_pf = ProtoField.uint32("psp.spi", "Security Parameters Index", base.HEX_DEC,
    nil, nil, "Index to identify security association (SA)")

-- Initialization Value
iv_pf = ProtoField.uint64("psp.iv", "Initialization Vector", base.HEX_DEC)

-- Virtualization Cookie
vc_pf = ProtoField.uint64("psp.vc", "Virtualization Cookie", base.HEX_DEC)
vc_key_pf = ProtoField.uint32(
    "psp.virtkey", "Virtualization Key", base.HEX_DEC)
vc_token_pf = ProtoField.uint32("psp.sectoken", "Security Token", base.HEX_DEC)

-- Payload
payload_pf = ProtoField.bytes("psp.payload", "Payload")

-- ICV
icv_pf = ProtoField.bytes("psp.icv", "Integrity Checksum Value")


-- Define PSP protocol and its fields.
psp_proto = Proto("psp", "PSP Protocol")
psp_proto.fields = {
    next_header_pf, hdrextlen_pf, spi_pf, iv_pf, cryptoffset_byte_pf,
    cryptoffset_pf, reserved0_pf, version_byte_pf, version_pf, reserved1_pf,
    is_virt_pf, always_one_pf, vc_pf, vc_key_pf, vc_token_pf, payload_pf,
    icv_pf
}

-- Define PSP preferences.
psp_proto.prefs.encrypted_payload = Pref.bool(
    "Encrypted PSP packet", true,
    "Whether PSP packet is encrypted. If the packet is encrypted, " ..
    "PSP.ICV is present and PSP payload is not decoded.")

ip_proto_table = DissectorTable.get("ip.proto")

-- Create a function to dissect PSP protocol.
function psp_proto.dissector(buffer, pinfo, tree)
  local function to_hex(value)
    return string.format("0x%x", value)
  end
  local next_header_buf = buffer(0, 1)
  local hdrextlen_buf = buffer(1, 1)
  local cryptoffset_buf = buffer(2, 1)
  local version_buf = buffer(3, 1)
  local spi_buf = buffer(4, 4)
  local iv_buf = buffer(8, 8)
  local is_virt = bit.band(version_buf:uint(), 0x2)
  local vc_buf = nil
  local sectoken_buf = nil
  local virtkey_buf = nil
  if is_virt > 0 then
    vc_buf = buffer(16, 8)
    sectoken_buf = buffer(16, 4)
    virtkey_buf = buffer(20, 4)
  end

  -- Construct summary.
  pinfo.cols.protocol:set("PSP")
  pinfo.cols.info:clear()
  local next_header = next_header_buf:uint()
  if next_header_values[next_header] == nil then
    next_header_str = "Unknown"
  else
    next_header_str = next_header_values[next_header]
  end
  local spi_str = to_hex(spi_buf:uint())
  local summary = "PSP Protocol, NxtHdr: " .. next_header_str ..
                  ", SPI: " .. spi_str
  pinfo.cols.info:set("NxtHdr: " .. next_header_str .. "  SPI: " .. spi_str)
  if is_virt > 0 then
    local sectoken_str = to_hex(sectoken_buf:uint())
    local virtkey_str = to_hex(virtkey_buf:uint())
    summary = summary .. ", SecToken: " .. sectoken_str ..  ", VirtKey: " ..
              virtkey_str
    pinfo.cols.info:append("  SecToken: " .. sectoken_str .. "  VirtKey: " ..
                           virtkey_str)
  end

  -- Construct PSP tree.
  local psp_tree = tree:add(psp_proto, buffer(), summary)
  psp_tree:add(next_header_pf, next_header_buf)

  local hdrextlen = hdrextlen_buf:uint()
  local hdrextlen_bytes = hdrextlen * 8
  local hdrextlen_item = psp_tree:add(hdrextlen_pf, hdrextlen_buf, hdrextlen)
  hdrextlen_item:append_text(" (" .. hdrextlen_bytes .. " bytes)")

  local cryptoffset = bit.band(cryptoffset_buf:uint(), 0x3f)
  local cryptoffset_bytes = cryptoffset * 4
  local cryptoffset_tree = psp_tree:add(
      cryptoffset_byte_pf, cryptoffset_buf,
      cryptoffset .. " (" .. cryptoffset_bytes .. " bytes)")
  cryptoffset_tree:add(cryptoffset_pf, cryptoffset_buf)
  cryptoffset_tree:add(reserved0_pf, cryptoffset_buf)

  local version = bit.rshift(bit.band(version_buf:uint(), 0x3c), 2)
  local version_tree = psp_tree:add(version_byte_pf, version_buf, version)
  version_tree:add(version_pf, version_buf, version)
  version_tree:add(reserved1_pf, version_buf)
  version_tree:add(is_virt_pf, version_buf)
  version_tree:add(always_one_pf, version_buf)

  psp_tree:add(spi_pf, spi_buf)
  psp_tree:add(iv_pf, iv_buf)

  -- Conditionally show virtualization cookie related items.
  if is_virt > 0 then
    local vc_tree = psp_tree:add(vc_pf, vc_buf)
    vc_tree:add(vc_key_pf, virtkey_buf)
    vc_tree:add(vc_token_pf, sectoken_buf)
  end

  local payload_offset = 8 + hdrextlen_bytes
  local payload_length = buffer:len() - payload_offset
  local icv_length = 16
  if psp_proto.prefs.encrypted_payload then
    payload_length = payload_length - icv_length
  end
  local payload_buf = buffer(payload_offset, payload_length)
  local payload_tree = psp_tree:add(payload_pf, payload_buf)
  if not psp_proto.prefs.encrypted_payload then
    local payload_dissector = ip_proto_table:get_dissector(next_header)
    payload_dissector:call(payload_buf:tvb(), pinfo, payload_tree)
  end

  if psp_proto.prefs.encrypted_payload then
    psp_tree:add(icv_pf, buffer(payload_offset + payload_length, icv_length))
  end
end

-- Register PSP protocol to handle UDP port 1000.
udp_table = DissectorTable.get("udp.port")
udp_table:add(1000, psp_proto)
