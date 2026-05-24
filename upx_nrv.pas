{$mode delphi}
{$POINTERMATH ON}
unit upx_nrv;

// UPX Pascal Port
// License: GNU GPL
// Author: www.xelitan.com
//
// NRV2B/2D/2E compression and decompression
//  Translated from UCL 1.03 (vendor/ucl) © Markus F.X.J. Oberhumer, GPL v2+
//
//  Supported bit buffer variants:
//    _8    – 8-bit (1 byte at a time)
//    _le16 – 16-bit little-endian
//    _le32 – 32-bit little-endian
//
//  Compressors: NRV2B-99, NRV2D-99, NRV2E-99 (sliding-window with chaining)


interface

uses upx_types;

// ── decompression ────────────────────────────────────────────────────────────

function nrv2b_decompress_8   (src: PByte; src_len: Cardinal;
                               dst: PByte; var dst_len: Cardinal): Integer;
function nrv2b_decompress_le16(src: PByte; src_len: Cardinal;
                               dst: PByte; var dst_len: Cardinal): Integer;
function nrv2b_decompress_le32(src: PByte; src_len: Cardinal;
                               dst: PByte; var dst_len: Cardinal): Integer;

function nrv2d_decompress_8   (src: PByte; src_len: Cardinal;
                               dst: PByte; var dst_len: Cardinal): Integer;
function nrv2d_decompress_le16(src: PByte; src_len: Cardinal;
                               dst: PByte; var dst_len: Cardinal): Integer;
function nrv2d_decompress_le32(src: PByte; src_len: Cardinal;
                               dst: PByte; var dst_len: Cardinal): Integer;

function nrv2e_decompress_8   (src: PByte; src_len: Cardinal;
                               dst: PByte; var dst_len: Cardinal): Integer;
function nrv2e_decompress_le16(src: PByte; src_len: Cardinal;
                               dst: PByte; var dst_len: Cardinal): Integer;
function nrv2e_decompress_le32(src: PByte; src_len: Cardinal;
                               dst: PByte; var dst_len: Cardinal): Integer;

// dispatcher by method code
function nrv_decompress(src: PByte; src_len: Cardinal;
                        dst: PByte; var dst_len: Cardinal;
                        method: Integer): Integer;

// ── compression ──────────────────────────────────────────────────────────────

// level 1..10
function nrv2b_compress(src: PByte; src_len: Cardinal;
                        dst: PByte; var dst_len: Cardinal;
                        level: Integer; bb_size: Integer): Integer;
function nrv2d_compress(src: PByte; src_len: Cardinal;
                        dst: PByte; var dst_len: Cardinal;
                        level: Integer; bb_size: Integer): Integer;
function nrv2e_compress(src: PByte; src_len: Cardinal;
                        dst: PByte; var dst_len: Cardinal;
                        level: Integer; bb_size: Integer): Integer;

function nrv_compress(src: PByte; src_len: Cardinal;
                      dst: PByte; var dst_len: Cardinal;
                      method: Integer; level: Integer): Integer;

implementation

// ═══════════════════════════════════════════════════════════════════════════
//  DECOMPRESSION SECTION
// ═══════════════════════════════════════════════════════════════════════════

(*
  getbit macros – translated from vendor/ucl/src/getbit.h
  For variant _8:
    bb = 0 at start
    if (bb & $7F) <> 0  =>  bb := bb shl 1
    else                =>  bb := src[ilen++] * 2 + 1
    bit = (bb shr 8) and 1
  For variant _le16:
    bb := bb shl 1
    if bb and $FFFF = 0 => load 2 bytes (LE), ilen+=2
    bit = (bb shr 16) and 1
  For variant _le32:
    bc > 0 => bit = (bb shr (bc-1)) and 1, bc--
    bc = 0 => load 4 bytes (LE), bc=31, bit = bb shr 31
*)

// ── NRV2B decompression ──────────────────────────────────────────────────────

function nrv2b_decompress_8(src: PByte; src_len: Cardinal;
                            dst: PByte; var dst_len: Cardinal): Integer;
var
  bb: Cardinal;
  ilen, olen, last_m_off: Cardinal;
  oend: Cardinal;
  m_off, m_len: Cardinal;
  m_pos: PByte;

  function getbit: Cardinal; inline;
  begin
    if (bb and $7F) <> 0 then
      bb := bb shl 1
    else begin
      if ilen >= src_len then begin Result := 0; Exit end; // handled by fail below
      bb := Cardinal(src[ilen]) * 2 + 1;
      Inc(ilen);
    end;
    Result := (bb shr 8) and 1;
  end;

begin
  bb := 0; ilen := 0; olen := 0; last_m_off := 1;
  oend := dst_len;
  while True do
  begin
    // literal run
    while getbit = 1 do
    begin
      if ilen >= src_len then begin dst_len := olen; Exit(UPX_E_INPUT_OVERRUN) end;
      if olen >= oend    then begin dst_len := olen; Exit(UPX_E_OUTPUT_OVERRUN) end;
      dst[olen] := src[ilen]; Inc(olen); Inc(ilen);
    end;
    // match – read offset
    m_off := 1;
    repeat
      m_off := m_off * 2 + getbit;
      if ilen >= src_len then begin dst_len := olen; Exit(UPX_E_INPUT_OVERRUN) end;
      if m_off > Cardinal($FFFFFF) + 3 then begin dst_len := olen; Exit(UPX_E_LOOKBEHIND_OVERRUN) end;
    until getbit = 1;
    if m_off = 2 then
      m_off := last_m_off
    else begin
      if ilen >= src_len then begin dst_len := olen; Exit(UPX_E_INPUT_OVERRUN) end;
      m_off := (m_off - 3) * 256 + src[ilen]; Inc(ilen);
      if m_off = Cardinal($FFFFFFFF) then Break; // EOF
      Inc(m_off);
      last_m_off := m_off;
    end;
    // read length
    m_len := getbit;
    m_len := m_len * 2 + getbit;
    if m_len = 0 then
    begin
      Inc(m_len);
      repeat
        m_len := m_len * 2 + getbit;
        if ilen >= src_len then begin dst_len := olen; Exit(UPX_E_INPUT_OVERRUN) end;
        if m_len >= oend   then begin dst_len := olen; Exit(UPX_E_OUTPUT_OVERRUN) end;
      until getbit = 1;
      Inc(m_len, 2);
    end;
    if m_off > $D00 then Inc(m_len);
    if olen + m_len >= oend then begin dst_len := olen; Exit(UPX_E_OUTPUT_OVERRUN) end;
    if m_off > olen then begin dst_len := olen; Exit(UPX_E_LOOKBEHIND_OVERRUN) end;
    m_pos := dst + olen - m_off;
    dst[olen] := m_pos[0]; Inc(olen); Inc(m_pos);
    while m_len > 0 do begin dst[olen] := m_pos[0]; Inc(olen); Inc(m_pos); Dec(m_len) end;
  end;
  dst_len := olen;
  if ilen = src_len then Result := UPX_E_OK
  else if ilen < src_len then Result := UPX_E_INPUT_NOT_CONSUMED
  else Result := UPX_E_INPUT_OVERRUN;
end;

function nrv2b_decompress_le16(src: PByte; src_len: Cardinal;
                               dst: PByte; var dst_len: Cardinal): Integer;
var
  bb: Cardinal;
  ilen, olen, last_m_off: Cardinal;
  oend: Cardinal;
  m_off, m_len: Cardinal;
  m_pos: PByte;

  function getbit: Cardinal; inline;
  begin
    bb := bb shl 1;
    if (bb and $FFFF) = 0 then
    begin
      bb := Cardinal(src[ilen]) or (Cardinal(src[ilen+1]) shl 8);
      bb := bb * 2 + 1;
      Inc(ilen, 2);
    end;
    Result := (bb shr 16) and 1;
  end;

begin
  bb := 0; ilen := 0; olen := 0; last_m_off := 1;
  oend := dst_len;
  while True do
  begin
    while getbit = 1 do
    begin
      if ilen >= src_len then begin dst_len := olen; Exit(UPX_E_INPUT_OVERRUN) end;
      if olen >= oend    then begin dst_len := olen; Exit(UPX_E_OUTPUT_OVERRUN) end;
      dst[olen] := src[ilen]; Inc(olen); Inc(ilen);
    end;
    m_off := 1;
    repeat
      m_off := m_off * 2 + getbit;
      if ilen >= src_len then begin dst_len := olen; Exit(UPX_E_INPUT_OVERRUN) end;
      if m_off > Cardinal($FFFFFF) + 3 then begin dst_len := olen; Exit(UPX_E_LOOKBEHIND_OVERRUN) end;
    until getbit = 1;
    if m_off = 2 then
      m_off := last_m_off
    else begin
      if ilen >= src_len then begin dst_len := olen; Exit(UPX_E_INPUT_OVERRUN) end;
      m_off := (m_off - 3) * 256 + src[ilen]; Inc(ilen);
      if m_off = Cardinal($FFFFFFFF) then Break;
      Inc(m_off);
      last_m_off := m_off;
    end;
    m_len := getbit; m_len := m_len * 2 + getbit;
    if m_len = 0 then
    begin
      Inc(m_len);
      repeat
        m_len := m_len * 2 + getbit;
        if ilen >= src_len then begin dst_len := olen; Exit(UPX_E_INPUT_OVERRUN) end;
        if m_len >= oend   then begin dst_len := olen; Exit(UPX_E_OUTPUT_OVERRUN) end;
      until getbit = 1;
      Inc(m_len, 2);
    end;
    if m_off > $D00 then Inc(m_len);
    if olen + m_len >= oend then begin dst_len := olen; Exit(UPX_E_OUTPUT_OVERRUN) end;
    if m_off > olen then begin dst_len := olen; Exit(UPX_E_LOOKBEHIND_OVERRUN) end;
    m_pos := dst + olen - m_off;
    dst[olen] := m_pos[0]; Inc(olen); Inc(m_pos);
    while m_len > 0 do begin dst[olen] := m_pos[0]; Inc(olen); Inc(m_pos); Dec(m_len) end;
  end;
  dst_len := olen;
  if ilen = src_len then Result := UPX_E_OK
  else if ilen < src_len then Result := UPX_E_INPUT_NOT_CONSUMED
  else Result := UPX_E_INPUT_OVERRUN;
end;

function nrv2b_decompress_le32(src: PByte; src_len: Cardinal;
                               dst: PByte; var dst_len: Cardinal): Integer;
var
  bb, bc: Cardinal;
  ilen, olen, last_m_off: Cardinal;
  oend: Cardinal;
  m_off, m_len: Cardinal;
  m_pos: PByte;

  function getbit: Cardinal; inline;
  begin
    if bc > 0 then
    begin
      Dec(bc);
      Result := (bb shr bc) and 1;
    end else begin
      bb := Cardinal(src[ilen]) or (Cardinal(src[ilen+1]) shl 8)
          or (Cardinal(src[ilen+2]) shl 16) or (Cardinal(src[ilen+3]) shl 24);
      Inc(ilen, 4);
      bc := 31;
      Result := (bb shr 31) and 1;
    end;
  end;

begin
  bb := 0; bc := 0; ilen := 0; olen := 0; last_m_off := 1;
  oend := dst_len;
  while True do
  begin
    while getbit = 1 do
    begin
      if ilen >= src_len then begin dst_len := olen; Exit(UPX_E_INPUT_OVERRUN) end;
      if olen >= oend    then begin dst_len := olen; Exit(UPX_E_OUTPUT_OVERRUN) end;
      dst[olen] := src[ilen]; Inc(olen); Inc(ilen);
    end;
    m_off := 1;
    repeat
      m_off := m_off * 2 + getbit;
      if ilen >= src_len then begin dst_len := olen; Exit(UPX_E_INPUT_OVERRUN) end;
      if m_off > Cardinal($FFFFFF) + 3 then begin dst_len := olen; Exit(UPX_E_LOOKBEHIND_OVERRUN) end;
    until getbit = 1;
    if m_off = 2 then
      m_off := last_m_off
    else begin
      if ilen >= src_len then begin dst_len := olen; Exit(UPX_E_INPUT_OVERRUN) end;
      m_off := (m_off - 3) * 256 + src[ilen]; Inc(ilen);
      if m_off = Cardinal($FFFFFFFF) then Break;
      Inc(m_off);
      last_m_off := m_off;
    end;
    m_len := getbit; m_len := m_len * 2 + getbit;
    if m_len = 0 then
    begin
      Inc(m_len);
      repeat
        m_len := m_len * 2 + getbit;
        if ilen >= src_len then begin dst_len := olen; Exit(UPX_E_INPUT_OVERRUN) end;
        if m_len >= oend   then begin dst_len := olen; Exit(UPX_E_OUTPUT_OVERRUN) end;
      until getbit = 1;
      Inc(m_len, 2);
    end;
    if m_off > $D00 then Inc(m_len);
    if olen + m_len >= oend then begin dst_len := olen; Exit(UPX_E_OUTPUT_OVERRUN) end;
    if m_off > olen then begin dst_len := olen; Exit(UPX_E_LOOKBEHIND_OVERRUN) end;
    m_pos := dst + olen - m_off;
    dst[olen] := m_pos[0]; Inc(olen); Inc(m_pos);
    while m_len > 0 do begin dst[olen] := m_pos[0]; Inc(olen); Inc(m_pos); Dec(m_len) end;
  end;
  dst_len := olen;
  if ilen = src_len then Result := UPX_E_OK
  else if ilen < src_len then Result := UPX_E_INPUT_NOT_CONSUMED
  else Result := UPX_E_INPUT_OVERRUN;
end;

// ── NRV2D decompression ──────────────────────────────────────────────────────
// Differences from NRV2B:
//   - offset: ss12 (4+2 bits per step) instead of ss11 (3+2 bits)
//   - length: bit taken from LSB of offset byte

function nrv2d_decompress_8(src: PByte; src_len: Cardinal;
                            dst: PByte; var dst_len: Cardinal): Integer;
var
  bb: Cardinal;
  ilen, olen, last_m_off: Cardinal;
  oend: Cardinal;
  m_off, m_len: Cardinal;
  m_pos: PByte;
  m_low: Cardinal;

  function getbit: Cardinal; inline;
  begin
    if (bb and $7F) <> 0 then bb := bb shl 1
    else begin
      bb := Cardinal(src[ilen]) * 2 + 1; Inc(ilen);
    end;
    Result := (bb shr 8) and 1;
  end;

begin
  bb := 0; ilen := 0; olen := 0; last_m_off := 1;
  oend := dst_len;
  while True do
  begin
    while getbit = 1 do
    begin
      if ilen >= src_len then begin dst_len := olen; Exit(UPX_E_INPUT_OVERRUN) end;
      if olen >= oend    then begin dst_len := olen; Exit(UPX_E_OUTPUT_OVERRUN) end;
      dst[olen] := src[ilen]; Inc(olen); Inc(ilen);
    end;
    m_off := 1;
    while True do
    begin
      m_off := m_off * 2 + getbit;
      if ilen >= src_len then begin dst_len := olen; Exit(UPX_E_INPUT_OVERRUN) end;
      if m_off > Cardinal($FFFFFF) + 3 then begin dst_len := olen; Exit(UPX_E_LOOKBEHIND_OVERRUN) end;
      if getbit = 1 then Break;
      m_off := (m_off - 1) * 2 + getbit;
    end;
    if m_off = 2 then
    begin
      m_off := last_m_off;
      m_len := getbit;
    end else begin
      if ilen >= src_len then begin dst_len := olen; Exit(UPX_E_INPUT_OVERRUN) end;
      m_off := (m_off - 3) * 256 + src[ilen]; Inc(ilen);
      if m_off = Cardinal($FFFFFFFF) then Break;
      m_low := (m_off xor Cardinal($FFFFFFFF)) and 1;
      m_off := m_off shr 1;
      Inc(m_off);
      last_m_off := m_off;
      m_len := m_low;
    end;
    m_len := m_len * 2 + getbit;
    if m_len = 0 then
    begin
      Inc(m_len);
      repeat
        m_len := m_len * 2 + getbit;
        if ilen >= src_len then begin dst_len := olen; Exit(UPX_E_INPUT_OVERRUN) end;
        if m_len >= oend   then begin dst_len := olen; Exit(UPX_E_OUTPUT_OVERRUN) end;
      until getbit = 1;
      Inc(m_len, 2);
    end;
    if m_off > $500 then Inc(m_len);
    if olen + m_len >= oend then begin dst_len := olen; Exit(UPX_E_OUTPUT_OVERRUN) end;
    if m_off > olen then begin dst_len := olen; Exit(UPX_E_LOOKBEHIND_OVERRUN) end;
    m_pos := dst + olen - m_off;
    dst[olen] := m_pos[0]; Inc(olen); Inc(m_pos);
    while m_len > 0 do begin dst[olen] := m_pos[0]; Inc(olen); Inc(m_pos); Dec(m_len) end;
  end;
  dst_len := olen;
  if ilen = src_len then Result := UPX_E_OK
  else if ilen < src_len then Result := UPX_E_INPUT_NOT_CONSUMED
  else Result := UPX_E_INPUT_OVERRUN;
end;

function nrv2d_decompress_le16(src: PByte; src_len: Cardinal;
                               dst: PByte; var dst_len: Cardinal): Integer;
var
  bb: Cardinal;
  ilen, olen, last_m_off: Cardinal;
  oend: Cardinal;
  m_off, m_len, m_low: Cardinal;
  m_pos: PByte;

  function getbit: Cardinal; inline;
  begin
    bb := bb shl 1;
    if (bb and $FFFF) = 0 then
    begin
      bb := Cardinal(src[ilen]) or (Cardinal(src[ilen+1]) shl 8);
      bb := bb * 2 + 1; Inc(ilen, 2);
    end;
    Result := (bb shr 16) and 1;
  end;

begin
  bb := 0; ilen := 0; olen := 0; last_m_off := 1;
  oend := dst_len;
  while True do
  begin
    while getbit = 1 do
    begin
      if ilen >= src_len then begin dst_len := olen; Exit(UPX_E_INPUT_OVERRUN) end;
      if olen >= oend    then begin dst_len := olen; Exit(UPX_E_OUTPUT_OVERRUN) end;
      dst[olen] := src[ilen]; Inc(olen); Inc(ilen);
    end;
    m_off := 1;
    while True do
    begin
      m_off := m_off * 2 + getbit;
      if ilen >= src_len then begin dst_len := olen; Exit(UPX_E_INPUT_OVERRUN) end;
      if m_off > Cardinal($FFFFFF) + 3 then begin dst_len := olen; Exit(UPX_E_LOOKBEHIND_OVERRUN) end;
      if getbit = 1 then Break;
      m_off := (m_off - 1) * 2 + getbit;
    end;
    if m_off = 2 then begin m_off := last_m_off; m_len := getbit end
    else begin
      m_off := (m_off - 3) * 256 + src[ilen]; Inc(ilen);
      if m_off = Cardinal($FFFFFFFF) then Break;
      m_low := (m_off xor Cardinal($FFFFFFFF)) and 1;
      m_off := m_off shr 1; Inc(m_off); last_m_off := m_off;
      m_len := m_low;
    end;
    m_len := m_len * 2 + getbit;
    if m_len = 0 then
    begin
      Inc(m_len);
      repeat
        m_len := m_len * 2 + getbit;
        if ilen >= src_len then begin dst_len := olen; Exit(UPX_E_INPUT_OVERRUN) end;
        if m_len >= oend   then begin dst_len := olen; Exit(UPX_E_OUTPUT_OVERRUN) end;
      until getbit = 1;
      Inc(m_len, 2);
    end;
    if m_off > $500 then Inc(m_len);
    if olen + m_len >= oend then begin dst_len := olen; Exit(UPX_E_OUTPUT_OVERRUN) end;
    if m_off > olen then begin dst_len := olen; Exit(UPX_E_LOOKBEHIND_OVERRUN) end;
    m_pos := dst + olen - m_off;
    dst[olen] := m_pos[0]; Inc(olen); Inc(m_pos);
    while m_len > 0 do begin dst[olen] := m_pos[0]; Inc(olen); Inc(m_pos); Dec(m_len) end;
  end;
  dst_len := olen;
  if ilen = src_len then Result := UPX_E_OK
  else if ilen < src_len then Result := UPX_E_INPUT_NOT_CONSUMED
  else Result := UPX_E_INPUT_OVERRUN;
end;

function nrv2d_decompress_le32(src: PByte; src_len: Cardinal;
                               dst: PByte; var dst_len: Cardinal): Integer;
var
  bb, bc: Cardinal;
  ilen, olen, last_m_off: Cardinal;
  oend: Cardinal;
  m_off, m_len, m_low: Cardinal;
  m_pos: PByte;

  function getbit: Cardinal; inline;
  begin
    if bc > 0 then begin Dec(bc); Result := (bb shr bc) and 1 end
    else begin
      bb := Cardinal(src[ilen]) or (Cardinal(src[ilen+1]) shl 8)
          or (Cardinal(src[ilen+2]) shl 16) or (Cardinal(src[ilen+3]) shl 24);
      Inc(ilen, 4); bc := 31;
      Result := (bb shr 31) and 1;
    end;
  end;

begin
  bb := 0; bc := 0; ilen := 0; olen := 0; last_m_off := 1;
  oend := dst_len;
  while True do
  begin
    while getbit = 1 do
    begin
      if ilen >= src_len then begin dst_len := olen; Exit(UPX_E_INPUT_OVERRUN) end;
      if olen >= oend    then begin dst_len := olen; Exit(UPX_E_OUTPUT_OVERRUN) end;
      dst[olen] := src[ilen]; Inc(olen); Inc(ilen);
    end;
    m_off := 1;
    while True do
    begin
      m_off := m_off * 2 + getbit;
      if ilen >= src_len then begin dst_len := olen; Exit(UPX_E_INPUT_OVERRUN) end;
      if m_off > Cardinal($FFFFFF) + 3 then begin dst_len := olen; Exit(UPX_E_LOOKBEHIND_OVERRUN) end;
      if getbit = 1 then Break;
      m_off := (m_off - 1) * 2 + getbit;
    end;
    if m_off = 2 then begin m_off := last_m_off; m_len := getbit end
    else begin
      m_off := (m_off - 3) * 256 + src[ilen]; Inc(ilen);
      if m_off = Cardinal($FFFFFFFF) then Break;
      m_low := (m_off xor Cardinal($FFFFFFFF)) and 1;
      m_off := m_off shr 1; Inc(m_off); last_m_off := m_off;
      m_len := m_low;
    end;
    m_len := m_len * 2 + getbit;
    if m_len = 0 then
    begin
      Inc(m_len);
      repeat
        m_len := m_len * 2 + getbit;
        if ilen >= src_len then begin dst_len := olen; Exit(UPX_E_INPUT_OVERRUN) end;
        if m_len >= oend   then begin dst_len := olen; Exit(UPX_E_OUTPUT_OVERRUN) end;
      until getbit = 1;
      Inc(m_len, 2);
    end;
    if m_off > $500 then Inc(m_len);
    if olen + m_len >= oend then begin dst_len := olen; Exit(UPX_E_OUTPUT_OVERRUN) end;
    if m_off > olen then begin dst_len := olen; Exit(UPX_E_LOOKBEHIND_OVERRUN) end;
    m_pos := dst + olen - m_off;
    dst[olen] := m_pos[0]; Inc(olen); Inc(m_pos);
    while m_len > 0 do begin dst[olen] := m_pos[0]; Inc(olen); Inc(m_pos); Dec(m_len) end;
  end;
  dst_len := olen;
  if ilen = src_len then Result := UPX_E_OK
  else if ilen < src_len then Result := UPX_E_INPUT_NOT_CONSUMED
  else Result := UPX_E_INPUT_OVERRUN;
end;

// ── NRV2E decompression ──────────────────────────────────────────────────────
// Differences from NRV2D: different match length encoding (3 cases: 1, 2-3, 4+)

function nrv2e_decompress_8(src: PByte; src_len: Cardinal;
                            dst: PByte; var dst_len: Cardinal): Integer;
var
  bb: Cardinal;
  ilen, olen, last_m_off: Cardinal;
  oend: Cardinal;
  m_off, m_len, m_low: Cardinal;
  m_pos: PByte;

  function getbit: Cardinal; inline;
  begin
    if (bb and $7F) <> 0 then bb := bb shl 1
    else begin bb := Cardinal(src[ilen]) * 2 + 1; Inc(ilen) end;
    Result := (bb shr 8) and 1;
  end;

begin
  bb := 0; ilen := 0; olen := 0; last_m_off := 1;
  oend := dst_len;
  while True do
  begin
    while getbit = 1 do
    begin
      if ilen >= src_len then begin dst_len := olen; Exit(UPX_E_INPUT_OVERRUN) end;
      if olen >= oend    then begin dst_len := olen; Exit(UPX_E_OUTPUT_OVERRUN) end;
      dst[olen] := src[ilen]; Inc(olen); Inc(ilen);
    end;
    m_off := 1;
    while True do
    begin
      m_off := m_off * 2 + getbit;
      if ilen >= src_len then begin dst_len := olen; Exit(UPX_E_INPUT_OVERRUN) end;
      if m_off > Cardinal($FFFFFF) + 3 then begin dst_len := olen; Exit(UPX_E_LOOKBEHIND_OVERRUN) end;
      if getbit = 1 then Break;
      m_off := (m_off - 1) * 2 + getbit;
    end;
    if m_off = 2 then
    begin
      m_off := last_m_off; m_len := getbit;
    end else begin
      m_off := (m_off - 3) * 256 + src[ilen]; Inc(ilen);
      if m_off = Cardinal($FFFFFFFF) then Break;
      m_low := (m_off xor Cardinal($FFFFFFFF)) and 1;
      m_off := m_off shr 1; Inc(m_off); last_m_off := m_off;
      m_len := m_low;
    end;
    // NRV2E: m_len 0=1, 1=1+getbit(1..2), 00=3+getbit(3..4+)
    if m_len <> 0 then
      m_len := 1 + getbit
    else if getbit <> 0 then
      m_len := 3 + getbit
    else begin
      Inc(m_len);
      repeat
        m_len := m_len * 2 + getbit;
        if ilen >= src_len then begin dst_len := olen; Exit(UPX_E_INPUT_OVERRUN) end;
        if m_len >= oend   then begin dst_len := olen; Exit(UPX_E_OUTPUT_OVERRUN) end;
      until getbit = 1;
      Inc(m_len, 3);
    end;
    if m_off > $500 then Inc(m_len);
    if olen + m_len >= oend then begin dst_len := olen; Exit(UPX_E_OUTPUT_OVERRUN) end;
    if m_off > olen then begin dst_len := olen; Exit(UPX_E_LOOKBEHIND_OVERRUN) end;
    m_pos := dst + olen - m_off;
    dst[olen] := m_pos[0]; Inc(olen); Inc(m_pos);
    while m_len > 0 do begin dst[olen] := m_pos[0]; Inc(olen); Inc(m_pos); Dec(m_len) end;
  end;
  dst_len := olen;
  if ilen = src_len then Result := UPX_E_OK
  else if ilen < src_len then Result := UPX_E_INPUT_NOT_CONSUMED
  else Result := UPX_E_INPUT_OVERRUN;
end;

function nrv2e_decompress_le16(src: PByte; src_len: Cardinal;
                               dst: PByte; var dst_len: Cardinal): Integer;
var
  bb: Cardinal;
  ilen, olen, last_m_off: Cardinal;
  oend: Cardinal;
  m_off, m_len, m_low: Cardinal;
  m_pos: PByte;

  function getbit: Cardinal; inline;
  begin
    bb := bb shl 1;
    if (bb and $FFFF) = 0 then
    begin
      bb := Cardinal(src[ilen]) or (Cardinal(src[ilen+1]) shl 8);
      bb := bb * 2 + 1; Inc(ilen, 2);
    end;
    Result := (bb shr 16) and 1;
  end;

begin
  bb := 0; ilen := 0; olen := 0; last_m_off := 1;
  oend := dst_len;
  while True do
  begin
    while getbit = 1 do
    begin
      if ilen >= src_len then begin dst_len := olen; Exit(UPX_E_INPUT_OVERRUN) end;
      if olen >= oend    then begin dst_len := olen; Exit(UPX_E_OUTPUT_OVERRUN) end;
      dst[olen] := src[ilen]; Inc(olen); Inc(ilen);
    end;
    m_off := 1;
    while True do
    begin
      m_off := m_off * 2 + getbit;
      if ilen >= src_len then begin dst_len := olen; Exit(UPX_E_INPUT_OVERRUN) end;
      if m_off > Cardinal($FFFFFF) + 3 then begin dst_len := olen; Exit(UPX_E_LOOKBEHIND_OVERRUN) end;
      if getbit = 1 then Break;
      m_off := (m_off - 1) * 2 + getbit;
    end;
    if m_off = 2 then begin m_off := last_m_off; m_len := getbit end
    else begin
      m_off := (m_off - 3) * 256 + src[ilen]; Inc(ilen);
      if m_off = Cardinal($FFFFFFFF) then Break;
      m_low := (m_off xor Cardinal($FFFFFFFF)) and 1;
      m_off := m_off shr 1; Inc(m_off); last_m_off := m_off; m_len := m_low;
    end;
    if m_len <> 0 then m_len := 1 + getbit
    else if getbit <> 0 then m_len := 3 + getbit
    else begin
      Inc(m_len);
      repeat
        m_len := m_len * 2 + getbit;
        if ilen >= src_len then begin dst_len := olen; Exit(UPX_E_INPUT_OVERRUN) end;
        if m_len >= oend   then begin dst_len := olen; Exit(UPX_E_OUTPUT_OVERRUN) end;
      until getbit = 1;
      Inc(m_len, 3);
    end;
    if m_off > $500 then Inc(m_len);
    if olen + m_len >= oend then begin dst_len := olen; Exit(UPX_E_OUTPUT_OVERRUN) end;
    if m_off > olen then begin dst_len := olen; Exit(UPX_E_LOOKBEHIND_OVERRUN) end;
    m_pos := dst + olen - m_off;
    dst[olen] := m_pos[0]; Inc(olen); Inc(m_pos);
    while m_len > 0 do begin dst[olen] := m_pos[0]; Inc(olen); Inc(m_pos); Dec(m_len) end;
  end;
  dst_len := olen;
  if ilen = src_len then Result := UPX_E_OK
  else if ilen < src_len then Result := UPX_E_INPUT_NOT_CONSUMED
  else Result := UPX_E_INPUT_OVERRUN;
end;

function nrv2e_decompress_le32(src: PByte; src_len: Cardinal;
                               dst: PByte; var dst_len: Cardinal): Integer;
var
  bb, bc: Cardinal;
  ilen, olen, last_m_off: Cardinal;
  oend: Cardinal;
  m_off, m_len, m_low: Cardinal;
  m_pos: PByte;

  function getbit: Cardinal; inline;
  begin
    if bc > 0 then begin Dec(bc); Result := (bb shr bc) and 1 end
    else begin
      bb := Cardinal(src[ilen]) or (Cardinal(src[ilen+1]) shl 8)
          or (Cardinal(src[ilen+2]) shl 16) or (Cardinal(src[ilen+3]) shl 24);
      Inc(ilen, 4); bc := 31;
      Result := (bb shr 31) and 1;
    end;
  end;

begin
  bb := 0; bc := 0; ilen := 0; olen := 0; last_m_off := 1;
  oend := dst_len;
  while True do
  begin
    while getbit = 1 do
    begin
      if ilen >= src_len then begin dst_len := olen; Exit(UPX_E_INPUT_OVERRUN) end;
      if olen >= oend    then begin dst_len := olen; Exit(UPX_E_OUTPUT_OVERRUN) end;
      dst[olen] := src[ilen]; Inc(olen); Inc(ilen);
    end;
    m_off := 1;
    while True do
    begin
      m_off := m_off * 2 + getbit;
      if ilen >= src_len then begin dst_len := olen; Exit(UPX_E_INPUT_OVERRUN) end;
      if m_off > Cardinal($FFFFFF) + 3 then begin dst_len := olen; Exit(UPX_E_LOOKBEHIND_OVERRUN) end;
      if getbit = 1 then Break;
      m_off := (m_off - 1) * 2 + getbit;
    end;
    if m_off = 2 then begin m_off := last_m_off; m_len := getbit end
    else begin
      m_off := (m_off - 3) * 256 + src[ilen]; Inc(ilen);
      if m_off = Cardinal($FFFFFFFF) then Break;
      m_low := (m_off xor Cardinal($FFFFFFFF)) and 1;
      m_off := m_off shr 1; Inc(m_off); last_m_off := m_off; m_len := m_low;
    end;
    if m_len <> 0 then m_len := 1 + getbit
    else if getbit <> 0 then m_len := 3 + getbit
    else begin
      Inc(m_len);
      repeat
        m_len := m_len * 2 + getbit;
        if ilen >= src_len then begin dst_len := olen; Exit(UPX_E_INPUT_OVERRUN) end;
        if m_len >= oend   then begin dst_len := olen; Exit(UPX_E_OUTPUT_OVERRUN) end;
      until getbit = 1;
      Inc(m_len, 3);
    end;
    if m_off > $500 then Inc(m_len);
    if olen + m_len >= oend then begin dst_len := olen; Exit(UPX_E_OUTPUT_OVERRUN) end;
    if m_off > olen then begin dst_len := olen; Exit(UPX_E_LOOKBEHIND_OVERRUN) end;
    m_pos := dst + olen - m_off;
    dst[olen] := m_pos[0]; Inc(olen); Inc(m_pos);
    while m_len > 0 do begin dst[olen] := m_pos[0]; Inc(olen); Inc(m_pos); Dec(m_len) end;
  end;
  dst_len := olen;
  if ilen = src_len then Result := UPX_E_OK
  else if ilen < src_len then Result := UPX_E_INPUT_NOT_CONSUMED
  else Result := UPX_E_INPUT_OVERRUN;
end;

// ── decompression dispatcher ─────────────────────────────────────────────────

function nrv_decompress(src: PByte; src_len: Cardinal;
                        dst: PByte; var dst_len: Cardinal;
                        method: Integer): Integer;
begin
  case method of
    M_NRV2B_8:    Result := nrv2b_decompress_8   (src, src_len, dst, dst_len);
    M_NRV2B_LE16: Result := nrv2b_decompress_le16(src, src_len, dst, dst_len);
    M_NRV2B_LE32: Result := nrv2b_decompress_le32(src, src_len, dst, dst_len);
    M_NRV2D_8:    Result := nrv2d_decompress_8   (src, src_len, dst, dst_len);
    M_NRV2D_LE16: Result := nrv2d_decompress_le16(src, src_len, dst, dst_len);
    M_NRV2D_LE32: Result := nrv2d_decompress_le32(src, src_len, dst, dst_len);
    M_NRV2E_8:    Result := nrv2e_decompress_8   (src, src_len, dst, dst_len);
    M_NRV2E_LE16: Result := nrv2e_decompress_le16(src, src_len, dst, dst_len);
    M_NRV2E_LE32: Result := nrv2e_decompress_le32(src, src_len, dst, dst_len);
  else
    Result := UPX_E_INVALID_ARGUMENT;
  end;
end;

// ═══════════════════════════════════════════════════════════════════════════
//  COMPRESSION SECTION  – NRV2B/2D/2E-99  (sliding window, hash chaining)
//  Translated from vendor/ucl/src/n2_99.ch + ucl_mchw.ch + ucl_swd.ch
// ═══════════════════════════════════════════════════════════════════════════

const
  SWD_F      = 2048;       // max match length
  SWD_HBITS  = 16;
  SWD_HMASK  = (1 shl SWD_HBITS) - 1;   // $FFFF
  SWD_HSIZE  = SWD_HMASK + 1;           // 65536
  SWD_NIL    = $FFFFFFFF;

type
  // SWD index type – using Cardinal (32-bit) because window can reach 8MB
  TSwdIdx = Cardinal;

  TNrvSwd = record
    n: Cardinal;               // window size
    f: Cardinal;               // max match length
    hmask: Cardinal;
    nice_length: Cardinal;
    max_chain: Cardinal;
    // tablice alokowane dynamicznie
    head2: array of TSwdIdx;   // [65536]
    head3: array of TSwdIdx;   // [SWD_HSIZE]
    succ:  array of TSwdIdx;   // [n + f]
    prev:  array of TSwdIdx;   // [n + f]
    buf:   array of Byte;      // copy of input data in the window
    // match state
    b_pos: Cardinal;           // position in input buffer
    rPos:  Cardinal;           // current input position (ip – in)
    look:  Cardinal;           // bytes in lookahead buffer
    m_len: Cardinal;
    m_off: Cardinal;
    last_m_off: Cardinal;
  end;

  // Bufor bitowy (wyjście kompresora)
  TBitBuf = record
    buf:    PByte;             // output
    op:     Cardinal;          // current output offset
    bb_b:   Cardinal;          // current bits
    bb_k:   Integer;           // number of loaded bits
    bb_endian: Integer;        // 0=LE
    bb_size: Integer;          // 8, 16 or 32
    p_pos:  Cardinal;          // position of last bb_flush
  end;

// ── bit-buffer helpers ────────────────────────────────────────────────────────

procedure bb_init(var b: TBitBuf; dst: PByte; bb_size: Integer);
begin
  b.buf    := dst;
  b.op     := 0;
  b.bb_b   := 0;
  b.bb_k   := 0;
  b.bb_endian := 0;
  b.bb_size   := bb_size;
  b.p_pos  := Cardinal($FFFFFFFF);
end;

procedure bb_flush(var b: TBitBuf);
begin
  // Guard: p_pos = $FFFFFFFF means no word has been allocated yet (bb_init state).
  // We must NOT skip when bb_k = 0 – that means the word is FULL (all 32 bits placed)
  // and needs to be written.  The old "if bb_k = 0 then Exit" was wrong: it silently
  // dropped bit 0 of every complete 32-bit word, corrupting the entire bit stream.
  if b.p_pos = Cardinal($FFFFFFFF) then Exit;
  case b.bb_size of
   8: begin
        b.buf[b.p_pos] := Byte(b.bb_b);
      end;
   16: begin
        b.buf[b.p_pos]   := Byte(b.bb_b and $FF);
        b.buf[b.p_pos+1] := Byte((b.bb_b shr 8) and $FF);
      end;
   32: begin
        b.buf[b.p_pos]   := Byte(b.bb_b and $FF);
        b.buf[b.p_pos+1] := Byte((b.bb_b shr 8) and $FF);
        b.buf[b.p_pos+2] := Byte((b.bb_b shr 16) and $FF);
        b.buf[b.p_pos+3] := Byte((b.bb_b shr 24) and $FF);
      end;
  end;
end;

procedure bb_put_bit(var b: TBitBuf; bit: Cardinal);
begin
  if b.bb_k = 0 then
  begin
    // reserve space for bit word
    b.p_pos := b.op;
    Inc(b.op, b.bb_size div 8);
    b.bb_k := b.bb_size;
    b.bb_b := 0;
  end;
  // for LE: filling from LSB
  Dec(b.bb_k);
  b.bb_b := b.bb_b or (bit shl b.bb_k);
  bb_flush(b);
end;

procedure bb_put_byte(var b: TBitBuf; v: Byte);
begin
  b.buf[b.op] := v;
  Inc(b.op);
end;

// ── hash ─────────────────────────────────────────────────────────────────────

function swd_head3(const data: PByte; pos: Cardinal; hmask: Cardinal): Cardinal; inline;
var h: Cardinal;
begin
  h := Cardinal(data[pos]) shl 5;
  h := h xor Cardinal(data[pos+1]);
  h := (h shl 5) xor Cardinal(data[pos+2]);
  h := ($9F5F * h) shr 5;
  Result := h and hmask;
end;

function swd_head2(const data: PByte; pos: Cardinal): Cardinal; inline;
begin
  Result := Cardinal(data[pos]) xor (Cardinal(data[pos+1]) shl 8);
end;

// ── SWD initialization ────────────────────────────────────────────────────────

procedure swd_init(var s: TNrvSwd;
                   n_val: Cardinal; f_val: Cardinal; max_chain_val: Cardinal;
                   nice_len_val: Cardinal);
var i: Cardinal;
begin
  s.n           := n_val;
  s.f           := f_val;
  s.hmask       := SWD_HMASK;
  s.max_chain   := max_chain_val;
  s.nice_length := nice_len_val;
  s.b_pos       := 0;
  s.rPos        := 0;
  s.m_len       := 0;
  s.m_off       := 0;
  s.last_m_off  := 1;
  s.look        := 0;

  // succ/prev store absolute positions in data (indexed by position mod n)
  SetLength(s.head2, SWD_HSIZE);
  SetLength(s.head3, SWD_HSIZE);
  SetLength(s.succ,  n_val + 1);
  SetLength(s.prev,  n_val + 1);
  SetLength(s.buf,   0);  // unused – we keep a pointer to the original data

  for i := 0 to SWD_HSIZE-1 do begin s.head2[i] := SWD_NIL; s.head3[i] := SWD_NIL end;
  for i := 0 to n_val do begin s.succ[i] := SWD_NIL; s.prev[i] := SWD_NIL end;
end;

// ── insert n_val bytes into SWD window (absolute data in data[]) ─────────────

procedure swd_accept(var s: TNrvSwd; data: PByte; data_len: Cardinal;
                     n_accept: Cardinal);
// rPos to absolutna pozycja bajtu dodawanego do okna (= ip przy wywołaniu)
var i: Cardinal; h2, h3: Cardinal; rp: Cardinal; old_h: Cardinal;
begin
  for i := 0 to n_accept - 1 do
  begin
    rp := s.rPos;
    if rp < data_len then
    begin
      // head3: 3-byte chain – key is hash(data[rp..rp+2])
      if rp + 2 < data_len then
      begin
        h3 := swd_head3(data, rp, s.hmask);
        old_h := s.head3[h3];
        s.prev[rp mod s.n] := old_h;   // back pointer: this position → old head
        s.head3[h3] := rp;             // new head = current absolute position
      end;
      // head2: 2-byte chain
      if rp + 1 < data_len then
      begin
        h2 := swd_head2(data, rp) and s.hmask;
        old_h := s.head2[h2];
        s.succ[rp mod s.n] := old_h;
        s.head2[h2] := rp;
      end;
    end;
    Inc(s.rPos);
  end;
end;

// ── find best match ───────────────────────────────────────────────────────────

procedure swd_find_match(var s: TNrvSwd; ip: Cardinal;
                         data: PByte; data_len: Cardinal;
                         max_offset: Cardinal; try_lazy: Integer);
var
  h3: Cardinal;
  cur: Cardinal;
  best_len, cur_len: Cardinal;
  dpos, chain, max_len: Cardinal;
begin
  s.m_len := 1; s.m_off := s.last_m_off;

  if ip + 2 >= data_len then Exit;

  max_len := s.f;
  if ip + max_len > data_len then max_len := data_len - ip;

  h3 := swd_head3(data, ip, s.hmask);
  cur := s.head3[h3];   // absolutna pozycja kandydata
  best_len := 1;
  chain := s.max_chain;

  while (cur <> SWD_NIL) and (chain > 0) do
  begin
    Dec(chain);
    if cur >= ip then Break;      // candidate must be earlier
    dpos := ip - cur;
    if dpos > max_offset then Break;  // too far

    // porównaj bajty
    cur_len := 0;
    while (cur_len < max_len) and (data[ip + cur_len] = data[cur + cur_len]) do
      Inc(cur_len);

    if cur_len > best_len then
    begin
      best_len := cur_len;
      s.m_off  := dpos;
      if cur_len >= s.nice_length then Break;
    end;

    // go to previous candidate in head3 chain
    cur := s.prev[cur mod s.n];
    if cur = SWD_NIL then Break;
  end;

  if best_len >= 2 then s.m_len := best_len;
end;

// ── ss11 prefix encoding (NRV2B) ─────────────────────────────────────────────
// Encodes i (modified Elias gamma)

procedure code_prefix_ss11(var b: TBitBuf; i: Cardinal);
var t: Cardinal;
begin
  if i >= 2 then
  begin
    t := 4; Inc(i, 2);
    while i >= t do t := t shl 1;
    t := t shr 1;
    while t > 2 do
    begin
      t := t shr 1;
      if (i and t) <> 0 then bb_put_bit(b, 1) else bb_put_bit(b, 0);
      bb_put_bit(b, 0);
    end;
  end;
  if (i and 1) <> 0 then bb_put_bit(b, 1) else bb_put_bit(b, 0);
  bb_put_bit(b, 1);
end;

// ── ss12 prefix encoding (NRV2D/2E) ──────────────────────────────────────────

procedure code_prefix_ss12(var b: TBitBuf; i: Cardinal);
var t: Cardinal;
begin
  if i >= 2 then
  begin
    t := 2;
    while i >= t do begin Dec(i, t); t := t shl 2 end;
    while t > 2 do
    begin
      t := t shr 1;
      if (i and t) <> 0 then bb_put_bit(b, 1) else bb_put_bit(b, 0);
      bb_put_bit(b, 0);
      t := t shr 1;
      if (i and t) <> 0 then bb_put_bit(b, 1) else bb_put_bit(b, 0);
    end;
  end;
  if (i and 1) <> 0 then bb_put_bit(b, 1) else bb_put_bit(b, 0);
  bb_put_bit(b, 1);
end;

// ── encode match (NRV2B) ──────────────────────────────────────────────────────

procedure code_match_nrv2b(var b: TBitBuf; var last_m_off: Cardinal;
                           m_len: Cardinal; m_off: Cardinal);
const M2_MAX_OFFSET_2B = $D00;
var adj_len: Cardinal;
begin
  bb_put_bit(b, 0);
  if m_off = last_m_off then
  begin
    bb_put_bit(b, 0); bb_put_bit(b, 1);
  end else begin
    code_prefix_ss11(b, 1 + ((m_off - 1) shr 8));
    bb_put_byte(b, Byte((m_off - 1) and $FF));
  end;
  adj_len := m_len - 1;
  if m_off > M2_MAX_OFFSET_2B then Dec(adj_len);
  if adj_len >= 4 then
  begin
    bb_put_bit(b, 0); bb_put_bit(b, 0);
    code_prefix_ss11(b, adj_len - 4);
  end else begin
    if adj_len > 1 then bb_put_bit(b, 1) else bb_put_bit(b, 0);
    if (adj_len and 1) <> 0 then bb_put_bit(b, 1) else bb_put_bit(b, 0);
  end;
  last_m_off := m_off;
end;

// ── encode match (NRV2D) ──────────────────────────────────────────────────────

procedure code_match_nrv2d(var b: TBitBuf; var last_m_off: Cardinal;
                           m_len: Cardinal; m_off: Cardinal);
const M2_MAX_OFFSET_2D = $500;
var adj_len, m_low: Cardinal;
begin
  bb_put_bit(b, 0);
  adj_len := m_len - 1;
  if m_off > M2_MAX_OFFSET_2D then Dec(adj_len);
  m_low := adj_len; if m_low >= 4 then m_low := 0;
  if m_off = last_m_off then
  begin
    bb_put_bit(b, 0); bb_put_bit(b, 1);
    if m_low > 1 then bb_put_bit(b, 1) else bb_put_bit(b, 0);
    if (m_low and 1) <> 0 then bb_put_bit(b, 1) else bb_put_bit(b, 0);
  end else begin
    code_prefix_ss12(b, 1 + ((m_off - 1) shr 7));
    bb_put_byte(b, Byte((((m_off - 1) and $7F) shl 1) or (Cardinal(m_low <= 1))));
    if (m_low and 1) <> 0 then bb_put_bit(b, 1) else bb_put_bit(b, 0);
  end;
  if adj_len >= 4 then code_prefix_ss11(b, adj_len - 4);
  last_m_off := m_off;
end;

// ── encode match (NRV2E) ──────────────────────────────────────────────────────

procedure code_match_nrv2e(var b: TBitBuf; var last_m_off: Cardinal;
                           m_len: Cardinal; m_off: Cardinal);
const M2_MAX_OFFSET_2E = $500;
var adj_len: Cardinal; m_low: Boolean;
begin
  bb_put_bit(b, 0);
  adj_len := m_len - 1;
  if m_off > M2_MAX_OFFSET_2E then Dec(adj_len);
  m_low := adj_len <= 2;
  if m_off = last_m_off then
  begin
    bb_put_bit(b, 0); bb_put_bit(b, 1);
    if m_low then bb_put_bit(b, 1) else bb_put_bit(b, 0);
  end else begin
    code_prefix_ss12(b, 1 + ((m_off - 1) shr 7));
    bb_put_byte(b, Byte((((m_off - 1) and $7F) shl 1) or Cardinal(not m_low)));
  end;
  if m_low then
    bb_put_bit(b, adj_len - 1)
  else if adj_len <= 4 then
  begin
    bb_put_bit(b, 1); bb_put_bit(b, adj_len - 3);
  end else begin
    bb_put_bit(b, 0);
    code_prefix_ss11(b, adj_len - 5);
  end;
  last_m_off := m_off;
end;

// ── encode literals ───────────────────────────────────────────────────────────

procedure code_run(var b: TBitBuf; data: PByte; start: Cardinal; lit: Cardinal);
var i: Cardinal;
begin
  for i := 0 to lit - 1 do
  begin
    bb_put_bit(b, 1);
    bb_put_byte(b, data[start + i]);
  end;
end;

// ── check if match is worth coding (returns -1 if not, else cost in bits)

function len_of_coded_match_nrv2b(m_len: Cardinal; m_off: Cardinal;
                                   last_m_off: Cardinal): Integer;
const M2B = $D00;
var b: Integer; t: Cardinal;
begin
  if m_len < 2 then begin Result := -1; Exit end;
  if (m_len = 2) and (m_off > M2B) then begin Result := -1; Exit end;
  b := 0;
  if m_off = last_m_off then b := 1 + 2
  else begin
    b := 1 + 10;
    t := (m_off - 1) shr 8;
    while t > 0 do begin Inc(b, 2); t := t shr 1 end;
  end;
  m_len := m_len - 2;
  if m_off > M2B then Dec(m_len);
  Inc(b, 2);
  if m_len < 3 then begin Result := b; Exit end;
  Dec(m_len, 3);
  repeat Inc(b, 2); m_len := m_len shr 1 until m_len = 0;
  Result := b;
end;

function len_of_coded_match_nrv2de(m_len: Cardinal; m_off: Cardinal;
                                    last_m_off: Cardinal;
                                    is_nrv2e: Boolean): Integer;
const M2DE = $500;
var b: Integer; t: Cardinal;
begin
  if m_len < 2 then begin Result := -1; Exit end;
  if (m_len = 2) and (m_off > M2DE) then begin Result := -1; Exit end;
  b := 0;
  if m_off = last_m_off then b := 1 + 2
  else begin
    b := 1 + 9;
    t := (m_off - 1) shr 7;
    while t > 0 do begin Inc(b, 3); t := t shr 2 end;
  end;
  m_len := m_len - 2;
  if m_off > M2DE then Dec(m_len);
  Inc(b, 2);
  if not is_nrv2e then begin
    if m_len < 3 then begin Result := b; Exit end;
    Dec(m_len, 3);
  end else begin
    if m_len < 2 then begin Result := b; Exit end;
    if m_len < 4 then begin Result := b + 1; Exit end;
    Dec(m_len, 4);
  end;
  repeat Inc(b, 2); m_len := m_len shr 1 until m_len = 0;
  Result := b;
end;

// ── main compression loop ─────────────────────────────────────────────────────

type
  TNrvVariant = (nvNRV2B, nvNRV2D, nvNRV2E);

const
  SWD_CFG: array[1..10] of record
    try_lazy: Integer;
    nice_len: Cardinal;
    max_chain: Cardinal;
    max_offset: Cardinal;
  end = (
    // level1
    (try_lazy:0; nice_len:8;    max_chain:4;    max_offset:48*1024),
    // level2
    (try_lazy:0; nice_len:16;   max_chain:8;    max_offset:48*1024),
    // level3
    (try_lazy:0; nice_len:32;   max_chain:16;   max_offset:48*1024),
    // level4
    (try_lazy:1; nice_len:16;   max_chain:16;   max_offset:48*1024),
    // level5
    (try_lazy:1; nice_len:32;   max_chain:32;   max_offset:48*1024),
    // level6
    (try_lazy:1; nice_len:128;  max_chain:128;  max_offset:48*1024),
    // level7
    (try_lazy:2; nice_len:128;  max_chain:256;  max_offset:128*1024),
    // level8
    (try_lazy:2; nice_len:SWD_F; max_chain:2048; max_offset:128*1024),
    // level9
    (try_lazy:2; nice_len:SWD_F; max_chain:2048; max_offset:256*1024),
    // level10
    (try_lazy:2; nice_len:SWD_F; max_chain:4096; max_offset:8*1024*1024)
  );

function nrv_compress_internal(src: PByte; src_len: Cardinal;
                               dst: PByte; var dst_len: Cardinal;
                               level: Integer; bb_size: Integer;
                               variant: TNrvVariant): Integer;
var
  s: TNrvSwd;
  b: TBitBuf;
  sc_try_lazy: Integer;
  sc_max_off: Cardinal;
  ip: Cardinal;          // current input position
  ii: Cardinal;          // start of literal run
  lit: Cardinal;         // number of literals
  m_len, m_off: Cardinal;
  last_m_off: Cardinal;
  m_len2, m_off2: Cardinal;
  cost1, cost2: Integer;
begin
  if (level < 1) or (level > 10) then begin Result := UPX_E_INVALID_ARGUMENT; Exit end;
  if src_len = 0 then begin dst_len := 0; Result := UPX_E_OK; Exit end;

  sc_try_lazy := SWD_CFG[level].try_lazy;
  sc_max_off  := SWD_CFG[level].max_offset;

  swd_init(s, sc_max_off, SWD_F,
           SWD_CFG[level].max_chain, SWD_CFG[level].nice_len);

  bb_init(b, dst, bb_size);

  ip := 0; ii := 0; lit := 0;
  last_m_off := 1;

  while ip < src_len do
  begin
    // find match at position ip
    swd_find_match(s, ip, src, src_len, sc_max_off, sc_try_lazy);
    m_len := s.m_len; m_off := s.m_off;

    // check profitability
    case variant of
      nvNRV2B: cost1 := len_of_coded_match_nrv2b(m_len, m_off, last_m_off);
      nvNRV2D: cost1 := len_of_coded_match_nrv2de(m_len, m_off, last_m_off, False);
      nvNRV2E: cost1 := len_of_coded_match_nrv2de(m_len, m_off, last_m_off, True);
    else cost1 := -1;
    end;

    // lazy matching
    if (cost1 >= 0) and (sc_try_lazy > 0) and (ip + 1 < src_len) then
    begin
      swd_find_match(s, ip + 1, src, src_len, sc_max_off, 0);
      m_len2 := s.m_len; m_off2 := s.m_off;
      case variant of
        nvNRV2B: cost2 := len_of_coded_match_nrv2b(m_len2, m_off2, last_m_off);
        nvNRV2D: cost2 := len_of_coded_match_nrv2de(m_len2, m_off2, last_m_off, False);
        nvNRV2E: cost2 := len_of_coded_match_nrv2de(m_len2, m_off2, last_m_off, True);
      else cost2 := -1;
      end;
      // 8 + 8 (literal + match from ip+1) vs cost1
      if (cost2 >= 0) and (8 + 8 + cost2 < cost1 + 8) then
      begin
        cost1 := -1; // force literal at ip, match from ip+1
      end;
    end;

    if cost1 < 0 then
    begin
      // literal
      swd_accept(s, src, src_len, 1);
      Inc(lit); Inc(ip);
    end else begin
      // encode accumulated literals
      if lit > 0 then code_run(b, src, ii, lit);
      ii := ip + m_len; lit := 0;
      // encode match
      case variant of
        nvNRV2B: code_match_nrv2b(b, last_m_off, m_len, m_off);
        nvNRV2D: code_match_nrv2d(b, last_m_off, m_len, m_off);
        nvNRV2E: code_match_nrv2e(b, last_m_off, m_len, m_off);
      end;
      swd_accept(s, src, src_len, m_len);
      Inc(ip, m_len);
    end;
  end;

  // remaining literals
  if lit > 0 then code_run(b, src, ii, lit);

  // end marker: offset = $FFFFFFFF
  // Decoder checks: m_off = (m_off_decoded - 3) * 256 + byte
  // For m_off = $FFFFFFFF: need m_off_decoded = $01000002, byte = $FF
  // code_prefix_ss11 with val=$01000000 → decoder gives m_off_decoded = val+2 = $01000002
  // (1 + ((UINT32_MAX - 3) shr 8) = 1 + $00FFFFFF = $01000000)
  // Same for NRV2D/2E: code_prefix_ss12 with val=$02000000
  bb_put_bit(b, 0);
  case variant of
    nvNRV2B: begin
               code_prefix_ss11(b, Cardinal($01000000));
               bb_put_byte(b, $FF);
             end;
    nvNRV2D,
    nvNRV2E: begin
               code_prefix_ss12(b, Cardinal($02000000));
               bb_put_byte(b, $FF);
             end;
  end;

  // align bit buffer (flush last word)
  bb_flush(b);

  dst_len := b.op;
  if dst_len >= src_len then Result := UPX_E_NOT_COMPRESSIBLE
  else Result := UPX_E_OK;
end;

// ── public compression functions ─────────────────────────────────────────────

function nrv2b_compress(src: PByte; src_len: Cardinal;
                        dst: PByte; var dst_len: Cardinal;
                        level: Integer; bb_size: Integer): Integer;
begin
  Result := nrv_compress_internal(src, src_len, dst, dst_len, level, bb_size, nvNRV2B);
end;

function nrv2d_compress(src: PByte; src_len: Cardinal;
                        dst: PByte; var dst_len: Cardinal;
                        level: Integer; bb_size: Integer): Integer;
begin
  Result := nrv_compress_internal(src, src_len, dst, dst_len, level, bb_size, nvNRV2D);
end;

function nrv2e_compress(src: PByte; src_len: Cardinal;
                        dst: PByte; var dst_len: Cardinal;
                        level: Integer; bb_size: Integer): Integer;
begin
  Result := nrv_compress_internal(src, src_len, dst, dst_len, level, bb_size, nvNRV2E);
end;

function nrv_compress(src: PByte; src_len: Cardinal;
                      dst: PByte; var dst_len: Cardinal;
                      method: Integer; level: Integer): Integer;
var bb_size: Integer; variant: TNrvVariant;
begin
  case method of
    M_NRV2B_LE32: begin variant := nvNRV2B; bb_size := 32 end;
    M_NRV2B_8:    begin variant := nvNRV2B; bb_size := 8  end;
    M_NRV2B_LE16: begin variant := nvNRV2B; bb_size := 16 end;
    M_NRV2D_LE32: begin variant := nvNRV2D; bb_size := 32 end;
    M_NRV2D_8:    begin variant := nvNRV2D; bb_size := 8  end;
    M_NRV2D_LE16: begin variant := nvNRV2D; bb_size := 16 end;
    M_NRV2E_LE32: begin variant := nvNRV2E; bb_size := 32 end;
    M_NRV2E_8:    begin variant := nvNRV2E; bb_size := 8  end;
    M_NRV2E_LE16: begin variant := nvNRV2E; bb_size := 16 end;
  else
    begin Result := UPX_E_INVALID_ARGUMENT; Exit end;
  end;
  Result := nrv_compress_internal(src, src_len, dst, dst_len, level, bb_size, variant);
end;

end.
