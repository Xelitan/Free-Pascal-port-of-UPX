{$mode delphi}
{$POINTERMATH ON}
unit upx_packhead;


// UPX Pascal Port
// License: GNU GPL
// Author: www.xelitan.com
//
//  PackHeader (compressed block header)
//  Translated from src/packhead.h + src/packhead.cpp
//  Header format: see src/stub/src/include/header.S
//
//  File structure (version >= 10, format >= 128 i.e. big-endian = Mach-O/PPC):
//    [0..3]  "UPX!" (magic LE32 = $21585055)
//    [4..7]  magic2 ($D5D0D8A1)
//    [4]     version
//    [5]     format
//    [6]     method
//    [7]     level
//    --- for LE (format < 128) ---
//    [8..11]  u_adler32
//    [12..15] c_adler32
//    [16..19] u_len  (LE32)
//    [20..23] c_len  (LE32)
//    [24..27] u_file_size (LE32)
//    [28]     filter
//    [29]     filter_cto
//    [30]     n_mru-1 (lub 0)
//    [31]     header_checksum
//    --- for BE (format >= 128) ---
//    [8..11]  u_len  (BE32)
//    [12..15] c_len  (BE32)
//    [16..19] u_adler32 (BE32)
//    [20..23] c_adler32 (BE32)
//    [24..27] u_file_size (BE32)
//    [28..30] filter, filter_cto, n_mru
//    [31]     header_checksum


interface

uses upx_types;

const
  PACK_HEADER_SIZE = 32;   // size for format >= 10, non-DOS

type
  TPackHeader = record
    version:     Integer;
    format:      Integer;
    method:      Integer;
    level:       Integer;
    u_len:       Cardinal;
    c_len:       Cardinal;
    u_adler:     Cardinal;
    c_adler:     Cardinal;
    u_file_size: Cardinal;
    filter:      Integer;
    filter_cto:  Integer;
    n_mru:       Integer;
    header_checksum: Integer;
    // informational field set by decode
    buf_offset:  Cardinal;
  end;

procedure PackHeader_Reset(var ph: TPackHeader);

// write header to dst buffer (must contain magic at the start)
procedure PackHeader_Put(const ph: TPackHeader; dst: PByte);

// read header from buffer (searches for UPX_MAGIC_LE32)
// returns True if found and decoded, False if no magic
function PackHeader_Decode(var ph: TPackHeader; buf: PByte; blen: Integer): Boolean;

// header size depending on version/format
function PackHeader_GetSize(const ph: TPackHeader): Integer;

implementation

procedure PackHeader_Reset(var ph: TPackHeader);
begin
  FillChar(ph, SizeOf(ph), 0);
  ph.version := -1;
  ph.format  := -1;
end;

// Header checksum (from byte 4 to size-2)
function GetChecksum(p: PByte; size: Integer): Byte;
var i, c: Integer;
begin
  Assert(GetLE32(p) = UPX_MAGIC_LE32);
  c := 0;
  p := p + 4;
  for i := 0 to size - 5 do
  begin
    Inc(c, p[i]);
  end;
  Result := Byte(c mod 251);
end;

function PackHeader_GetSize(const ph: TPackHeader): Integer;
begin
  if ph.version <= 3 then begin Result := 24; Exit end;
  if ph.version <= 9 then
  begin
    if (ph.format = UPX_F_DOS_COM) or (ph.format = UPX_F_DOS_SYS) then Result := 20
    else if ph.format = UPX_F_DOS_EXE then Result := 25
    else Result := 28;
    Exit;
  end;
  // version >= 10
  if (ph.format = UPX_F_DOS_COM) or (ph.format = UPX_F_DOS_SYS) then Result := 22
  else if ph.format = UPX_F_DOS_EXE then Result := 27
  else Result := 32;
end;

procedure PackHeader_Put(const ph: TPackHeader; dst: PByte);
var size: Integer; old_chk: Byte;
begin
  Assert(GetLE32(dst) = UPX_MAGIC_LE32);
  Assert(GetLE32(dst+4) = UPX_MAGIC2_LE32);

  size := PackHeader_GetSize(ph);

  dst[4] := Byte(ph.version);
  dst[5] := Byte(ph.format);
  dst[6] := Byte(ph.method);
  dst[7] := Byte(ph.level);

  if ph.format < 128 then
  begin
    // little-endian
    SetLE32(dst+8,  ph.u_adler);
    SetLE32(dst+12, ph.c_adler);
    if (ph.format = UPX_F_DOS_COM) or (ph.format = UPX_F_DOS_SYS) then
    begin
      SetLE16(dst+16, Word(ph.u_len));
      SetLE16(dst+18, Word(ph.c_len));
      dst[20] := Byte(ph.filter);
    end else if ph.format = UPX_F_DOS_EXE then
    begin
      // LE24 – 3 bytes
      dst[16] := Byte(ph.u_len); dst[17] := Byte(ph.u_len shr 8); dst[18] := Byte(ph.u_len shr 16);
      dst[19] := Byte(ph.c_len); dst[20] := Byte(ph.c_len shr 8); dst[21] := Byte(ph.c_len shr 16);
      dst[22] := Byte(ph.u_file_size); dst[23] := Byte(ph.u_file_size shr 8);
      dst[24] := Byte(ph.u_file_size shr 16);
      dst[25] := Byte(ph.filter);
    end else begin
      SetLE32(dst+16, ph.u_len);
      SetLE32(dst+20, ph.c_len);
      SetLE32(dst+24, ph.u_file_size);
      dst[28] := Byte(ph.filter);
      dst[29] := Byte(ph.filter_cto);
      if ph.n_mru > 0 then dst[30] := Byte(ph.n_mru - 1) else dst[30] := 0;
    end;
  end else begin
    // big-endian (e.g. Mach-O PPC)
    SetBE32(dst+8,  ph.u_len);
    SetBE32(dst+12, ph.c_len);
    SetBE32(dst+16, ph.u_adler);
    SetBE32(dst+20, ph.c_adler);
    SetBE32(dst+24, ph.u_file_size);
    dst[28] := Byte(ph.filter);
    dst[29] := Byte(ph.filter_cto);
    if ph.n_mru > 0 then dst[30] := Byte(ph.n_mru - 1) else dst[30] := 0;
  end;

  // set checksum
  old_chk := GetChecksum(dst, size - 1);
  // verify old checksum if it was set
  if dst[size-1] <> 0 then
    Assert(dst[size-1] = old_chk);
  dst[size-1] := GetChecksum(dst, size - 1);
end;

function PackHeader_Decode(var ph: TPackHeader; buf: PByte; blen: Integer): Boolean;
var
  boff: Integer;
  p: PByte;
  size, off_filter: Integer;
  i: Integer;
begin
  Result := False;
  // find magic
  boff := -1;
  for i := 0 to blen - 4 do
    if GetLE32(buf + i) = UPX_MAGIC_LE32 then begin boff := i; Break end;
  if boff < 0 then Exit;

  p := buf + boff;
  blen := blen - boff;
  if blen < 20 then Exit; // too short

  ph.version    := p[4];
  ph.format     := p[5];
  ph.method     := p[6];
  ph.level      := p[7];
  ph.filter_cto := 0;
  off_filter    := 0;

  if ph.format < 128 then
  begin
    ph.u_adler := GetLE32(p+8);
    ph.c_adler := GetLE32(p+12);
    if (ph.format = UPX_F_DOS_COM) or (ph.format = UPX_F_DOS_SYS) then
    begin
      ph.u_len       := GetLE16(p+16);
      ph.c_len       := GetLE16(p+18);
      ph.u_file_size := ph.u_len;
      off_filter := 20;
    end else if (ph.format = UPX_F_DOS_EXE) then
    begin
      if blen < 25 then Exit;
      ph.u_len       := Cardinal(p[16]) or (Cardinal(p[17]) shl 8) or (Cardinal(p[18]) shl 16);
      ph.c_len       := Cardinal(p[19]) or (Cardinal(p[20]) shl 8) or (Cardinal(p[21]) shl 16);
      ph.u_file_size := Cardinal(p[22]) or (Cardinal(p[23]) shl 8) or (Cardinal(p[24]) shl 16);
      off_filter := 25;
    end else begin
      if blen < 31 then Exit;
      ph.u_len       := GetLE32(p+16);
      ph.c_len       := GetLE32(p+20);
      ph.u_file_size := GetLE32(p+24);
      off_filter := 28;
      ph.filter_cto := p[29];
      if p[30] <> 0 then ph.n_mru := 1 + p[30] else ph.n_mru := 0;
    end;
  end else begin
    if blen < 31 then Exit;
    ph.u_len       := GetBE32(p+8);
    ph.c_len       := GetBE32(p+12);
    ph.u_adler     := GetBE32(p+16);
    ph.c_adler     := GetBE32(p+20);
    ph.u_file_size := GetBE32(p+24);
    off_filter := 28;
    ph.filter_cto := p[29];
    if p[30] <> 0 then ph.n_mru := 1 + p[30] else ph.n_mru := 0;
  end;

  if ph.version >= 10 then
  begin
    if blen < off_filter + 1 then Exit;
    ph.filter := p[off_filter];
  end else if (ph.level and 128) = 0 then
    ph.filter := 0
  else begin
    ph.level := ph.level and 127;
    if (ph.format = UPX_F_DOS_COM) or (ph.format = UPX_F_DOS_SYS) then
      ph.filter := $06
    else
      ph.filter := $26;
  end;
  ph.level := ph.level and 15;

  if ph.version = $FF then Exit; // "cannot unpack UPX ;-)"

  // checksum verification
  if ph.version >= 10 then
  begin
    size := PackHeader_GetSize(ph);
    if (size > blen) or (p[size-1] <> GetChecksum(p, size - 1)) then Exit;
  end;

  if (ph.c_len < 2) or (ph.u_len < 2) then Exit;

  ph.buf_offset := Cardinal(boff);
  Result := True;
end;

end.
