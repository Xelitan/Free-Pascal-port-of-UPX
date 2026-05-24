{$mode delphi}
{$POINTERMATH ON}
unit upx_filter;

// UPX Pascal Port
// License: GNU GPL
// Author: www.xelitan.com
//
//  UPX Pascal port — complete filter library (all 60 filters)
//  Translated from UPX 5.1.1 src/filter/ (C) Markus Oberhumer, Laszlo Molnar, John F. Reiser — GPL v2+
//
//  Filter IDs implemented:
//    0x00            no filter
//    0x01-0x09       CT16 (naive 16-bit call trick)
//    0x0A-0x0C       SW16 (16-bit swap trick)
//    0x0D-0x0E       CTSW16 (call+swap combo)
//    0x11-0x19       CT32 (naive 32-bit call trick)
//    0x1A-0x1C       SW32 (32-bit swap trick)
//    0x1D-0x1E       CTSW32 (call+swap combo)
//    0x24-0x26       CTO32 (CTO range-check, bswap_le)
//    0x36, 0x46      CTOJ32 (CTO + JMP)
//    0x49            CTOK32 (CTO + JMP + optional JCC)
//    0x50-0x51       ARM24 LE/BE (ARM BL call trick)
//    0x52            ARM26 LE  (ARM64 B/BL call trick)
//    0x55            AUIPC     (RISC-V AUIPC+JALR)
//    0x80-0x87       CTOJR32   (CTO + JCC + MRU renumbering)
//    0x90-0x93       Sub8      (delta 8-bit, N=1..4)
//    0xA0-0xA3       Sub16     (delta 16-bit, N=1..4)
//    0xB0-0xB3       Sub32     (delta 32-bit, N=1..4)
//    0xD0            PPC       (PowerPC branch trick, W_CTO=4)
//
//  addvalue = 0 throughout (buffer always at offset 0 from segment start).


interface

uses upx_types;

const
  UPX_FILTER_NONE              = $00;
  UPX_FILTER_CT16_E8           = $01;
  UPX_FILTER_CT16_E9           = $02;
  UPX_FILTER_CT16_E8E9         = $03;
  UPX_FILTER_CT16_E8_BSWPLE    = $04;
  UPX_FILTER_CT16_E9_BSWPLE    = $05;
  UPX_FILTER_CT16_E8E9_BSWPLE  = $06;
  UPX_FILTER_CT16_E8_BSWPBE    = $07;
  UPX_FILTER_CT16_E9_BSWPBE    = $08;
  UPX_FILTER_CT16_E8E9_BSWPBE  = $09;
  UPX_FILTER_SW16_E8           = $0A;
  UPX_FILTER_SW16_E9           = $0B;
  UPX_FILTER_SW16_E8E9         = $0C;
  UPX_FILTER_CTSW16_E8_E9      = $0D;
  UPX_FILTER_CTSW16_E9_E8      = $0E;
  UPX_FILTER_CT32_E8           = $11;
  UPX_FILTER_CT32_E9           = $12;
  UPX_FILTER_CT32_E8E9         = $13;
  UPX_FILTER_CT32_E8_BSWPLE    = $14;
  UPX_FILTER_CT32_E9_BSWPLE    = $15;
  UPX_FILTER_CT32_E8E9_BSWPLE  = $16;
  UPX_FILTER_CT32_E8_BSWPBE    = $17;
  UPX_FILTER_CT32_E9_BSWPBE    = $18;
  UPX_FILTER_CT32_E8E9_BSWPBE  = $19;
  UPX_FILTER_SW32_E8           = $1A;
  UPX_FILTER_SW32_E9           = $1B;
  UPX_FILTER_SW32_E8E9         = $1C;
  UPX_FILTER_CTSW32_E8_E9      = $1D;
  UPX_FILTER_CTSW32_E9_E8      = $1E;
  UPX_FILTER_CTO32_E8          = $24;
  UPX_FILTER_CTO32_E9          = $25;
  UPX_FILTER_CTO32_E8E9        = $26;
  UPX_FILTER_CTOJ32_36         = $36;
  UPX_FILTER_CTOJ32_46         = $46;
  UPX_FILTER_CTOK32            = $49;
  UPX_FILTER_CT24ARM_LE        = $50;
  UPX_FILTER_CT24ARM_BE        = $51;
  UPX_FILTER_CT26ARM_LE        = $52;
  UPX_FILTER_AUIPC             = $55;
  UPX_FILTER_CTOJR_80          = $80;
  UPX_FILTER_CTOJR_81          = $81;
  UPX_FILTER_CTOJR_82          = $82;
  UPX_FILTER_CTOJR_83          = $83;
  UPX_FILTER_CTOJR_84          = $84;
  UPX_FILTER_CTOJR_85          = $85;
  UPX_FILTER_CTOJR_86          = $86;
  UPX_FILTER_CTOJR_87          = $87;
  UPX_FILTER_SUB8_1            = $90;
  UPX_FILTER_SUB8_2            = $91;
  UPX_FILTER_SUB8_3            = $92;
  UPX_FILTER_SUB8_4            = $93;
  UPX_FILTER_SUB16_1           = $A0;
  UPX_FILTER_SUB16_2           = $A1;
  UPX_FILTER_SUB16_3           = $A2;
  UPX_FILTER_SUB16_4           = $A3;
  UPX_FILTER_SUB32_1           = $B0;
  UPX_FILTER_SUB32_2           = $B1;
  UPX_FILTER_SUB32_3           = $B2;
  UPX_FILTER_SUB32_4           = $B3;
  UPX_FILTER_PPC               = $D0;

  // alias used by callers (ELF/Mach-O x86 < 16 MB)
  UPX_FILTER_X86_E8E9          = UPX_FILTER_CTO32_E8E9;  // $26

// Apply filter in-place.
//   cto_out: receives the CTO marker byte (0 for non-CTO filters).
//   Returns False if filter cannot be applied (buffer too large for CTO or
//   no free marker byte found).
function ApplyFilter(buf: PByte; len: Cardinal; filter_id: Integer;
                     out cto_out: Byte): Boolean;

// Reverse filter in-place.
//   cto: ph.filter_cto from the pack header (0 for non-CTO filters).
function ApplyUnfilter(buf: PByte; len: Cardinal; filter_id: Integer;
                       cto: Byte): Boolean;

implementation

// ── extra endianness helpers (not in upx_types) ───────────────────────────────

function GetBE16(p: PByte): Word; inline;
begin
  Result := (Word(p[0]) shl 8) or Word(p[1]);
end;

procedure SetBE16(p: PByte; v: Word); inline;
begin
  p[0] := (v shr 8) and $FF;
  p[1] := v and $FF;
end;

// ARM 24-bit LE: bytes 0..2 of a 4-byte LE instruction
function GetLE24(p: PByte): Cardinal; inline;
begin
  Result := Cardinal(p[0]) or (Cardinal(p[1]) shl 8) or (Cardinal(p[2]) shl 16);
end;

procedure SetLE24(p: PByte; v: Cardinal); inline;
begin
  p[0] := v and $FF;
  p[1] := (v shr 8) and $FF;
  p[2] := (v shr 16) and $FF;
end;

// ARM 24-bit BE: bytes 1..3 of a 4-byte BE instruction
function GetBE24(p: PByte): Cardinal; inline;
begin
  Result := (Cardinal(p[1]) shl 16) or (Cardinal(p[2]) shl 8) or Cardinal(p[3]);
end;

procedure SetBE24(p: PByte; v: Cardinal); inline;
begin
  p[1] := (v shr 16) and $FF;
  p[2] := (v shr 8) and $FF;
  p[3] := v and $FF;
end;

// ARM64 26-bit LE: bits 25:0 of LE32 (B/BL offset field)
function GetLE26(p: PByte): Cardinal; inline;
begin
  Result := GetLE32(p) and $03FFFFFF;
end;

procedure SetLE26(p: PByte; v: Cardinal); inline;
var
  w: Cardinal;
begin
  w := GetLE32(p);
  SetLE32(p, (w and $FC000000) or (v and $03FFFFFF));
end;

// ── getCTO helpers ─────────────────────────────────────────────────────────────
// Scans for a byte value that is never used as the first operand byte of an
// out-of-range call/branch, so it can serve as an unambiguous CTO marker.

function GetCTO_E8E9(buf: PByte; len: Cardinal;
                     want_e8, want_e9: Boolean): Integer;
var
  used: array[0..255] of Byte;
  ic, jc: Cardinal;
  found: Integer;
begin
  FillChar(used, SizeOf(used), 0);
  if len >= 5 then
  begin
    ic := 0;
    while ic <= len - 5 do
    begin
      if (want_e8 and (buf[ic] = $E8)) or (want_e9 and (buf[ic] = $E9)) then
      begin
        jc := GetLE32(buf + ic + 1) + ic + 1;
        if jc >= len then
          used[buf[ic + 1]] := 1;
      end;
      Inc(ic);
    end;
  end;
  found := -1;
  ic := 0;
  while ic <= 255 do
  begin
    if used[ic] = 0 then begin found := ic; Break; end;
    Inc(ic);
  end;
  Result := found;
end;

function GetCTO_WithJCC(buf: PByte; len: Cardinal;
                        want_jcc: Boolean): Integer;
// Like GetCTO_E8E9(E8E9) but also considers out-of-range JCC (0F 80-8F).
var
  used: array[0..255] of Byte;
  ic, jc: Cardinal;
  found: Integer;
  lastcall: Cardinal;
begin
  FillChar(used, SizeOf(used), 0);
  lastcall := 0;
  if len >= 5 then
  begin
    ic := 0;
    while ic <= len - 5 do
    begin
      if (buf[ic] = $E8) or (buf[ic] = $E9) then
      begin
        jc := GetLE32(buf + ic + 1) + ic + 1;
        if jc >= len then
          used[buf[ic + 1]] := 1;
      end
      else if want_jcc and (ic >= 1) and (lastcall <> ic)
           and (buf[ic - 1] = $0F)
           and (buf[ic] >= $80) and (buf[ic] <= $8F) then
      begin
        jc := GetLE32(buf + ic + 1) + ic + 1;
        if jc >= len then
          used[buf[ic + 1]] := 1;
      end;
      Inc(ic);
    end;
  end;
  found := -1;
  ic := 0;
  while ic <= 255 do
  begin
    if used[ic] = 0 then begin found := ic; Break; end;
    Inc(ic);
  end;
  Result := found;
end;

// ── CT16 ──────────────────────────────────────────────────────────────────────
// Naive 16-bit call trick.  b_end = buf+len-3; scan byte-by-byte; operand 2 bytes.
// add_a=True: filter (add offset a); False: unfilter (subtract).
// rd_be/wr_be: False=LE encoding, True=BE encoding for the 16-bit operand.

procedure CT16_impl(buf: PByte; len: Cardinal;
                    want_e8, want_e9, rd_be, wr_be, add_a: Boolean);
var
  i, a: Cardinal;
  v: Word;
begin
  if len < 4 then Exit;
  i := 0;
  while i <= len - 4 do
  begin
    if (want_e8 and (buf[i] = $E8)) or (want_e9 and (buf[i] = $E9)) then
    begin
      a := i + 1;
      if rd_be then v := GetBE16(buf + i + 1)
      else           v := GetLE16(buf + i + 1);
      if add_a then v := Word(v + Word(a))
      else          v := Word(v - Word(a));
      if wr_be then SetBE16(buf + i + 1, v)
      else          SetLE16(buf + i + 1, v);
      Inc(i, 3);
    end
    else
      Inc(i);
  end;
end;

// ── SW16 ──────────────────────────────────────────────────────────────────────
// Swap LE↔BE in the 2-byte operand (no address addition).

procedure SW16_impl(buf: PByte; len: Cardinal;
                    want_e8, want_e9: Boolean;
                    rd_le_wr_be: Boolean);
var
  i: Cardinal;
  v: Word;
begin
  if len < 4 then Exit;
  i := 0;
  while i <= len - 4 do
  begin
    if (want_e8 and (buf[i] = $E8)) or (want_e9 and (buf[i] = $E9)) then
    begin
      if rd_le_wr_be then
      begin
        v := GetLE16(buf + i + 1);
        SetBE16(buf + i + 1, v);
      end
      else
      begin
        v := GetBE16(buf + i + 1);
        SetLE16(buf + i + 1, v);
      end;
      Inc(i, 3);
    end
    else
      Inc(i);
  end;
end;

// ── CTSW16 ───────────────────────────────────────────────────────────────────
// ct_op gets calltrick (add/subtract + BE write), sw_op gets swaptrick.

procedure CTSW16_impl(buf: PByte; len: Cardinal;
                      ct_is_e8, add_a: Boolean);
var
  i, a: Cardinal;
  v: Word;
  ct_op, sw_op: Byte;
begin
  if len < 4 then Exit;
  if ct_is_e8 then begin ct_op := $E8; sw_op := $E9; end
  else              begin ct_op := $E9; sw_op := $E8; end;
  i := 0;
  while i <= len - 4 do
  begin
    if buf[i] = ct_op then
    begin
      a := i + 1;
      v := GetLE16(buf + i + 1);
      if add_a then v := Word(v + Word(a)) else v := Word(v - Word(a));
      SetBE16(buf + i + 1, v);
      Inc(i, 3);
    end
    else if buf[i] = sw_op then
    begin
      if add_a then begin v := GetLE16(buf+i+1); SetBE16(buf+i+1, v); end
      else           begin v := GetBE16(buf+i+1); SetLE16(buf+i+1, v); end;
      Inc(i, 3);
    end
    else
      Inc(i);
  end;
end;

// ── CT32 ──────────────────────────────────────────────────────────────────────
// b_end = buf+len-5; 4-byte operand at buf[i+1..i+4].

procedure CT32_impl(buf: PByte; len: Cardinal;
                    want_e8, want_e9, rd_be, wr_be, add_a: Boolean);
var
  i, a, v: Cardinal;
begin
  if len < 6 then Exit;
  i := 0;
  while i <= len - 6 do
  begin
    if (want_e8 and (buf[i] = $E8)) or (want_e9 and (buf[i] = $E9)) then
    begin
      a := i + 1;
      if rd_be then v := GetBE32(buf + i + 1) else v := GetLE32(buf + i + 1);
      if add_a then v := v + a else v := v - a;
      if wr_be then SetBE32(buf + i + 1, v) else SetLE32(buf + i + 1, v);
      Inc(i, 5);
    end
    else
      Inc(i);
  end;
end;

// ── SW32 ──────────────────────────────────────────────────────────────────────

procedure SW32_impl(buf: PByte; len: Cardinal;
                    want_e8, want_e9: Boolean;
                    rd_le_wr_be: Boolean);
var
  i, v: Cardinal;
begin
  if len < 6 then Exit;
  i := 0;
  while i <= len - 6 do
  begin
    if (want_e8 and (buf[i] = $E8)) or (want_e9 and (buf[i] = $E9)) then
    begin
      if rd_le_wr_be then begin v := GetLE32(buf+i+1); SetBE32(buf+i+1, v); end
      else                begin v := GetBE32(buf+i+1); SetLE32(buf+i+1, v); end;
      Inc(i, 5);
    end
    else
      Inc(i);
  end;
end;

// ── CTSW32 ───────────────────────────────────────────────────────────────────

procedure CTSW32_impl(buf: PByte; len: Cardinal;
                      ct_is_e8, add_a: Boolean);
var
  i, a, v: Cardinal;
  ct_op, sw_op: Byte;
begin
  if len < 6 then Exit;
  if ct_is_e8 then begin ct_op := $E8; sw_op := $E9; end
  else              begin ct_op := $E9; sw_op := $E8; end;
  i := 0;
  while i <= len - 6 do
  begin
    if buf[i] = ct_op then
    begin
      a := i + 1;
      v := GetLE32(buf + i + 1);
      if add_a then v := v + a else v := v - a;
      SetBE32(buf + i + 1, v);
      Inc(i, 5);
    end
    else if buf[i] = sw_op then
    begin
      if add_a then begin v := GetLE32(buf+i+1); SetBE32(buf+i+1, v); end
      else           begin v := GetBE32(buf+i+1); SetLE32(buf+i+1, v); end;
      Inc(i, 5);
    end
    else
      Inc(i);
  end;
end;

// ── CTO32 filter/unfilter ─────────────────────────────────────────────────────
// For in-range calls (jc < len AND jc < 16 MB): stores the absolute target
// address in big-endian with cto8 as the high byte.
// Conflict check: if the overlapping previous instruction also looks filtered,
// roll back and treat the current call as a non-call.

function CTO32_Filter(buf: PByte; len: Cardinal;
                      want_e8, want_e9: Boolean;
                      out cto8: Byte): Boolean;
var
  cto_val: Integer;
  cto: Cardinal;
  ic, jc, kc: Cardinal;
  lastnoncall: Cardinal;
  did_conflict: Boolean;
begin
  Result := False;
  cto_val := GetCTO_E8E9(buf, len, want_e8, want_e9);
  if cto_val < 0 then Exit;
  cto8 := Byte(cto_val);
  cto := Cardinal(cto8) shl 24;
  lastnoncall := len;
  if len < 5 then begin Result := True; Exit; end;
  ic := 0;
  while ic <= len - 5 do
  begin
    if not ((want_e8 and (buf[ic] = $E8)) or (want_e9 and (buf[ic] = $E9))) then
    begin
      Inc(ic); Continue;
    end;
    jc := GetLE32(buf + ic + 1) + ic + 1;
    if jc < len then
    begin
      if jc >= $1000000 then begin Result := False; Exit; end;
      SetBE32(buf + ic + 1, jc + cto);
      did_conflict := False;
      if (lastnoncall <= ic) and (ic - lastnoncall < 5) then
      begin
        kc := 4;
        while kc >= 1 do
        begin
          if ic >= kc then
          begin
            if ((want_e8 and (buf[ic - kc] = $E8)) or
                (want_e9 and (buf[ic - kc] = $E9)))
               and (buf[ic - kc + 1] = cto8) then
            begin
              SetLE32(buf + ic + 1, jc - ic - 1);
              if buf[ic + 1] = cto8 then begin Result := False; Exit; end;
              lastnoncall := ic;
              did_conflict := True;
              Break;
            end;
          end;
          Dec(kc);
        end;
      end;
      if did_conflict then begin Inc(ic); Continue; end;
      Inc(ic, 4);
    end
    else
      lastnoncall := ic;
    Inc(ic);
  end;
  Result := True;
end;

procedure CTO32_Unfilter(buf: PByte; len: Cardinal;
                         want_e8, want_e9: Boolean;
                         cto8: Byte);
var
  cto: Cardinal;
  ic, jc: Cardinal;
begin
  cto := Cardinal(cto8) shl 24;
  if len < 5 then Exit;
  ic := 0;
  while ic <= len - 5 do
  begin
    if (want_e8 and (buf[ic] = $E8)) or (want_e9 and (buf[ic] = $E9)) then
    begin
      if buf[ic + 1] = cto8 then
      begin
        jc := GetBE32(buf + ic + 1);
        SetLE32(buf + ic + 1, jc - ic - 1 - cto);
        Inc(ic, 4);
      end;
    end;
    Inc(ic);
  end;
end;

// ── CTOJ32 (0x36, 0x46) ──────────────────────────────────────────────────────
// Identical to CTO32 E8E9 for our addvalue=0 case (the lastcall parameter in
// the C COND macro is only relevant for the overlap-conflict scan, which we
// already handle correctly in CTO32_Filter).

function CTOJ32_Filter(buf: PByte; len: Cardinal; out cto8: Byte): Boolean;
begin
  Result := CTO32_Filter(buf, len, True, True, cto8);
end;

procedure CTOJ32_Unfilter(buf: PByte; len: Cardinal; cto8: Byte);
begin
  CTO32_Unfilter(buf, len, True, True, cto8);
end;

// ── CTOK32 (0x49) ────────────────────────────────────────────────────────────
// Like CTO32 E8E9 but also processes 2-byte Jcc (0F 80-8F prefix form) when
// the id nibble >= 9.  For 0x49: nibble=9 >= 9, so JCC is enabled.
// The Jcc operand is at buf[ic+1] (ic points to the 0x80-0x8F condition byte).

function CTOK32_Filter(buf: PByte; len: Cardinal; id: Byte; out cto8: Byte): Boolean;
var
  cto_val: Integer;
  cto: Cardinal;
  ic, jc, kc: Cardinal;
  lastnoncall: Cardinal;
  lastcall: Cardinal;
  want_jcc: Boolean;
  did_conflict: Boolean;

  function MatchHere(pos: Cardinal): Boolean;
  begin
    Result := (buf[pos] = $E8) or (buf[pos] = $E9)
           or (want_jcc and (pos >= 1) and (lastcall <> pos)
               and (buf[pos-1] = $0F)
               and (buf[pos] >= $80) and (buf[pos] <= $8F));
  end;

begin
  Result := False;
  want_jcc := (id and $0F) >= 9;
  cto_val := GetCTO_WithJCC(buf, len, want_jcc);
  if cto_val < 0 then Exit;
  cto8 := Byte(cto_val);
  cto := Cardinal(cto8) shl 24;
  lastnoncall := len;
  lastcall := 0;
  if len < 5 then begin Result := True; Exit; end;
  ic := 0;
  while ic <= len - 5 do
  begin
    if not MatchHere(ic) then begin Inc(ic); Continue; end;
    jc := GetLE32(buf + ic + 1) + ic + 1;
    if jc < len then
    begin
      if jc >= $1000000 then begin Result := False; Exit; end;
      SetBE32(buf + ic + 1, jc + cto);
      did_conflict := False;
      if (lastnoncall <= ic) and (ic - lastnoncall < 5) then
      begin
        kc := 4;
        while kc >= 1 do
        begin
          if ic >= kc then
          begin
            if MatchHere(ic - kc) and (buf[ic - kc + 1] = cto8) then
            begin
              SetLE32(buf + ic + 1, jc - ic - 1);
              if buf[ic + 1] = cto8 then begin Result := False; Exit; end;
              lastnoncall := ic;
              did_conflict := True;
              Break;
            end;
          end;
          Dec(kc);
        end;
      end;
      if did_conflict then begin Inc(ic); Continue; end;
      lastcall := ic + 1;
      Inc(ic, 4);
    end
    else
      lastnoncall := ic;
    Inc(ic);
  end;
  Result := True;
end;

procedure CTOK32_Unfilter(buf: PByte; len: Cardinal; id: Byte; cto8: Byte);
var
  cto: Cardinal;
  ic, jc: Cardinal;
  lastcall: Cardinal;
  want_jcc: Boolean;

  function MatchHere(pos: Cardinal): Boolean;
  begin
    Result := (buf[pos] = $E8) or (buf[pos] = $E9)
           or (want_jcc and (pos >= 1) and (lastcall <> pos)
               and (buf[pos-1] = $0F)
               and (buf[pos] >= $80) and (buf[pos] <= $8F));
  end;

begin
  cto := Cardinal(cto8) shl 24;
  want_jcc := (id and $0F) >= 9;
  lastcall := 0;
  if len < 5 then Exit;
  ic := 0;
  while ic <= len - 5 do
  begin
    if MatchHere(ic) then
    begin
      if buf[ic + 1] = cto8 then
      begin
        jc := GetBE32(buf + ic + 1);
        SetLE32(buf + ic + 1, jc - ic - 1 - cto);
        lastcall := ic + 1;
        Inc(ic, 4);
      end;
    end;
    Inc(ic);
  end;
end;

// ── CTOJR32 (0x80-0x87) ──────────────────────────────────────────────────────
// CTO with JCC opcode-swap AND optional MRU renumbering of call destinations.
//
// id nibble n (0..7) determines per-instruction-type filter mode:
//   f_call = (1+n) mod 3;  f_jmp1 = ((1+n)/3) mod 3;  f_jcc2 = f_jmp1
//   0=NOFILT, 1=FNOMRU (plain CTO write), 2=MRUFLT (MRU index write).
//
// CONDF (filter pass): E8 (which=0), E9 (which=1), or 0F→8x at ic-1→ic (which=2).
// CONDU (unfilter pass): E8 (which=0), E9 (which=1), or 8x→0F at ic-1→ic (which=2).
//   (In filter pass the 0x0F/0x8x pair is swapped; unfilter sees them swapped.)
//
// JCC opcode-swap: during filter, swap buf[ic-1]↔buf[ic] before writing dest.
//                  during unfilter, swap buf[ic-1]↔buf[ic] after reading dest.
//
// MRU: N_MRU=32 slot circular buffer.  If dest already in MRU, store index<<1;
//      otherwise store (dest<<1)|1 and push dest to MRU head.

const
  CTOJR_N_MRU = 32;
  CTOJR_NOFILT = 0;
  CTOJR_FNOMRU = 1;
  CTOJR_MRUFLT = 2;

procedure ctojr_update_mru(jc: Cardinal; kh: Integer;
                            var mru: array of Cardinal;
                            var hand, tail: Integer);
var
  t, t2: Cardinal;
begin
  Dec(hand);
  if hand < 0 then hand := CTOJR_N_MRU - 1;
  t := mru[hand];
  if t <> 0 then
    mru[kh] := t
  else
  begin
    Dec(tail);
    if tail < 0 then tail := CTOJR_N_MRU - 1;
    t2 := mru[tail];
    mru[tail] := 0;
    mru[kh] := t2;
  end;
  mru[hand] := jc;
end;

function CTOJR32_Filter(buf: PByte; len: Cardinal; id: Byte; out cto8: Byte): Boolean;
var
  cto_val: Integer;
  cto: Cardinal;
  ic, jc, kc: Cardinal;
  lastnoncall: Cardinal;
  lastcall: Cardinal;
  nibble, f_call, f_jmp1, f_jcc2: Integer;
  which: Integer;
  f_on: Boolean;
  did_conflict: Boolean;
  mru: array[0..CTOJR_N_MRU - 1] of Cardinal;
  hand, tail, k, kh: Integer;
  t_byte: Byte;

  function MatchF(pos: Cardinal; var wh: Integer): Boolean;
  begin
    wh := -1;
    if buf[pos] = $E8 then begin wh := 0; Result := True; Exit; end;
    if buf[pos] = $E9 then begin wh := 1; Result := True; Exit; end;
    if (pos >= 1) and (lastcall <> pos)
       and (buf[pos - 1] = $0F)
       and (buf[pos] >= $80) and (buf[pos] <= $8F) then
    begin
      wh := 2; Result := True; Exit;
    end;
    Result := False;
  end;

begin
  Result := False;
  nibble := id and $0F;
  f_call := (1 + nibble) mod 3;
  f_jmp1 := ((1 + nibble) div 3) mod 3;
  f_jcc2 := f_jmp1;
  cto_val := GetCTO_WithJCC(buf, len, True);
  if cto_val < 0 then Exit;
  cto8 := Byte(cto_val);
  cto := Cardinal(cto8) shl 24;
  FillChar(mru, SizeOf(mru), 0);
  hand := 0; tail := 0;
  lastnoncall := len;
  lastcall := 0;
  if len < 5 then begin Result := True; Exit; end;
  ic := 0;
  while ic <= len - 5 do
  begin
    if not MatchF(ic, which) then begin Inc(ic); Continue; end;
    jc := GetLE32(buf + ic + 1) + ic + 1;
    f_on := False;
    did_conflict := False;
    if jc < len then
    begin
      if jc >= $1000000 then begin Result := False; Exit; end;
      // JCC opcode swap (filter direction: 0F is at ic-1, 8x at ic → swap)
      if (which = 2) and (f_jcc2 <> CTOJR_NOFILT) then
      begin
        t_byte := buf[ic - 1];
        buf[ic - 1] := buf[ic];
        buf[ic] := t_byte;
      end;
      // determine if this instruction type is filtered
      if ((which = 0) and (f_call = CTOJR_MRUFLT))
      or ((which = 1) and (f_jmp1 = CTOJR_MRUFLT))
      or ((which = 2) and (f_jcc2 = CTOJR_MRUFLT)) then
      begin
        f_on := True;
        k := 0; kh := 0;
        while k < CTOJR_N_MRU do
        begin
          kh := hand + k;
          if kh >= CTOJR_N_MRU then Dec(kh, CTOJR_N_MRU);
          if mru[kh] = jc then
          begin
            SetBE32(buf + ic + 1, Cardinal(k shl 1) + cto);
            ctojr_update_mru(jc, kh, mru, hand, tail);
            Break;
          end;
          Inc(k);
        end;
        if k = CTOJR_N_MRU then
        begin
          SetBE32(buf + ic + 1, Cardinal((jc shl 1) or 1) + cto);
          Dec(hand);
          if hand < 0 then hand := CTOJR_N_MRU - 1;
          mru[hand] := jc;
        end;
      end
      else if ((which = 0) and (f_call <> CTOJR_NOFILT))
           or ((which = 1) and (f_jmp1 <> CTOJR_NOFILT))
           or ((which = 2) and (f_jcc2 <> CTOJR_NOFILT)) then
      begin
        f_on := True;
        SetBE32(buf + ic + 1, jc + cto);
      end;
      if f_on then
      begin
        if (lastnoncall <= ic) and (ic - lastnoncall < 5) then
        begin
          kc := 4;
          while kc >= 1 do
          begin
            if ic >= kc then
            begin
              if MatchF(ic - kc, which) and (buf[ic - kc + 1] = cto8) then
              begin
                // undo JCC swap
                if (which = 2) and (f_jcc2 <> CTOJR_NOFILT) then
                begin
                  t_byte := buf[ic - 1];
                  buf[ic - 1] := buf[ic];
                  buf[ic] := t_byte;
                end;
                SetLE32(buf + ic + 1, jc - ic - 1);
                if buf[ic + 1] = cto8 then begin Result := False; Exit; end;
                lastnoncall := ic;
                did_conflict := True;
                Break;
              end;
            end;
            Dec(kc);
          end;
        end;
        if did_conflict then begin Inc(ic); Continue; end;
        lastcall := ic + 1;
        Inc(ic, 4);
      end;
    end
    else
      lastnoncall := ic;
    Inc(ic);
  end;
  Result := True;
end;

procedure CTOJR32_Unfilter(buf: PByte; len: Cardinal; id: Byte; cto8: Byte);
var
  cto: Cardinal;
  ic, jc: Cardinal;
  lastcall: Cardinal;
  nibble, f_call, f_jmp1, f_jcc2: Integer;
  which: Integer;
  mru: array[0..CTOJR_N_MRU - 1] of Cardinal;
  hand, tail, kh: Integer;
  t_byte: Byte;
  f_on: Boolean;
  jc_raw: Cardinal;

  function MatchU(pos: Cardinal; var wh: Integer): Boolean;
  begin
    wh := -1;
    if buf[pos] = $E8 then begin wh := 0; Result := True; Exit; end;
    if buf[pos] = $E9 then begin wh := 1; Result := True; Exit; end;
    // After filter, prefix 0x0F was swapped to pos, 0x8x is now at pos-1
    if (pos >= 1) and (lastcall <> pos)
       and (buf[pos] = $0F)
       and (buf[pos - 1] >= $80) and (buf[pos - 1] <= $8F) then
    begin
      wh := 2; Result := True; Exit;
    end;
    Result := False;
  end;

begin
  cto := Cardinal(cto8) shl 24;
  nibble := id and $0F;
  f_call := (1 + nibble) mod 3;
  f_jmp1 := ((1 + nibble) div 3) mod 3;
  f_jcc2 := f_jmp1;
  FillChar(mru, SizeOf(mru), 0);
  hand := 0; tail := 0;
  lastcall := 0;
  if len < 5 then Exit;
  ic := 0;
  while ic <= len - 5 do
  begin
    if not MatchU(ic, which) then begin Inc(ic); Continue; end;
    if buf[ic + 1] = cto8 then
    begin
      f_on := False;
      jc_raw := GetBE32(buf + ic + 1) - cto;
      if ((which = 0) and (f_call = CTOJR_MRUFLT))
      or ((which = 1) and (f_jmp1 = CTOJR_MRUFLT))
      or ((which = 2) and (f_jcc2 = CTOJR_MRUFLT)) then
      begin
        f_on := True;
        if (jc_raw and 1) = 1 then
        begin
          jc := jc_raw shr 1;
          Dec(hand);
          if hand < 0 then hand := CTOJR_N_MRU - 1;
          mru[hand] := jc;
        end
        else
        begin
          kh := Integer(jc_raw shr 1) + hand;
          if kh >= CTOJR_N_MRU then Dec(kh, CTOJR_N_MRU);
          jc := mru[kh];
          ctojr_update_mru(jc, kh, mru, hand, tail);
        end;
        SetLE32(buf + ic + 1, jc - ic - 1);
      end
      else if ((which = 0) and (f_call <> CTOJR_NOFILT))
           or ((which = 1) and (f_jmp1 <> CTOJR_NOFILT))
           or ((which = 2) and (f_jcc2 <> CTOJR_NOFILT)) then
      begin
        f_on := True;
        jc := jc_raw;
        SetLE32(buf + ic + 1, jc - ic - 1);
      end;
      // unswap JCC
      if (which = 2) and (f_jcc2 <> CTOJR_NOFILT) then
      begin
        t_byte := buf[ic - 1];
        buf[ic - 1] := buf[ic];
        buf[ic] := t_byte;
      end;
      if f_on then
      begin
        lastcall := ic + 1;
        Inc(ic, 4);
      end;
    end;
    Inc(ic);
  end;
end;

// ── ARM24 LE (0x50) ───────────────────────────────────────────────────────────
// COND: (buf[i+3] & 0x0F) == 0x0B  — ARM BL (any condition code), LE word.
// Operand: 24-bit signed offset at bytes 0..2 of the 4-byte instruction.
// addvalue = i/4 (word index = position / 4).

procedure ARM24LE_Filter(buf: PByte; len: Cardinal);
var
  i, v: Cardinal;
begin
  if len < 8 then Exit;
  i := 0;
  while i <= len - 8 do
  begin
    if (buf[i + 3] and $0F) = $0B then
    begin
      v := GetLE24(buf + i) + (i div 4);
      SetLE24(buf + i, v);
    end;
    Inc(i, 4);
  end;
end;

procedure ARM24LE_Unfilter(buf: PByte; len: Cardinal);
var
  i, v: Cardinal;
begin
  if len < 8 then Exit;
  i := 0;
  while i <= len - 8 do
  begin
    if (buf[i + 3] and $0F) = $0B then
    begin
      v := GetLE24(buf + i) - (i div 4);
      SetLE24(buf + i, v);
    end;
    Inc(i, 4);
  end;
end;

// ── ARM24 BE (0x51) ───────────────────────────────────────────────────────────
// COND: (buf[i+0] & 0x0F) == 0x0B  — ARM BE BL.
// Operand: 24-bit at bytes 1..3.

procedure ARM24BE_Filter(buf: PByte; len: Cardinal);
var
  i, v: Cardinal;
begin
  if len < 8 then Exit;
  i := 0;
  while i <= len - 8 do
  begin
    if (buf[i] and $0F) = $0B then
    begin
      v := GetBE24(buf + i) + (i div 4);
      SetBE24(buf + i, v);
    end;
    Inc(i, 4);
  end;
end;

procedure ARM24BE_Unfilter(buf: PByte; len: Cardinal);
var
  i, v: Cardinal;
begin
  if len < 8 then Exit;
  i := 0;
  while i <= len - 8 do
  begin
    if (buf[i] and $0F) = $0B then
    begin
      v := GetBE24(buf + i) - (i div 4);
      SetBE24(buf + i, v);
    end;
    Inc(i, 4);
  end;
end;

// ── ARM26 LE (0x52) ───────────────────────────────────────────────────────────
// COND: (buf[i+3] & 0x7C) == 0x14  — ARM64 B or BL (bits 30:26 = 00101).
// Operand: 26-bit field bits[25:0] of LE32.  addvalue = i/4.

procedure ARM26LE_Filter(buf: PByte; len: Cardinal);
var
  i, v: Cardinal;
begin
  if len < 8 then Exit;
  i := 0;
  while i <= len - 8 do
  begin
    if (buf[i + 3] and $7C) = $14 then
    begin
      v := GetLE26(buf + i) + (i div 4);
      SetLE26(buf + i, v);
    end;
    Inc(i, 4);
  end;
end;

procedure ARM26LE_Unfilter(buf: PByte; len: Cardinal);
var
  i, v: Cardinal;
begin
  if len < 8 then Exit;
  i := 0;
  while i <= len - 8 do
  begin
    if (buf[i + 3] and $7C) = $14 then
    begin
      v := GetLE26(buf + i) - (i div 4);
      SetLE26(buf + i, v);
    end;
    Inc(i, 4);
  end;
end;

// ── RISC-V AUIPC (0x55) ───────────────────────────────────────────────────────
// AUIPC (opcode 0x17) followed by JALR/ADDI/LOAD using the same rd register.
// The 8-byte pair is re-encoded to store the absolute target address.
//
// Filter:
//   word1 = LE32[ic];  r_aui = word1[11:7]
//   word2 = LE32[ic+4]
//   addr  = (word1 & ~0xFFF) + SignExt12(word2>>20) + ic
//   Encode:
//     buf[ic]     = ((addr&1)<<7) | 0x17
//     BE32[ic+1]  = addr   (stores 4 bytes starting at byte-offset 1)
//     LE32[ic+4]  = (word2<<12) | (r_aui<<7) | ((addr>>1)&0x7F)
//
// Unfilter:
//   word1 = LE32[ic]; check opcode==0x17
//   word2 = LE32[ic+4]; r_aui = word2[11:7]
//   Check CONDu: opcode of rotated word2 == JALR/ADDI/LOAD using rs1=r_aui
//   addr  = reconstruct from BE32[ic+1] with bit correction
//   Restore word1 = (addr&~0xFFF)|(r_aui<<7)|0x17
//   Restore word2 = (addr<<20)|(word2>>12)

function AUIPC_get_ilen(b0: Byte): Integer;
begin
  Result := 2;
  if (b0 and $03) = $03 then
  begin
    Inc(Result, 2);
    if (b0 and $1C) = $1C then  // 6+ bytes (NYI for our purposes)
      Inc(Result, 2);
  end;
end;

function AUIPC_Filter(buf: PByte; len: Cardinal; out cto_out: Byte): Boolean;
var
  ic, ilen, jc, kc: Integer;
  size: Integer;
  gi: Integer;
  gang: array[0..24] of Integer;
  b2: Byte;
  word1, word2, addr, r_aui: LongInt;
begin
  cto_out := 0;
  Result := True;
  if Integer(len) < 9 then Exit;
  size := Integer(len) - 8;
  ic := 0;
  ilen := 0;
  while ic <= size do
  begin
    b2 := buf[ic];
    if (b2 and $7F) <> $17 then
    begin
      ilen := AUIPC_get_ilen(b2);
      Inc(ic, ilen);
      Continue;
    end;
    // Build the gang of AUIPC instructions whose shadows overlap
    gi := 1;
    gang[0] := ic;
    jc := ic;
    ilen := 4;
    while True do
    begin
      kc := 4 + jc;
      if kc > size then Break;
      b2 := buf[kc];
      if (b2 and $7F) = $17 then
      begin
        if gi < 25 then begin gang[gi] := kc; Inc(gi); end;
        jc := kc;
        Continue;
      end;
      if AUIPC_get_ilen(b2) = 2 then
      begin
        kc := 6 + jc;
        if kc <= size then
        begin
          b2 := buf[kc];
          if (b2 and $7F) = $17 then
          begin
            if gi < 25 then begin gang[gi] := kc; Inc(gi); end;
            jc := kc;
            Continue;
          end;
        end;
      end;
      ilen := (AUIPC_get_ilen(buf[4 + jc]) + 4 + jc) - ic;
      Break;
    end;
    // Process gang in reverse order
    Dec(gi);
    while gi >= 0 do
    begin
      jc := gang[gi];
      word1 := LongInt(GetLE32(buf + jc));
      r_aui := (word1 shr 7) and $1F;
      word2 := LongInt(GetLE32(buf + jc + 4));
      // addr = upper 20 bits of word1 + sign-extend 12-bit imm from word2 + position
      addr := word1 and LongInt($FFFFF000);
      addr := addr + (word2 shr 20);  // arithmetic shr on LongInt sign-extends
      addr := addr + jc;
      // encode into buffer
      buf[jc] := Byte(((addr and 1) shl 7) or $17);
      SetBE32(buf + jc + 1, Cardinal(addr));
      SetLE32(buf + jc + 4,
        Cardinal((word2 shl 12) or (r_aui shl 7) or ((addr shr 1) and $7F)));
      Dec(gi);
    end;
    Inc(ic, ilen);
  end;
end;

function AUIPC_Unfilter(buf: PByte; len: Cardinal): Boolean;
var
  ic, ilen: Integer;
  size: Integer;
  word1, word2, addr, r_aui, opc2, func3: LongInt;
begin
  Result := True;
  if Integer(len) < 9 then Exit;
  size := Integer(len) - 8;
  ic := 0;
  while ic <= size do
  begin
    word1 := LongInt(GetLE32(buf + ic));
    if (word1 and $7F) <> $17 then
    begin
      ilen := AUIPC_get_ilen(Byte(word1));
      Inc(ic, ilen);
      Continue;
    end;
    word2 := LongInt(GetLE32(buf + ic + 4));
    r_aui := (word2 shr 7) and $1F;
    // CONDu: check opcode of rotated word2 (opu = opf(word2>>12))
    opc2  := (word2 shr 12) and $7F;
    func3 := (word2 shr 24) and $07;
    if not (((opc2 = $03))
         or ((opc2 = $67) and (func3 = 0))
         or ((opc2 = $13) and (func3 = 0)))
    then
    begin
      Inc(ic, 4);
      Continue;
    end;
    // Reconstruct addr from big-endian at offset 1
    addr := LongInt(GetBE32(buf + ic + 1));
    // re-insert the low bit stored in buf[ic] bit 7
    addr := (addr and LongInt($FFFFFF00))
          or LongInt(LongInt((addr and $7F) shl 1) or LongInt((word1 shr 7) and 1));
    addr := addr - ic;
    // correct for 12-bit sign extension: if bit 11 of imm is set, the upper 20 bits
    // of word1 were one higher; undo that
    if (addr and $800) <> 0 then
      addr := addr + $1000;
    // restore
    SetLE32(buf + ic,
      Cardinal((addr and LongInt($FFFFF000)) or (r_aui shl 7) or $17));
    SetLE32(buf + ic + 4,
      Cardinal((addr shl 20) or LongInt(Cardinal(word2) shr 12)));
    Inc(ic, 4);
  end;
end;

// ── Delta filters ─────────────────────────────────────────────────────────────
// N interleaved channels (N=1..4).  Sub8/Sub16/Sub32 differ only in element size.
// Filter: element[i] -= prev_element[same_channel]; (running delta)
// Unfilter: element[i] += accumulated_element[same_channel]; (running sum)

procedure Sub8_Filter(buf: PByte; len: Cardinal; N: Integer);
var
  d: array[0..3] of Byte;
  i, ch: Integer;
  v: Byte;
begin
  FillChar(d, SizeOf(d), 0);
  ch := N - 1;
  i := 0;
  while i < Integer(len) do
  begin
    v := buf[i] - d[ch];
    buf[i] := v;
    d[ch] := d[ch] + v;
    Dec(ch);
    if ch < 0 then ch := N - 1;
    Inc(i);
  end;
end;

procedure Sub8_Unfilter(buf: PByte; len: Cardinal; N: Integer);
var
  d: array[0..3] of Byte;
  i, ch: Integer;
begin
  FillChar(d, SizeOf(d), 0);
  ch := N - 1;
  i := 0;
  while i < Integer(len) do
  begin
    d[ch] := d[ch] + buf[i];
    buf[i] := d[ch];
    Dec(ch);
    if ch < 0 then ch := N - 1;
    Inc(i);
  end;
end;

procedure Sub16_Filter(buf: PByte; len: Cardinal; N: Integer);
var
  d: array[0..3] of Word;
  i, ch: Integer;
  count: Cardinal;
  v: Word;
begin
  FillChar(d, SizeOf(d), 0);
  ch := N - 1;
  count := len div 2;
  i := 0;
  while i < Integer(count) do
  begin
    v := Word(GetLE16(buf + i * 2) - d[ch]);
    SetLE16(buf + i * 2, v);
    d[ch] := d[ch] + v;
    Dec(ch);
    if ch < 0 then ch := N - 1;
    Inc(i);
  end;
end;

procedure Sub16_Unfilter(buf: PByte; len: Cardinal; N: Integer);
var
  d: array[0..3] of Word;
  i, ch: Integer;
  count: Cardinal;
begin
  FillChar(d, SizeOf(d), 0);
  ch := N - 1;
  count := len div 2;
  i := 0;
  while i < Integer(count) do
  begin
    d[ch] := d[ch] + GetLE16(buf + i * 2);
    SetLE16(buf + i * 2, d[ch]);
    Dec(ch);
    if ch < 0 then ch := N - 1;
    Inc(i);
  end;
end;

procedure Sub32_Filter(buf: PByte; len: Cardinal; N: Integer);
var
  d: array[0..3] of Cardinal;
  i, ch: Integer;
  count: Cardinal;
  v: Cardinal;
begin
  FillChar(d, SizeOf(d), 0);
  ch := N - 1;
  count := len div 4;
  i := 0;
  while i < Integer(count) do
  begin
    v := GetLE32(buf + i * 4) - d[ch];
    SetLE32(buf + i * 4, v);
    d[ch] := d[ch] + v;
    Dec(ch);
    if ch < 0 then ch := N - 1;
    Inc(i);
  end;
end;

procedure Sub32_Unfilter(buf: PByte; len: Cardinal; N: Integer);
var
  d: array[0..3] of Cardinal;
  i, ch: Integer;
  count: Cardinal;
begin
  FillChar(d, SizeOf(d), 0);
  ch := N - 1;
  count := len div 4;
  i := 0;
  while i < Integer(count) do
  begin
    d[ch] := d[ch] + GetLE32(buf + i * 4);
    SetLE32(buf + i * 4, d[ch]);
    Dec(ch);
    if ch < 0 then ch := N - 1;
    Inc(i);
  end;
end;

// ── PowerPC branch trick (0xD0) ───────────────────────────────────────────────
// COND: bits 31:26 of BE32 word == 18 (PPC unconditional/conditional branch).
// W_CTO = 4: 4-bit CTO nibble stored in bits 25:22 of the filtered instruction.
// Only applied to the first PPC_SIZE_LIMIT (4 MB) bytes.
//
// Filter:
//   off = SignExt26(word & 0x03FFFFFF);  jc = (off & ~3) + ic
//   if jc < size: word' = (word & 0xFC000003) | (jc + cto8<<22)
// Unfilter:
//   if bits[25:22] == cto8: jc = word & 0x3FFFFC
//   word' = (word & 0xFC000003) | ((jc - ic) & 0x03FFFFFC)

const
  PPC_SIZE_LIMIT = $400000;   // 4 MB limit for W_CTO=4

function GetCTO_PPC(buf: PByte; size: Cardinal): Integer;
var
  used: array[0..15] of Byte;  // 4-bit CTO → 16 possible values
  ic, size4: Cardinal;
  word, off26, jc: Cardinal;
  found: Integer;
begin
  FillChar(used, SizeOf(used), 0);
  if size < 8 then begin Result := 0; Exit; end;
  size4 := size - 4;
  ic := 0;
  while ic <= size4 do
  begin
    word := GetBE32(buf + ic);
    if word shr 26 = 18 then
    begin
      off26 := word and $03FFFFFF;
      if (off26 and $02000000) <> 0 then
        off26 := off26 or $FC000000;  // sign-extend 26→32 bit
      jc := (off26 and $FFFFFFFC) + ic;
      if jc >= size then
        used[(off26 shr 22) and $0F] := 1;
    end;
    Inc(ic, 4);
  end;
  found := -1;
  ic := 0;
  while ic <= 15 do
  begin
    if used[ic] = 0 then begin found := ic; Break; end;
    Inc(ic);
  end;
  Result := found;
end;

function PPC_Filter(buf: PByte; len: Cardinal; out cto8: Byte): Boolean;
var
  cto_val: Integer;
  cto: Cardinal;
  ic, size4: Cardinal;
  word, off26, jc: Cardinal;
  size: Cardinal;
begin
  Result := False;
  size := len;
  if size > PPC_SIZE_LIMIT then size := PPC_SIZE_LIMIT;
  cto_val := GetCTO_PPC(buf, size);
  if cto_val < 0 then Exit;
  cto8 := Byte(cto_val);
  cto := Cardinal(cto8) shl 22;
  if size < 8 then begin Result := True; Exit; end;
  size4 := size - 4;
  ic := 0;
  while ic <= size4 do
  begin
    word := GetBE32(buf + ic);
    if word shr 26 = 18 then
    begin
      off26 := word and $03FFFFFF;
      if (off26 and $02000000) <> 0 then
        off26 := off26 or $FC000000;
      jc := (off26 and $FFFFFFFC) + ic;
      if jc < size then
        SetBE32(buf + ic, (word and $FC000003) or ((jc + cto) and $03FFFFFC));
    end;
    Inc(ic, 4);
  end;
  Result := True;
end;

procedure PPC_Unfilter(buf: PByte; len: Cardinal; cto8: Byte);
var
  ic, size4: Cardinal;
  word, jc: Cardinal;
  size: Cardinal;
begin
  size := len;
  if size > PPC_SIZE_LIMIT then size := PPC_SIZE_LIMIT;
  if size < 8 then Exit;
  size4 := size - 4;
  ic := 0;
  while ic <= size4 do
  begin
    word := GetBE32(buf + ic);
    if word shr 26 = 18 then
    begin
      if ((word shr 22) and $0F) = Cardinal(cto8) then
      begin
        jc := word and $3FFFFC;  // bits 21:2
        SetBE32(buf + ic,
          (word and $FC000003) or (Cardinal(LongInt(jc) - LongInt(ic)) and $03FFFFFC));
      end;
    end;
    Inc(ic, 4);
  end;
end;

// ── Public dispatch ────────────────────────────────────────────────────────────

function ApplyFilter(buf: PByte; len: Cardinal; filter_id: Integer;
                     out cto_out: Byte): Boolean;
begin
  cto_out := 0;
  Result := True;
  case filter_id of
    // CT16 naive
    $01: CT16_impl(buf,len,True, False,False,False,True);
    $02: CT16_impl(buf,len,False,True, False,False,True);
    $03: CT16_impl(buf,len,True, True, False,False,True);
    $04: CT16_impl(buf,len,True, False,False,True, True);   // bswap_le: rd=LE,wr=BE
    $05: CT16_impl(buf,len,False,True, False,True, True);
    $06: CT16_impl(buf,len,True, True, False,True, True);
    $07: CT16_impl(buf,len,True, False,True, False,True);   // bswap_be: rd=BE,wr=LE
    $08: CT16_impl(buf,len,False,True, True, False,True);
    $09: CT16_impl(buf,len,True, True, True, False,True);
    // SW16
    $0A: SW16_impl(buf,len,True, False,True);
    $0B: SW16_impl(buf,len,False,True, True);
    $0C: SW16_impl(buf,len,True, True, True);
    // CTSW16
    $0D: CTSW16_impl(buf,len,True, True);  // E8=CT, E9=SW
    $0E: CTSW16_impl(buf,len,False,True);  // E9=CT, E8=SW
    // CT32 naive
    $11: CT32_impl(buf,len,True, False,False,False,True);
    $12: CT32_impl(buf,len,False,True, False,False,True);
    $13: CT32_impl(buf,len,True, True, False,False,True);
    $14: CT32_impl(buf,len,True, False,False,True, True);
    $15: CT32_impl(buf,len,False,True, False,True, True);
    $16: CT32_impl(buf,len,True, True, False,True, True);
    $17: CT32_impl(buf,len,True, False,True, False,True);
    $18: CT32_impl(buf,len,False,True, True, False,True);
    $19: CT32_impl(buf,len,True, True, True, False,True);
    // SW32
    $1A: SW32_impl(buf,len,True, False,True);
    $1B: SW32_impl(buf,len,False,True, True);
    $1C: SW32_impl(buf,len,True, True, True);
    // CTSW32
    $1D: CTSW32_impl(buf,len,True, True);
    $1E: CTSW32_impl(buf,len,False,True);
    // CTO32
    $24: Result := CTO32_Filter(buf,len,True, False,cto_out);
    $25: Result := CTO32_Filter(buf,len,False,True, cto_out);
    $26: Result := CTO32_Filter(buf,len,True, True, cto_out);
    // CTOJ32
    $36,$46: Result := CTOJ32_Filter(buf,len,cto_out);
    // CTOK32
    $49: Result := CTOK32_Filter(buf,len,$49,cto_out);
    // ARM
    $50: ARM24LE_Filter(buf,len);
    $51: ARM24BE_Filter(buf,len);
    $52: ARM26LE_Filter(buf,len);
    // RISC-V
    $55: Result := AUIPC_Filter(buf,len,cto_out);
    // CTOJR
    $80..$87: Result := CTOJR32_Filter(buf,len,Byte(filter_id),cto_out);
    // Sub8
    $90: Sub8_Filter(buf,len,1);
    $91: Sub8_Filter(buf,len,2);
    $92: Sub8_Filter(buf,len,3);
    $93: Sub8_Filter(buf,len,4);
    // Sub16
    $A0: Sub16_Filter(buf,len,1);
    $A1: Sub16_Filter(buf,len,2);
    $A2: Sub16_Filter(buf,len,3);
    $A3: Sub16_Filter(buf,len,4);
    // Sub32
    $B0: Sub32_Filter(buf,len,1);
    $B1: Sub32_Filter(buf,len,2);
    $B2: Sub32_Filter(buf,len,3);
    $B3: Sub32_Filter(buf,len,4);
    // PPC
    $D0: Result := PPC_Filter(buf,len,cto_out);
    // else: UPX_FILTER_NONE or unknown → no-op, Result=True
  end;
end;

function ApplyUnfilter(buf: PByte; len: Cardinal; filter_id: Integer;
                       cto: Byte): Boolean;
begin
  Result := True;
  case filter_id of
    // CT16 naive unfilter — swap rd_be/wr_be compared to filter for bswap variants
    $01: CT16_impl(buf,len,True, False,False,False,False);
    $02: CT16_impl(buf,len,False,True, False,False,False);
    $03: CT16_impl(buf,len,True, True, False,False,False);
    $04: CT16_impl(buf,len,True, False,True, False,False);  // filter wrote BE → read BE, write LE
    $05: CT16_impl(buf,len,False,True, True, False,False);
    $06: CT16_impl(buf,len,True, True, True, False,False);
    $07: CT16_impl(buf,len,True, False,False,True, False);  // filter wrote LE → read LE, write BE
    $08: CT16_impl(buf,len,False,True, False,True, False);
    $09: CT16_impl(buf,len,True, True, False,True, False);
    // SW16 unfilter: BE→LE
    $0A: SW16_impl(buf,len,True, False,False);
    $0B: SW16_impl(buf,len,False,True, False);
    $0C: SW16_impl(buf,len,True, True, False);
    // CTSW16 unfilter
    $0D: CTSW16_impl(buf,len,True, False);
    $0E: CTSW16_impl(buf,len,False,False);
    // CT32 naive unfilter
    $11: CT32_impl(buf,len,True, False,False,False,False);
    $12: CT32_impl(buf,len,False,True, False,False,False);
    $13: CT32_impl(buf,len,True, True, False,False,False);
    $14: CT32_impl(buf,len,True, False,True, False,False);
    $15: CT32_impl(buf,len,False,True, True, False,False);
    $16: CT32_impl(buf,len,True, True, True, False,False);
    $17: CT32_impl(buf,len,True, False,False,True, False);
    $18: CT32_impl(buf,len,False,True, False,True, False);
    $19: CT32_impl(buf,len,True, True, False,True, False);
    // SW32 unfilter
    $1A: SW32_impl(buf,len,True, False,False);
    $1B: SW32_impl(buf,len,False,True, False);
    $1C: SW32_impl(buf,len,True, True, False);
    // CTSW32 unfilter
    $1D: CTSW32_impl(buf,len,True, False);
    $1E: CTSW32_impl(buf,len,False,False);
    // CTO32 unfilter
    $24: CTO32_Unfilter(buf,len,True, False,cto);
    $25: CTO32_Unfilter(buf,len,False,True, cto);
    $26: CTO32_Unfilter(buf,len,True, True, cto);
    // CTOJ32 unfilter
    $36,$46: CTOJ32_Unfilter(buf,len,cto);
    // CTOK32 unfilter
    $49: CTOK32_Unfilter(buf,len,$49,cto);
    // ARM unfilter
    $50: ARM24LE_Unfilter(buf,len);
    $51: ARM24BE_Unfilter(buf,len);
    $52: ARM26LE_Unfilter(buf,len);
    // RISC-V unfilter
    $55: Result := AUIPC_Unfilter(buf,len);
    // CTOJR unfilter
    $80..$87: CTOJR32_Unfilter(buf,len,Byte(filter_id),cto);
    // Sub8 unfilter
    $90: Sub8_Unfilter(buf,len,1);
    $91: Sub8_Unfilter(buf,len,2);
    $92: Sub8_Unfilter(buf,len,3);
    $93: Sub8_Unfilter(buf,len,4);
    // Sub16 unfilter
    $A0: Sub16_Unfilter(buf,len,1);
    $A1: Sub16_Unfilter(buf,len,2);
    $A2: Sub16_Unfilter(buf,len,3);
    $A3: Sub16_Unfilter(buf,len,4);
    // Sub32 unfilter
    $B0: Sub32_Unfilter(buf,len,1);
    $B1: Sub32_Unfilter(buf,len,2);
    $B2: Sub32_Unfilter(buf,len,3);
    $B3: Sub32_Unfilter(buf,len,4);
    // PPC unfilter
    $D0: PPC_Unfilter(buf,len,cto);
  end;
end;

end.
