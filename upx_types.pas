{$mode delphi}
{$POINTERMATH ON}
unit upx_types;


// UPX Pascal Port
// License: GNU GPL
// Author: www.xelitan.com
//
// Types, constants, basic utilities
//  Translated from UPX 5.1.1 (C) Markus F.X.J. Oberhumer, Laszlo Molnar
//  GPL v2+


interface

uses SysUtils;

// ── basic types ──────────────────────────────────────────────────────────────

type
  TByteArray   = array[0..MaxInt-1] of Byte;
  PByteArray   = ^TByteArray;

// ── error codes (conf.h) ─────────────────────────────────────────────────────
const
  UPX_E_OK                  =  0;
  UPX_E_ERROR               = -1;
  UPX_E_OUT_OF_MEMORY       = -2;
  UPX_E_NOT_COMPRESSIBLE    = -3;
  UPX_E_INPUT_OVERRUN       = -4;
  UPX_E_OUTPUT_OVERRUN      = -5;
  UPX_E_LOOKBEHIND_OVERRUN  = -6;
  UPX_E_EOF_NOT_FOUND       = -7;
  UPX_E_INPUT_NOT_CONSUMED  = -8;
  UPX_E_NOT_YET_IMPLEMENTED = -9;
  UPX_E_INVALID_ARGUMENT    = -10;

// ── compression methods (conf.h) ─────────────────────────────────────────────
const
  M_NRV2B_LE32  = 2;
  M_NRV2B_8     = 3;
  M_NRV2B_LE16  = 4;
  M_NRV2D_LE32  = 5;
  M_NRV2D_8     = 6;
  M_NRV2D_LE16  = 7;
  M_NRV2E_LE32  = 8;
  M_NRV2E_8     = 9;
  M_NRV2E_LE16  = 10;
  M_LZMA        = 14;
  M_DEFLATE     = 15;

// ── file formats (conf.h) ────────────────────────────────────────────────────
const
  UPX_F_DOS_COM             = 1;
  UPX_F_DOS_SYS             = 2;
  UPX_F_DOS_EXE             = 3;
  UPX_F_W32PE_I386          = 9;
  UPX_F_LINUX_i386          = 10;
  UPX_F_LINUX_ELF_i386      = 12;
  UPX_F_WINCE_ARM           = 21;
  UPX_F_LINUX_ELF64_AMD64   = 22;
  UPX_F_LINUX_ELF32_ARM     = 23;
  UPX_F_MACH_i386           = 29;
  UPX_F_MACH_ARM            = 32;
  UPX_F_MACH_AMD64          = 34;
  UPX_F_W64PE_AMD64         = 36;
  UPX_F_MACH_ARM64          = 37;
  UPX_F_LINUX_ELF64_ARM64   = 42;
  UPX_F_MACH_PPC32          = 131;
  UPX_F_MACH_FAT            = 134;
  UPX_F_MACH_PPC64          = 139;

// ── magic numbers ────────────────────────────────────────────────────────────
const
  UPX_MAGIC_LE32  = $21585055;   // "UPX!"
  UPX_MAGIC2_LE32 = $D5D0D8A1;

// ── version ───────────────────────────────────────────────────────────────────
const
  UPX_VERSION_STRING = '5.1.1';
  UPX_VERSION_HEX    = $050101;

// ── endianness helpers ────────────────────────────────────────────────────────

function GetLE16(p: PByte): Word; inline;
function GetLE32(p: PByte): Cardinal; inline;
function GetLE64(p: PByte): QWord; inline;
function GetBE32(p: PByte): Cardinal; inline;
procedure SetLE16(p: PByte; v: Word); inline;
procedure SetLE32(p: PByte; v: Cardinal); inline;
procedure SetLE64(p: PByte; v: QWord); inline;
procedure SetBE32(p: PByte; v: Cardinal); inline;

// ── Adler-32 ─────────────────────────────────────────────────────────────────
function upx_adler32(data: PByte; len: Cardinal; adler: Cardinal = 1): Cardinal;

// ── method predicates ────────────────────────────────────────────────────────
function M_IS_NRV2B(m: Integer): Boolean; inline;
function M_IS_NRV2D(m: Integer): Boolean; inline;
function M_IS_NRV2E(m: Integer): Boolean; inline;
function M_IS_LZMA(m: Integer): Boolean;  inline;
function M_IS_NRV(m: Integer): Boolean;   inline;

implementation

// ── endianness ───────────────────────────────────────────────────────────────

function GetLE16(p: PByte): Word;
begin
  Result := Word(p[0]) or (Word(p[1]) shl 8);
end;

function GetLE32(p: PByte): Cardinal;
begin
  Result := Cardinal(p[0]) or (Cardinal(p[1]) shl 8)
          or (Cardinal(p[2]) shl 16) or (Cardinal(p[3]) shl 24);
end;

function GetLE64(p: PByte): QWord;
begin
  Result := QWord(GetLE32(p)) or (QWord(GetLE32(p+4)) shl 32);
end;

function GetBE32(p: PByte): Cardinal;
begin
  Result := (Cardinal(p[0]) shl 24) or (Cardinal(p[1]) shl 16)
          or (Cardinal(p[2]) shl 8) or Cardinal(p[3]);
end;

procedure SetLE16(p: PByte; v: Word);
begin
  p[0] := v and $FF;
  p[1] := (v shr 8) and $FF;
end;

procedure SetLE32(p: PByte; v: Cardinal);
begin
  p[0] := v and $FF;
  p[1] := (v shr 8) and $FF;
  p[2] := (v shr 16) and $FF;
  p[3] := (v shr 24) and $FF;
end;

procedure SetLE64(p: PByte; v: QWord);
begin
  SetLE32(p,   Cardinal(v and $FFFFFFFF));
  SetLE32(p+4, Cardinal(v shr 32));
end;

procedure SetBE32(p: PByte; v: Cardinal);
begin
  p[0] := (v shr 24) and $FF;
  p[1] := (v shr 16) and $FF;
  p[2] := (v shr 8) and $FF;
  p[3] := v and $FF;
end;

// ── Adler-32 (RFC 1950) ──────────────────────────────────────────────────────

function upx_adler32(data: PByte; len: Cardinal; adler: Cardinal): Cardinal;
const
  ADLER_MOD = 65521;
  NMAX      = 5552;
var
  s1, s2: Cardinal;
  k, i: Cardinal;
begin
  s1 := adler and $FFFF;
  s2 := (adler shr 16) and $FFFF;
  while len > 0 do
  begin
    if len < NMAX then k := len else k := NMAX;
    Dec(len, k);
    for i := 0 to k-1 do
    begin
      Inc(s1, data[i]);
      Inc(s2, s1);
    end;
    Inc(data, k);
    s1 := s1 mod ADLER_MOD;
    s2 := s2 mod ADLER_MOD;
  end;
  Result := (s2 shl 16) or s1;
end;

// ── method predicates ────────────────────────────────────────────────────────

function M_IS_NRV2B(m: Integer): Boolean;
begin
  Result := (m >= M_NRV2B_LE32) and (m <= M_NRV2B_LE16);
end;

function M_IS_NRV2D(m: Integer): Boolean;
begin
  Result := (m >= M_NRV2D_LE32) and (m <= M_NRV2D_LE16);
end;

function M_IS_NRV2E(m: Integer): Boolean;
begin
  Result := (m >= M_NRV2E_LE32) and (m <= M_NRV2E_LE16);
end;

function M_IS_LZMA(m: Integer): Boolean;
begin
  Result := (m and 255) = M_LZMA;
end;

function M_IS_NRV(m: Integer): Boolean;
begin
  Result := M_IS_NRV2B(m) or M_IS_NRV2D(m) or M_IS_NRV2E(m);
end;

end.
