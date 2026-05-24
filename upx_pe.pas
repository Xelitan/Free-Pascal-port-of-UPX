{$mode delphi}
{$POINTERMATH ON}
unit upx_pe;

// UPX Pascal Port
// License: GNU GPL
// Author: www.xelitan.com

interface
uses upx_types, upx_nrv, upx_packhead, SysUtils, Classes;

const
  IMAGE_DOS_SIGNATURE    = $5A4D;
  IMAGE_NT_SIGNATURE     = $00004550;
  IMAGE_NT_OPTIONAL_HDR32_MAGIC = $010B;
  IMAGE_NT_OPTIONAL_HDR64_MAGIC = $020B;
  IMAGE_SCN_CNT_CODE               = $00000020;
  IMAGE_SCN_CNT_INITIALIZED_DATA   = $00000040;
  IMAGE_SCN_CNT_UNINITIALIZED_DATA = $00000080;
  IMAGE_SCN_MEM_EXECUTE            = $20000000;
  IMAGE_SCN_MEM_READ               = $40000000;
  IMAGE_SCN_MEM_WRITE              = $80000000;
  IMAGE_SIZEOF_SECTION_HEADER = 40;
  IMAGE_SIZEOF_FILE_HEADER    = 20;

type
  TImageDosHeader = packed record
    e_magic:    Word;   e_cblp: Word;  e_cp: Word;     e_crlc: Word;
    e_cparhdr:  Word;   e_minalloc: Word; e_maxalloc: Word; e_ss: Word;
    e_sp:       Word;   e_csum: Word;  e_ip: Word;     e_cs: Word;
    e_lfarlc:   Word;   e_ovno: Word;
    e_res:      array[0..3] of Word;
    e_oemid:    Word;   e_oeminfo: Word;
    e_res2:     array[0..9] of Word;
    e_lfanew:   LongInt;
  end;
  TImageFileHeader = packed record
    Machine: Word; NumberOfSections: Word; TimeDateStamp: Cardinal;
    PointerToSymbolTable: Cardinal; NumberOfSymbols: Cardinal;
    SizeOfOptionalHeader: Word; Characteristics: Word;
  end;
  TImageDataDirectory = packed record VirtualAddress: Cardinal; Size: Cardinal; end;
  TImageOptionalHeader32 = packed record
    Magic: Word; MajorLinkerVersion: Byte; MinorLinkerVersion: Byte;
    SizeOfCode: Cardinal; SizeOfInitializedData: Cardinal; SizeOfUninitializedData: Cardinal;
    AddressOfEntryPoint: Cardinal; BaseOfCode: Cardinal; BaseOfData: Cardinal;
    ImageBase: Cardinal; SectionAlignment: Cardinal; FileAlignment: Cardinal;
    MajorOperatingSystemVersion: Word; MinorOperatingSystemVersion: Word;
    MajorImageVersion: Word; MinorImageVersion: Word;
    MajorSubsystemVersion: Word; MinorSubsystemVersion: Word;
    Win32VersionValue: Cardinal; SizeOfImage: Cardinal; SizeOfHeaders: Cardinal;
    CheckSum: Cardinal; Subsystem: Word; DllCharacteristics: Word;
    SizeOfStackReserve: Cardinal; SizeOfStackCommit: Cardinal;
    SizeOfHeapReserve: Cardinal; SizeOfHeapCommit: Cardinal;
    LoaderFlags: Cardinal; NumberOfRvaAndSizes: Cardinal;
    DataDirectory: array[0..15] of TImageDataDirectory;
  end;
  TImageOptionalHeader64 = packed record
    Magic: Word; MajorLinkerVersion: Byte; MinorLinkerVersion: Byte;
    SizeOfCode: Cardinal; SizeOfInitializedData: Cardinal; SizeOfUninitializedData: Cardinal;
    AddressOfEntryPoint: Cardinal; BaseOfCode: Cardinal;
    ImageBase: QWord; SectionAlignment: Cardinal; FileAlignment: Cardinal;
    MajorOperatingSystemVersion: Word; MinorOperatingSystemVersion: Word;
    MajorImageVersion: Word; MinorImageVersion: Word;
    MajorSubsystemVersion: Word; MinorSubsystemVersion: Word;
    Win32VersionValue: Cardinal; SizeOfImage: Cardinal; SizeOfHeaders: Cardinal;
    CheckSum: Cardinal; Subsystem: Word; DllCharacteristics: Word;
    SizeOfStackReserve: QWord; SizeOfStackCommit: QWord;
    SizeOfHeapReserve: QWord; SizeOfHeapCommit: QWord;
    LoaderFlags: Cardinal; NumberOfRvaAndSizes: Cardinal;
    DataDirectory: array[0..15] of TImageDataDirectory;
  end;
  TImageSectionHeader = packed record
    Name: array[0..7] of AnsiChar;
    VirtualSize: Cardinal; VirtualAddress: Cardinal;
    SizeOfRawData: Cardinal; PointerToRawData: Cardinal;
    PointerToRelocations: Cardinal; PointerToLinenumbers: Cardinal;
    NumberOfRelocations: Word; NumberOfLinenumbers: Word;
    Characteristics: Cardinal;
  end;
  TImageNtHeaders32 = packed record
    Signature: Cardinal; FileHeader: TImageFileHeader; OptionalHeader: TImageOptionalHeader32;
  end;
  TImageNtHeaders64 = packed record
    Signature: Cardinal; FileHeader: TImageFileHeader; OptionalHeader: TImageOptionalHeader64;
  end;
  TPeSection = record
    Name: string; VirtualAddress: Cardinal; VirtualSize: Cardinal;
    RawOffset: Cardinal; RawSize: Cardinal; Characteristics: Cardinal; Data: TBytes;
  end;
  TPeFile = class
  private
    FIs64: Boolean;
    FDosHdr: TImageDosHeader;
    FNtHdrs32: TImageNtHeaders32;
    FNtHdrs64: TImageNtHeaders64;
    FSections: array of TPeSection;
    FFileData: TBytes;
    FFilePath: string;
    function GetFileAlignment: Cardinal;
    function GetSectionAlignment: Cardinal;
    function AlignUp(v, align: Cardinal): Cardinal;
    function GetEntry: Cardinal;
    procedure SetEntry(v: Cardinal);
    function GetImageBase32: Cardinal;
    function GetImageBase64: QWord;
    procedure ParseSections;
    function ReadSectionData(secIdx: Integer): Boolean;
    function RebuildOriginalPE(const ph: TPackHeader; cdata: PByte; clen: Cardinal): TBytes;
  public
    constructor Create; destructor Destroy; override;
    function LoadFile(const FileName: string): Boolean;
    function SaveFile(const FileName: string): Boolean;
    property Is64: Boolean read FIs64;
    property FilePath: string read FFilePath;
    property Entry: Cardinal read GetEntry write SetEntry;
    property ImageBase32: Cardinal read GetImageBase32;
    property ImageBase64: QWord read GetImageBase64;
    function IsValid: Boolean;
    function IsPackedUPX: Boolean;
    function Pack(const OutFile: string; method: Integer; level: Integer): Boolean;
    function Unpack(const OutFile: string): Boolean;
    function FindUPXHeader(out ph: TPackHeader; out secIdx: Integer): Boolean;
  end;

implementation

{$include stub_pe64_data.inc}
{$include stub_pe64_nrv2d_data.inc}
{$include stub_pe64_nrv2e_data.inc}
{$include stub_pe32_nrv2b_data.inc}
{$include stub_pe32_nrv2d_data.inc}
{$include stub_pe32_nrv2e_data.inc}

function TPeFile.AlignUp(v, align: Cardinal): Cardinal;
begin
  if align = 0 then Result := v
  else Result := (v + align - 1) and (not (align - 1));
end;
function TPeFile.GetFileAlignment: Cardinal;
begin
  if FIs64 then Result := FNtHdrs64.OptionalHeader.FileAlignment
  else Result := FNtHdrs32.OptionalHeader.FileAlignment;
  if Result = 0 then Result := $200;
end;
function TPeFile.GetSectionAlignment: Cardinal;
begin
  if FIs64 then Result := FNtHdrs64.OptionalHeader.SectionAlignment
  else Result := FNtHdrs32.OptionalHeader.SectionAlignment;
  if Result = 0 then Result := $1000;
end;
function TPeFile.GetEntry: Cardinal;
begin
  if FIs64 then Result := FNtHdrs64.OptionalHeader.AddressOfEntryPoint
  else Result := FNtHdrs32.OptionalHeader.AddressOfEntryPoint;
end;
procedure TPeFile.SetEntry(v: Cardinal);
begin
  if FIs64 then FNtHdrs64.OptionalHeader.AddressOfEntryPoint := v
  else FNtHdrs32.OptionalHeader.AddressOfEntryPoint := v;
end;
function TPeFile.GetImageBase32: Cardinal; begin Result := FNtHdrs32.OptionalHeader.ImageBase; end;
function TPeFile.GetImageBase64: QWord;   begin Result := FNtHdrs64.OptionalHeader.ImageBase; end;

constructor TPeFile.Create; begin inherited; FIs64 := False; end;
destructor TPeFile.Destroy; begin inherited; end;

function TPeFile.LoadFile(const FileName: string): Boolean;
var fs: TFileStream; sz: Int64;
begin
  Result := False; FFilePath := FileName;
  try
    fs := TFileStream.Create(FileName, fmOpenRead or fmShareDenyWrite);
    try sz := fs.Size; SetLength(FFileData, sz); if sz > 0 then fs.Read(FFileData[0], sz);
    finally fs.Free; end;
  except Exit; end;
  if not IsValid then Exit;
  ParseSections; Result := True;
end;

function TPeFile.IsValid: Boolean;
var p: PByte; nt_off: Integer;
begin
  Result := False;
  if Length(FFileData) < SizeOf(TImageDosHeader) then Exit;
  Move(FFileData[0], FDosHdr, SizeOf(TImageDosHeader));
  if FDosHdr.e_magic <> IMAGE_DOS_SIGNATURE then Exit;
  nt_off := FDosHdr.e_lfanew;
  if (nt_off < 0) or (nt_off + SizeOf(TImageNtHeaders32) > Length(FFileData)) then Exit;
  p := @FFileData[nt_off];
  if GetLE32(p) <> IMAGE_NT_SIGNATURE then Exit;
  p := p + SizeOf(Cardinal) + SizeOf(TImageFileHeader);
  case GetLE16(p) of
    IMAGE_NT_OPTIONAL_HDR32_MAGIC: begin FIs64 := False; Move(FFileData[nt_off], FNtHdrs32, SizeOf(TImageNtHeaders32)); end;
    IMAGE_NT_OPTIONAL_HDR64_MAGIC: begin FIs64 := True;  Move(FFileData[nt_off], FNtHdrs64, SizeOf(TImageNtHeaders64)); end;
  else Exit;
  end;
  Result := True;
end;

procedure TPeFile.ParseSections;
var nt_off, num_sec, sec_off, i: Integer; sh: TImageSectionHeader;
begin
  nt_off := FDosHdr.e_lfanew;
  if FIs64 then begin
    num_sec := FNtHdrs64.FileHeader.NumberOfSections;
    sec_off := nt_off + SizeOf(Cardinal) + SizeOf(TImageFileHeader) + FNtHdrs64.FileHeader.SizeOfOptionalHeader;
  end else begin
    num_sec := FNtHdrs32.FileHeader.NumberOfSections;
    sec_off := nt_off + SizeOf(Cardinal) + SizeOf(TImageFileHeader) + FNtHdrs32.FileHeader.SizeOfOptionalHeader;
  end;
  SetLength(FSections, num_sec);
  for i := 0 to num_sec - 1 do begin
    Move(FFileData[sec_off + i * IMAGE_SIZEOF_SECTION_HEADER], sh, SizeOf(sh));
    FSections[i].Name           := TrimRight(string(AnsiString(PAnsiChar(@sh.Name[0]))));
    FSections[i].VirtualAddress := sh.VirtualAddress;
    FSections[i].VirtualSize    := sh.VirtualSize;
    FSections[i].RawOffset      := sh.PointerToRawData;
    FSections[i].RawSize        := sh.SizeOfRawData;
    FSections[i].Characteristics := sh.Characteristics;
    if (sh.SizeOfRawData > 0) and (sh.PointerToRawData + sh.SizeOfRawData <= Cardinal(Length(FFileData))) then begin
      SetLength(FSections[i].Data, sh.SizeOfRawData);
      Move(FFileData[sh.PointerToRawData], FSections[i].Data[0], sh.SizeOfRawData);
    end;
  end;
end;

function TPeFile.ReadSectionData(secIdx: Integer): Boolean;
begin Result := (secIdx >= 0) and (secIdx < Length(FSections)) and (Length(FSections[secIdx].Data) > 0); end;

function TPeFile.IsPackedUPX: Boolean;
var ph: TPackHeader; si: Integer; begin Result := FindUPXHeader(ph, si); end;

function TPeFile.FindUPXHeader(out ph: TPackHeader; out secIdx: Integer): Boolean;
var i: Integer; p: PByte; sz: Integer;
begin
  Result := False; secIdx := -1;
  for i := 0 to Length(FSections) - 1 do
    if (FSections[i].Name = 'UPX1') or (FSections[i].Name = 'UPX2') then
      if Length(FSections[i].Data) > 0 then begin
        p := @FSections[i].Data[0]; sz := Length(FSections[i].Data);
        if PackHeader_Decode(ph, p, sz) then begin secIdx := i; Result := True; Exit; end;
      end;
  for i := 0 to Length(FSections) - 1 do
    if Length(FSections[i].Data) > 0 then begin
      p := @FSections[i].Data[0]; sz := Length(FSections[i].Data);
      if PackHeader_Decode(ph, p, sz) then begin secIdx := i; Result := True; Exit; end;
    end;
end;

function TPeFile.RebuildOriginalPE(const ph: TPackHeader; cdata: PByte; clen: Cardinal): TBytes;
begin Result := nil; end;

// ── Unpack ────────────────────────────────────────────────────────────────────
// Format full_buf (nowy):
//   [0..flat_size-1]          = flat virtual image (sekcje przy VA-rvamin)
//   [flat_size..+imp_len-1]   = import stream (kończy się 4×0x00)
//   [flat_size+imp_len..+N-1] = hdr_blob (SizeOfHeaders bajtów oryg. pliku)
//   [last 4 bytes]            = hdr_blob_size jako LE32
// Jeśli hdr_blob zaczyna się od MZ → rekonstrukcja oryginału; inaczej → błąd.

function TPeFile.Unpack(const OutFile: string): Boolean;
var
  ph           : TPackHeader;
  secIdx, i    : Integer;
  cdata        : PByte;
  coff         : Cardinal;
  full_buf     : TBytes;
  udst_len     : Cardinal;
  r            : Integer;
  flat_size    : Cardinal;
  hdr_blob_size: Cardinal;
  hdr_blob_off : Cardinal;
  dos_hdr      : TImageDosHeader;
  nt32_hdr     : TImageNtHeaders32;
  nt64_hdr     : TImageNtHeaders64;
  num_sec      : Integer;
  sec_tab_off  : Integer;
  nt_off       : Integer;
  sh           : TImageSectionHeader;
  rvamin       : Cardinal;
  out_size     : Cardinal;
  out_buf      : TBytes;
  src_off      : Cardinal;
  copy_len     : Cardinal;
  fs           : TFileStream;
begin
  Result := False;
  if not FindUPXHeader(ph, secIdx) then
    raise Exception.Create('Nagłówek UPX nie znaleziony');

  // compressed data at constant delta from UPX! header (delta cancels method shift)
  if not FIs64 then
    coff := ph.buf_offset + 161   // PE32: vkCompDataOff(408+d) - vkPtHead(247+d)
  else
    coff := ph.buf_offset + 197;  // PE64: vkCompDataOff(578+d) - vkPtHead(381+d)

  if coff + ph.c_len > Cardinal(Length(FSections[secIdx].Data)) then
    raise Exception.CreateFmt('Dane skompresowane %d+%d > rozmiar sekcji %d',
      [coff, ph.c_len, Length(FSections[secIdx].Data)]);
  cdata := @FSections[secIdx].Data[coff];

  SetLength(full_buf, ph.u_len + 256);
  udst_len := ph.u_len;
  r := nrv_decompress(cdata, ph.c_len, @full_buf[0], udst_len, ph.method);
  if udst_len <> ph.u_len then
    raise Exception.CreateFmt('NRV rozmiar: oczekiwano %d, dostano %d', [ph.u_len, udst_len]);
  if (r <> UPX_E_OK) and (r <> UPX_E_INPUT_NOT_CONSUMED) and (r <> UPX_E_LOOKBEHIND_OVERRUN) then
    raise Exception.CreateFmt('Błąd NRV dekompresji: %d', [r]);
  if upx_adler32(@full_buf[0], udst_len) <> ph.u_adler then
    raise Exception.Create('Adler32 niezgodny');

  // recover flat_size from stub patch point
  if not FIs64 then begin
    if ph.buf_offset < 76 then raise Exception.Create('buf_offset za mały (PE32)');
    flat_size := GetLE32(@FSections[secIdx].Data[ph.buf_offset - 76]);
  end else begin
    if ph.buf_offset < 127 then raise Exception.Create('buf_offset za mały (PE64)');
    flat_size := GetLE32(@FSections[secIdx].Data[ph.buf_offset - 127]);
  end;

  if flat_size > udst_len then
    raise Exception.Create('flat_size > u_len – uszkodzony nagłówek');

  // read hdr_blob_size from last 4 bytes of full_buf
  if udst_len < 8 then raise Exception.Create('u_len za mały');
  hdr_blob_size := GetLE32(@full_buf[udst_len - 4]);

  if (hdr_blob_size = 0) or (hdr_blob_size > 65536) or
     (hdr_blob_size + 4 > udst_len - flat_size) then
    raise Exception.Create('Nieprawidłowy hdr_blob_size – plik spakowany starą wersją?');

  hdr_blob_off := udst_len - 4 - hdr_blob_size;

  // verify MZ magic in hdr_blob
  if (full_buf[hdr_blob_off] <> $4D) or (full_buf[hdr_blob_off + 1] <> $5A) then
    raise Exception.Create('Brak MZ w hdr_blob – plik spakowany starą wersją');

  // parse hdr_blob
  Move(full_buf[hdr_blob_off], dos_hdr, SizeOf(TImageDosHeader));
  nt_off := dos_hdr.e_lfanew;
  if (nt_off < 0) or (Cardinal(nt_off) + SizeOf(TImageNtHeaders32) > hdr_blob_size) then
    raise Exception.Create('Nieprawidłowy e_lfanew w hdr_blob');

  if FIs64 then begin
    Move(full_buf[hdr_blob_off + Cardinal(nt_off)], nt64_hdr, SizeOf(TImageNtHeaders64));
    num_sec     := nt64_hdr.FileHeader.NumberOfSections;
    sec_tab_off := nt_off + SizeOf(Cardinal) + SizeOf(TImageFileHeader)
                   + nt64_hdr.FileHeader.SizeOfOptionalHeader;
  end else begin
    Move(full_buf[hdr_blob_off + Cardinal(nt_off)], nt32_hdr, SizeOf(TImageNtHeaders32));
    num_sec     := nt32_hdr.FileHeader.NumberOfSections;
    sec_tab_off := nt_off + SizeOf(Cardinal) + SizeOf(TImageFileHeader)
                   + nt32_hdr.FileHeader.SizeOfOptionalHeader;
  end;

  // compute rvamin from section table in hdr_blob
  rvamin := $FFFFFFFF;
  for i := 0 to num_sec - 1 do begin
    Move(full_buf[hdr_blob_off + Cardinal(sec_tab_off) + Cardinal(i) * 40], sh, SizeOf(sh));
    if sh.VirtualAddress < rvamin then rvamin := sh.VirtualAddress;
  end;
  if rvamin = $FFFFFFFF then rvamin := 0;

  // compute original file size = max(PointerToRawData + SizeOfRawData)
  out_size := hdr_blob_size;
  for i := 0 to num_sec - 1 do begin
    Move(full_buf[hdr_blob_off + Cardinal(sec_tab_off) + Cardinal(i) * 40], sh, SizeOf(sh));
    if sh.PointerToRawData + sh.SizeOfRawData > out_size then
      out_size := sh.PointerToRawData + sh.SizeOfRawData;
  end;

  // build output buffer
  SetLength(out_buf, out_size);
  FillChar(out_buf[0], out_size, 0);

  // copy original headers
  Move(full_buf[hdr_blob_off], out_buf[0], hdr_blob_size);

  // copy each section's raw data from flat_buf to its original file offset
  for i := 0 to num_sec - 1 do begin
    Move(full_buf[hdr_blob_off + Cardinal(sec_tab_off) + Cardinal(i) * 40], sh, SizeOf(sh));
    if (sh.SizeOfRawData = 0) or (sh.PointerToRawData = 0) then Continue;
    if sh.VirtualAddress < rvamin then Continue;
    src_off  := sh.VirtualAddress - rvamin;
    copy_len := sh.SizeOfRawData;
    if src_off >= flat_size then Continue;
    if src_off + copy_len > flat_size then copy_len := flat_size - src_off;
    if sh.PointerToRawData + copy_len > out_size then
      copy_len := out_size - sh.PointerToRawData;
    if copy_len = 0 then Continue;
    Move(full_buf[src_off], out_buf[sh.PointerToRawData], copy_len);
  end;

  try
    fs := TFileStream.Create(OutFile, fmCreate);
    try fs.Write(out_buf[0], out_size); finally fs.Free; end;
    Result := True;
  except
    on E: Exception do
      raise Exception.CreateFmt('Nie można zapisać "%s": %s', [OutFile, E.Message]);
  end;
end;

// ── Pack ──────────────────────────────────────────────────────────────────────
// full_buf = flat_buf [flat_size] + import_stream [imp_len]
//          + hdr_blob [SizeOfHeaders] + hdr_blob_size[4]
// Stub jest w pełni opatchowany do uruchomienia w runtime.

function TPeFile.Pack(const OutFile: string; method: Integer; level: Integer): Boolean;
var
  delta, vkStubSize, vkIATOff, vkINTOff, vkIMPDirOff: Integer;
  vkDllNmOff, vkHnLaOff, vkHnGpaOff, vkHnEpOff, vkCompDataOff: Integer;
  vkPtCI, vkPtSI, vkPtLA, vkPtK32, vkPtGPA, vkPtEP, vkPtOE, vkPtHead: Integer;
  fa, sa: Cardinal;
  i: Integer;
  orig_entry, import_dir_rva, import_dir_size: Cardinal;
  rvamin, newvsize, flat_size: Cardinal;
  flat_buf: TBytes;
  imp_stream: TBytes;
  imp_len: Cardinal;
  hdr_blob_size: Cardinal;
  full_buf: TBytes;
  full_len: Cardinal;
  compressed: TBytes;
  comp_len, u_adler, c_adler: Cardinal;
  r: Integer;
  ph: TPackHeader;
  out_buf: TBytes;
  nt_off, sec_off_hdr: Integer;
  hdr_size, upx0_va, upx1_va, upx0_vs, upx1_vs, upx1_rs: Cardinal;
  sh: TImageSectionHeader;
  nt64: TImageNtHeaders64; nt32: TImageNtHeaders32;
  fs: TFileStream;
  upx1_raw, p_raw: PByte;
  stub: array[0..STUB_PE64_NRV2E_SIZE-1] of Byte;
  stub32: array[0..STUB_PE32_NRV2E_SIZE-1] of Byte;
  imp_thunk_val32: Cardinal;
  imp_thunk_val: QWord;
  imp_desc_off: Integer;
  imp_desc_rva, imp_lookup_rva, imp_iat_base_rva, imp_dll_name_rva: Cardinal;
  imp_dn_off: Integer;
  imp_dll_name_str: AnsiString;
  imp_is_k32: Boolean;
  imp_thunk_rva: Cardinal;
  imp_thunk_off: Integer;
  imp_ordinal: Word;
  imp_name_rva: Cardinal;
  imp_name_off: Integer;
  copy_len: Cardinal;
  src_off: Cardinal;
  rsrc_orig_rva, rsrc_orig_size, rsrc_raw_size: Cardinal;
  rsrc_raw_off: Integer;
  rsrc_buf: TBytes;
  rsrc_off_in_upx1, new_rsrc_rva: Cardinal;
  rsrc_delta: LongInt;
  k: Integer;

  function RvaToOff(rva: Cardinal): Integer;
  var j: Integer;
  begin
    for j := 0 to Length(FSections) - 1 do
      if (rva >= FSections[j].VirtualAddress) and
         (rva <  FSections[j].VirtualAddress + FSections[j].VirtualSize) and
         (FSections[j].RawOffset > 0) then
      begin
        Result := Integer(FSections[j].RawOffset + (rva - FSections[j].VirtualAddress));
        Exit;
      end;
    Result := -1;
  end;

  procedure ImpByte(b: Byte);
  begin
    if imp_len >= Cardinal(Length(imp_stream)) then
      SetLength(imp_stream, imp_len + 4096);
    imp_stream[imp_len] := b; Inc(imp_len);
  end;
  procedure ImpU16(v: Word); begin ImpByte(Byte(v)); ImpByte(Byte(v shr 8)); end;
  procedure ImpU32(v: Cardinal);
  begin ImpByte(Byte(v)); ImpByte(Byte(v shr 8)); ImpByte(Byte(v shr 16)); ImpByte(Byte(v shr 24)); end;

  // patch d32 field in stub[] at byte offset 'off'
  procedure PatchS32(off: Integer; sv: LongInt);
  var lw: LongWord;
  begin lw := LongWord(sv);
    stub[off+0]:=Byte(lw); stub[off+1]:=Byte(lw shr 8);
    stub[off+2]:=Byte(lw shr 16); stub[off+3]:=Byte(lw shr 24);
  end;

  procedure WriteNameZ(dst: PByte; const s: string);
  var j: Integer;
  begin for j := 1 to Length(s) do begin dst^:=Byte(Ord(s[j])); Inc(dst); end; dst^:=0; end;

  // Walk IMAGE_RESOURCE_DIRECTORY tree and add rdelta to every leaf DataRVA.
  // All offsets in directory entries are relative to the start of the resource section (buf).
  procedure RelocRsrcDir(buf: PByte; bsz: Cardinal; dir_off: Cardinal; rdelta: LongInt);
  var nn, ni, ne, ii: Integer; eo, doff, old_rva: Cardinal;
  begin
    if dir_off + 16 > bsz then Exit;
    nn := GetLE16(buf + dir_off + 12); ni := GetLE16(buf + dir_off + 14);
    ne := nn + ni; eo := dir_off + 16;
    for ii := 0 to ne - 1 do begin
      if eo + 8 > bsz then Break;
      doff := GetLE32(buf + eo + 4);
      if (doff and $80000000) <> 0 then
        RelocRsrcDir(buf, bsz, doff and $7FFFFFFF, rdelta)
      else if doff + 4 <= bsz then begin
        old_rva := GetLE32(buf + doff);
        SetLE32(buf + doff, Cardinal(LongInt(old_rva) + rdelta));
      end;
      Inc(eo, 8);
    end;
  end;

begin
  Result := False;
  if IsPackedUPX then raise Exception.Create('Plik jest już spakowany przez UPX');
  if not (method in [M_NRV2B_LE32, M_NRV2D_LE32, M_NRV2E_LE32]) then
    raise Exception.CreateFmt('PE obsługuje NRV2B/2D/2E. Podano metodę %d.', [method]);

  fa := GetFileAlignment; sa := GetSectionAlignment;

  // ── rvamin / newvsize ─────────────────────────────────────────────────────
  rvamin := $FFFFFFFF; newvsize := 0;
  for i := 0 to Length(FSections) - 1 do begin
    if FSections[i].VirtualAddress < rvamin then rvamin := FSections[i].VirtualAddress;
    if FSections[i].VirtualAddress + FSections[i].VirtualSize > newvsize then
      newvsize := FSections[i].VirtualAddress + FSections[i].VirtualSize;
  end;
  if rvamin = $FFFFFFFF then rvamin := sa;
  newvsize := AlignUp(newvsize, sa);
  flat_size := newvsize - rvamin;

  // ── flat_buf ──────────────────────────────────────────────────────────────
  SetLength(flat_buf, flat_size);
  FillChar(flat_buf[0], flat_size, 0);
  for i := 0 to Length(FSections) - 1 do
    if (FSections[i].VirtualAddress >= rvamin) and (Length(FSections[i].Data) > 0) then begin
      copy_len := Cardinal(Length(FSections[i].Data));
      src_off  := FSections[i].VirtualAddress - rvamin;
      if src_off >= flat_size then Continue;
      if src_off + copy_len > flat_size then copy_len := flat_size - src_off;
      Move(FSections[i].Data[0], flat_buf[src_off], copy_len);
    end;

  orig_entry := GetEntry;

  // ── PE32 path ─────────────────────────────────────────────────────────────
  if not FIs64 then begin
    case method of
      M_NRV2D_LE32: delta := STUB_PE32_NRV2D_SIZE - STUB_PE32_NRV2B_SIZE;
      M_NRV2E_LE32: delta := STUB_PE32_NRV2E_SIZE - STUB_PE32_NRV2B_SIZE;
    else delta := 0; end;
    vkStubSize    := STUB_PE32_NRV2B_SIZE + delta;
    vkIATOff      := 279 + delta; vkINTOff      := 295 + delta;
    vkIMPDirOff   := 311 + delta; vkDllNmOff    := 351 + delta;
    vkHnLaOff     := 364 + delta; vkHnGpaOff    := 378 + delta;
    vkHnEpOff     := 394 + delta; vkCompDataOff := 408 + delta;
    vkPtCI := 171 + delta; vkPtSI := 187 + delta;
    vkPtLA := 199 + delta; vkPtGPA := 220 + delta; vkPtEP := 237 + delta;
    vkPtOE := 243 + delta; vkPtHead := 247 + delta;

    import_dir_rva  := FNtHdrs32.OptionalHeader.DataDirectory[1].VirtualAddress;
    import_dir_size := FNtHdrs32.OptionalHeader.DataDirectory[1].Size;

    // build import stream (32-bit thunks)
    SetLength(imp_stream, 4096); imp_len := 0;
    if (import_dir_rva <> 0) and (import_dir_size >= 20) then begin
      imp_desc_rva := import_dir_rva;
      while True do begin
        imp_desc_off := RvaToOff(imp_desc_rva);
        if (imp_desc_off < 0) or (imp_desc_off + 20 > Length(FFileData)) then Break;
        imp_lookup_rva   := GetLE32(@FFileData[imp_desc_off +  0]);
        imp_dll_name_rva := GetLE32(@FFileData[imp_desc_off + 12]);
        imp_iat_base_rva := GetLE32(@FFileData[imp_desc_off + 16]);
        if imp_iat_base_rva = 0 then Break;
        ImpU32(imp_dll_name_rva - import_dir_rva); ImpU32(imp_iat_base_rva - rvamin);
        imp_dll_name_str := ''; imp_dn_off := RvaToOff(imp_dll_name_rva);
        if imp_dn_off >= 0 then
          while (imp_dn_off < Length(FFileData)) and (FFileData[imp_dn_off] <> 0) do
            begin imp_dll_name_str := imp_dll_name_str + AnsiChar(FFileData[imp_dn_off]); Inc(imp_dn_off); end;
        imp_is_k32 := (LowerCase(string(imp_dll_name_str)) = 'kernel32.dll');
        if imp_lookup_rva <> 0 then imp_thunk_rva := imp_lookup_rva
        else imp_thunk_rva := imp_iat_base_rva;
        while True do begin
          imp_thunk_off := RvaToOff(imp_thunk_rva);
          if (imp_thunk_off < 0) or (imp_thunk_off + 4 > Length(FFileData)) then Break;
          imp_thunk_val32 := GetLE32(@FFileData[imp_thunk_off]);
          if imp_thunk_val32 = 0 then Break;
          if (imp_thunk_val32 and Cardinal($80000000)) <> 0 then begin
            imp_ordinal := Word(imp_thunk_val32 and $FFFF);
            ImpByte($FF); ImpU16(imp_ordinal);
          end else begin
            imp_name_rva := Cardinal(imp_thunk_val32 and $7FFFFFFF);
            imp_name_off := RvaToOff(imp_name_rva);
            if imp_name_off >= 0 then begin
              Inc(imp_name_off, 2); ImpByte($01);
              while (imp_name_off < Length(FFileData)) and (FFileData[imp_name_off] <> 0) do
                begin ImpByte(FFileData[imp_name_off]); Inc(imp_name_off); end;
              ImpByte(0);
            end;
          end;
          Inc(imp_thunk_rva, 4);
        end;
        ImpByte(0); Inc(imp_desc_rva, 20);
      end;
    end;
    ImpU32(0);

    // hdr_blob = first SizeOfHeaders bytes of original file
    hdr_blob_size := FNtHdrs32.OptionalHeader.SizeOfHeaders;
    if hdr_blob_size > Cardinal(Length(FFileData)) then hdr_blob_size := Cardinal(Length(FFileData));
    if hdr_blob_size = 0 then hdr_blob_size := AlignUp(
      SizeOf(TImageDosHeader) + SizeOf(TImageNtHeaders32)
      + Cardinal(Length(FSections)) * IMAGE_SIZEOF_SECTION_HEADER, fa);

    full_len := flat_size + imp_len + hdr_blob_size + 4;
    SetLength(full_buf, full_len);
    Move(flat_buf[0], full_buf[0], flat_size);
    if imp_len > 0 then Move(imp_stream[0], full_buf[flat_size], imp_len);
    Move(FFileData[0], full_buf[flat_size + imp_len], hdr_blob_size);
    SetLE32(@full_buf[flat_size + imp_len + hdr_blob_size], hdr_blob_size);
    u_adler := upx_adler32(@full_buf[0], full_len);

    SetLength(compressed, full_len + full_len div 8 + 4096);
    comp_len := Cardinal(Length(compressed));
    r := nrv_compress(@full_buf[0], full_len, @compressed[0], comp_len, method, level);
    if r = UPX_E_NOT_COMPRESSIBLE then raise Exception.Create('Plik niekompresowalny');
    if r <> UPX_E_OK then raise Exception.CreateFmt('Błąd kompresji NRV: %d', [r]);
    c_adler := upx_adler32(@compressed[0], comp_len);

    // ── find original resource section for icon/manifest visibility ──────────
    rsrc_orig_rva  := FNtHdrs32.OptionalHeader.DataDirectory[2].VirtualAddress;
    rsrc_orig_size := FNtHdrs32.OptionalHeader.DataDirectory[2].Size;
    rsrc_raw_off := -1; rsrc_raw_size := 0; rsrc_buf := nil;
    if (rsrc_orig_rva <> 0) and (rsrc_orig_size <> 0) then
      for k := 0 to Length(FSections)-1 do
        if (FSections[k].VirtualAddress <= rsrc_orig_rva) and
           (rsrc_orig_rva < FSections[k].VirtualAddress + FSections[k].VirtualSize) and
           (FSections[k].RawOffset > 0) and (FSections[k].RawSize > 0) then begin
          rsrc_raw_off  := FSections[k].RawOffset;
          rsrc_raw_size := FSections[k].RawSize;
          if rsrc_raw_off + Integer(rsrc_raw_size) > Length(FFileData) then
            rsrc_raw_size := Cardinal(Length(FFileData)) - Cardinal(rsrc_raw_off);
          SetLength(rsrc_buf, rsrc_raw_size);
          Move(FFileData[rsrc_raw_off], rsrc_buf[0], rsrc_raw_size);
          Break;
        end;

    hdr_size := AlignUp(SizeOf(TImageDosHeader) + SizeOf(TImageNtHeaders32)
                + 2 * IMAGE_SIZEOF_SECTION_HEADER, fa);
    upx0_va := rvamin; upx0_vs := AlignUp(full_len, sa);
    upx1_va := upx0_va + upx0_vs;
    upx1_rs := AlignUp(Cardinal(vkCompDataOff) + comp_len, fa);
    // append resources after compressed data in UPX1 so they are visible on disk
    rsrc_off_in_upx1 := 0; new_rsrc_rva := 0;
    if (rsrc_raw_size > 0) and (Length(rsrc_buf) > 0) then begin
      rsrc_off_in_upx1 := upx1_rs;
      new_rsrc_rva     := upx1_va + rsrc_off_in_upx1;
      rsrc_delta       := LongInt(new_rsrc_rva) - LongInt(rsrc_orig_rva);
      RelocRsrcDir(@rsrc_buf[0], rsrc_raw_size, 0, rsrc_delta);
      upx1_rs := AlignUp(rsrc_off_in_upx1 + rsrc_raw_size, fa);
    end;
    upx1_vs := AlignUp(upx1_rs, sa);

    SetLength(out_buf, hdr_size + upx1_rs);
    FillChar(out_buf[0], Length(out_buf), 0);
    upx1_raw := @out_buf[hdr_size];

    SetLE16(@out_buf[0], IMAGE_DOS_SIGNATURE);
    nt_off := SizeOf(TImageDosHeader); SetLE32(@out_buf[60], nt_off);

    FillChar(nt32, SizeOf(nt32), 0);
    nt32.Signature := IMAGE_NT_SIGNATURE; nt32.FileHeader.Machine := $014C;
    nt32.FileHeader.NumberOfSections := 2;
    nt32.FileHeader.SizeOfOptionalHeader := SizeOf(TImageOptionalHeader32);
    nt32.FileHeader.Characteristics := $010F;
    nt32.OptionalHeader.Magic := IMAGE_NT_OPTIONAL_HDR32_MAGIC;
    nt32.OptionalHeader.AddressOfEntryPoint := upx1_va;
    nt32.OptionalHeader.ImageBase := FNtHdrs32.OptionalHeader.ImageBase;
    if nt32.OptionalHeader.ImageBase = 0 then nt32.OptionalHeader.ImageBase := $400000;
    nt32.OptionalHeader.SectionAlignment := sa; nt32.OptionalHeader.FileAlignment := fa;
    nt32.OptionalHeader.MajorSubsystemVersion := 4;
    nt32.OptionalHeader.Subsystem := FNtHdrs32.OptionalHeader.Subsystem;
    if nt32.OptionalHeader.Subsystem = 0 then nt32.OptionalHeader.Subsystem := 2;
    nt32.OptionalHeader.SizeOfHeaders := hdr_size;
    nt32.OptionalHeader.SizeOfImage := upx1_va + upx1_vs;
    nt32.OptionalHeader.NumberOfRvaAndSizes := 16;
    // Copy all original data dirs (resources, exception, debug, loadconfig, etc.)
    // so they resolve correctly in post-decompression memory (they land at original RVAs).
    Move(FNtHdrs32.OptionalHeader.DataDirectory[0],
         nt32.OptionalHeader.DataDirectory[0],
         16 * SizeOf(TImageDataDirectory));
    // Override with stub-managed directories
    nt32.OptionalHeader.DataDirectory[1].VirtualAddress := upx1_va + Cardinal(vkIMPDirOff);
    nt32.OptionalHeader.DataDirectory[1].Size := 40;
    nt32.OptionalHeader.DataDirectory[12].VirtualAddress := upx1_va + Cardinal(vkIATOff);
    nt32.OptionalHeader.DataDirectory[12].Size := 16;
    // Zero stale/unsafe entries
    FillChar(nt32.OptionalHeader.DataDirectory[4],  SizeOf(TImageDataDirectory), 0); // Security (cert)
    FillChar(nt32.OptionalHeader.DataDirectory[9],  SizeOf(TImageDataDirectory), 0); // TLS (not supported yet)
    FillChar(nt32.OptionalHeader.DataDirectory[11], SizeOf(TImageDataDirectory), 0); // BoundImport (stale)
    // Override resource dir to point to UPX1 copy so icon/manifest are visible on disk
    if new_rsrc_rva <> 0 then begin
      nt32.OptionalHeader.DataDirectory[2].VirtualAddress := new_rsrc_rva;
      nt32.OptionalHeader.DataDirectory[2].Size := rsrc_orig_size;
    end;
    // Preserve original stack/heap sizes
    nt32.OptionalHeader.SizeOfStackReserve := FNtHdrs32.OptionalHeader.SizeOfStackReserve;
    if nt32.OptionalHeader.SizeOfStackReserve = 0 then nt32.OptionalHeader.SizeOfStackReserve := $100000;
    nt32.OptionalHeader.SizeOfStackCommit := FNtHdrs32.OptionalHeader.SizeOfStackCommit;
    if nt32.OptionalHeader.SizeOfStackCommit = 0 then nt32.OptionalHeader.SizeOfStackCommit := $1000;
    nt32.OptionalHeader.SizeOfHeapReserve  := $100000; nt32.OptionalHeader.SizeOfHeapCommit  := $1000;
    nt32.OptionalHeader.DllCharacteristics := FNtHdrs32.OptionalHeader.DllCharacteristics and not $0140;
    Move(nt32, out_buf[nt_off], SizeOf(nt32)); sec_off_hdr := nt_off + SizeOf(nt32);

    FillChar(sh, SizeOf(sh), 0);
    sh.Name[0]:='U'; sh.Name[1]:='P'; sh.Name[2]:='X'; sh.Name[3]:='0';
    sh.VirtualSize := upx0_vs; sh.VirtualAddress := upx0_va;
    sh.Characteristics := IMAGE_SCN_CNT_UNINITIALIZED_DATA or IMAGE_SCN_MEM_READ or IMAGE_SCN_MEM_WRITE or IMAGE_SCN_MEM_EXECUTE;
    Move(sh, out_buf[sec_off_hdr], SizeOf(sh)); Inc(sec_off_hdr, IMAGE_SIZEOF_SECTION_HEADER);

    FillChar(sh, SizeOf(sh), 0);
    sh.Name[0]:='U'; sh.Name[1]:='P'; sh.Name[2]:='X'; sh.Name[3]:='1';
    sh.VirtualSize := upx1_vs; sh.VirtualAddress := upx1_va;
    sh.SizeOfRawData := upx1_rs; sh.PointerToRawData := hdr_size;
    sh.Characteristics := IMAGE_SCN_CNT_INITIALIZED_DATA or IMAGE_SCN_MEM_READ or IMAGE_SCN_MEM_WRITE or IMAGE_SCN_MEM_EXECUTE;
    Move(sh, out_buf[sec_off_hdr], SizeOf(sh));

    case method of
      M_NRV2D_LE32: Move(STUB_PE32_NRV2D[0], stub32[0], vkStubSize);
      M_NRV2E_LE32: Move(STUB_PE32_NRV2E[0], stub32[0], vkStubSize);
    else             Move(STUB_PE32_NRV2B[0], stub32[0], vkStubSize); end;

    // patch stub32 (PE32 runtime patches)
    SetLE32(@stub32[9],  LongWord(vkCompDataOff - 6));  // LEA ESI source
    SetLE32(@stub32[15], LongWord(LongInt(rvamin) - LongInt(upx1_va) - LongInt(vkCompDataOff)));  // LEA EDI dest (ESI-relative)
    SetLE32(@stub32[vkPtCI], flat_size);
    if import_dir_rva >= rvamin then SetLE32(@stub32[vkPtSI], import_dir_rva - rvamin)
    else SetLE32(@stub32[vkPtSI], 0);
    SetLE32(@stub32[vkPtLA],  LongWord(LongInt(upx1_va) + vkIATOff + 0 - LongInt(rvamin)));
    SetLE32(@stub32[vkPtGPA], LongWord(LongInt(upx1_va) + vkIATOff + 4 - LongInt(rvamin)));
    SetLE32(@stub32[vkPtEP],  LongWord(LongInt(upx1_va) + vkIATOff + 8 - LongInt(rvamin)));
    SetLE32(@stub32[vkPtOE],  LongWord(LongInt(orig_entry) - LongInt(upx1_va) - LongInt(vkPtHead)));

    PackHeader_Reset(ph); ph.version:=13; ph.format:=UPX_F_W32PE_I386;
    ph.method:=method; ph.level:=level; ph.u_len:=full_len; ph.c_len:=comp_len;
    ph.u_adler:=u_adler; ph.c_adler:=c_adler; ph.u_file_size:=Cardinal(Length(FFileData));
    PackHeader_Put(ph, @stub32[vkPtHead]);
    Move(stub32[0], upx1_raw[0], vkStubSize);

    SetLE32(upx1_raw + vkIATOff + 0, upx1_va + Cardinal(vkHnLaOff));
    SetLE32(upx1_raw + vkIATOff + 4, upx1_va + Cardinal(vkHnGpaOff));
    SetLE32(upx1_raw + vkIATOff + 8, upx1_va + Cardinal(vkHnEpOff));
    SetLE32(upx1_raw + vkINTOff + 0, upx1_va + Cardinal(vkHnLaOff));
    SetLE32(upx1_raw + vkINTOff + 4, upx1_va + Cardinal(vkHnGpaOff));
    SetLE32(upx1_raw + vkINTOff + 8, upx1_va + Cardinal(vkHnEpOff));
    p_raw := upx1_raw + vkIMPDirOff;
    SetLE32(p_raw+ 0, upx1_va + Cardinal(vkINTOff));  SetLE32(p_raw+ 4, 0);
    SetLE32(p_raw+ 8, 0);
    SetLE32(p_raw+12, upx1_va + Cardinal(vkDllNmOff));
    SetLE32(p_raw+16, upx1_va + Cardinal(vkIATOff));
    WriteNameZ(upx1_raw + vkDllNmOff, 'kernel32.dll');
    SetLE16(upx1_raw + vkHnLaOff,  0); WriteNameZ(upx1_raw + vkHnLaOff  + 2, 'LoadLibraryA');
    SetLE16(upx1_raw + vkHnGpaOff, 0); WriteNameZ(upx1_raw + vkHnGpaOff + 2, 'GetProcAddress');
    SetLE16(upx1_raw + vkHnEpOff,  0); WriteNameZ(upx1_raw + vkHnEpOff  + 2, 'ExitProcess');
    Move(compressed[0], upx1_raw[vkCompDataOff], comp_len);
    // write resource section copy into UPX1 so icon/manifest are readable from disk
    if (new_rsrc_rva <> 0) and (Length(rsrc_buf) > 0) then
      Move(rsrc_buf[0], upx1_raw[rsrc_off_in_upx1], Length(rsrc_buf));

    try
      fs := TFileStream.Create(OutFile, fmCreate);
      try fs.Write(out_buf[0], Length(out_buf)); finally fs.Free; end;
      Result := True;
      WriteLn(Format('[PE32] Spakowano: %s -> %s  (%d -> %d bajtów, metoda %d, poziom %d)',
              [FFilePath, OutFile, Cardinal(Length(FFileData)), Length(out_buf), method, level]));
    except on E: Exception do raise Exception.CreateFmt('Nie można zapisać: %s', [E.Message]); end;
    Exit;
  end;

  // ── PE64 path ─────────────────────────────────────────────────────────────
  case method of
    M_NRV2D_LE32: delta := STUB_PE64_NRV2D_SIZE - STUB_PE64_SIZE;
    M_NRV2E_LE32: delta := STUB_PE64_NRV2E_SIZE - STUB_PE64_SIZE;
  else delta := 0; end;
  vkStubSize    := STUB_PE64_SIZE + delta;
  vkIATOff      := 413 + delta; vkINTOff      := 445 + delta;
  vkIMPDirOff   := 477 + delta; vkDllNmOff    := 517 + delta;
  vkHnLaOff     := 530 + delta; vkHnGpaOff    := 546 + delta;
  vkHnEpOff     := 562 + delta; vkCompDataOff := 578 + delta;
  vkPtCI  := 254 + delta; vkPtSI  := 271 + delta;
  vkPtLA  := 284 + delta; vkPtK32 := 313 + delta;
  vkPtGPA := 344 + delta; vkPtEP  := 364 + delta;
  vkPtOE  := 377 + delta; vkPtHead := 381 + delta;

  import_dir_rva  := FNtHdrs64.OptionalHeader.DataDirectory[1].VirtualAddress;
  import_dir_size := FNtHdrs64.OptionalHeader.DataDirectory[1].Size;

  // Warn if TLS callbacks exist (full TLS stub support not yet implemented)
  if FNtHdrs64.OptionalHeader.DataDirectory[9].VirtualAddress <> 0 then
    WriteLn('[WARN] Plik ma katalog TLS. Callbacks TLS nie beda wywolane przez stub UPX. Program moze nie dzialac.');

  // build import stream (64-bit thunks)
  SetLength(imp_stream, 4096); imp_len := 0;
  if (import_dir_rva <> 0) and (import_dir_size >= 20) then begin
    imp_desc_rva := import_dir_rva;
    while True do begin
      imp_desc_off := RvaToOff(imp_desc_rva);
      if (imp_desc_off < 0) or (imp_desc_off + 20 > Length(FFileData)) then Break;
      imp_lookup_rva   := GetLE32(@FFileData[imp_desc_off +  0]);
      imp_dll_name_rva := GetLE32(@FFileData[imp_desc_off + 12]);
      imp_iat_base_rva := GetLE32(@FFileData[imp_desc_off + 16]);
      if imp_iat_base_rva = 0 then Break;
      ImpU32(imp_dll_name_rva - import_dir_rva); ImpU32(imp_iat_base_rva - rvamin);
      imp_dll_name_str := ''; imp_dn_off := RvaToOff(imp_dll_name_rva);
      if imp_dn_off >= 0 then
        while (imp_dn_off < Length(FFileData)) and (FFileData[imp_dn_off] <> 0) do
          begin imp_dll_name_str := imp_dll_name_str + AnsiChar(FFileData[imp_dn_off]); Inc(imp_dn_off); end;
      imp_is_k32 := (LowerCase(string(imp_dll_name_str)) = 'kernel32.dll');
      if imp_lookup_rva <> 0 then imp_thunk_rva := imp_lookup_rva
      else imp_thunk_rva := imp_iat_base_rva;
      while True do begin
        imp_thunk_off := RvaToOff(imp_thunk_rva);
        if (imp_thunk_off < 0) or (imp_thunk_off + 8 > Length(FFileData)) then Break;
        imp_thunk_val := GetLE64(@FFileData[imp_thunk_off]);
        if imp_thunk_val = 0 then Break;
        if (imp_thunk_val and QWord($8000000000000000)) <> 0 then begin
          imp_ordinal := Word(imp_thunk_val and $FFFF);
          ImpByte($FF); ImpU16(imp_ordinal);
        end else begin
          imp_name_rva := Cardinal(imp_thunk_val and $7FFFFFFF);
          imp_name_off := RvaToOff(imp_name_rva);
          if imp_name_off >= 0 then begin
            Inc(imp_name_off, 2); ImpByte($01);
            while (imp_name_off < Length(FFileData)) and (FFileData[imp_name_off] <> 0) do
              begin ImpByte(FFileData[imp_name_off]); Inc(imp_name_off); end;
            ImpByte(0);
          end;
        end;
        Inc(imp_thunk_rva, 8);
      end;
      ImpByte(0); Inc(imp_desc_rva, 20);
    end;
  end;
  ImpU32(0);

  // hdr_blob
  hdr_blob_size := FNtHdrs64.OptionalHeader.SizeOfHeaders;
  if hdr_blob_size > Cardinal(Length(FFileData)) then hdr_blob_size := Cardinal(Length(FFileData));
  if hdr_blob_size = 0 then hdr_blob_size := AlignUp(
    SizeOf(TImageDosHeader) + SizeOf(TImageNtHeaders64)
    + Cardinal(Length(FSections)) * IMAGE_SIZEOF_SECTION_HEADER, fa);

  full_len := flat_size + imp_len + hdr_blob_size + 4;
  SetLength(full_buf, full_len);
  Move(flat_buf[0], full_buf[0], flat_size);
  if imp_len > 0 then Move(imp_stream[0], full_buf[flat_size], imp_len);
  Move(FFileData[0], full_buf[flat_size + imp_len], hdr_blob_size);
  SetLE32(@full_buf[flat_size + imp_len + hdr_blob_size], hdr_blob_size);
  u_adler := upx_adler32(@full_buf[0], full_len);

  SetLength(compressed, full_len + full_len div 8 + 4096);
  comp_len := Cardinal(Length(compressed));
  r := nrv_compress(@full_buf[0], full_len, @compressed[0], comp_len, method, level);
  if r = UPX_E_NOT_COMPRESSIBLE then raise Exception.Create('Plik niekompresowalny');
  if r <> UPX_E_OK then raise Exception.CreateFmt('Błąd kompresji NRV: %d', [r]);
  c_adler := upx_adler32(@compressed[0], comp_len);

  // ── find original resource section for icon/manifest visibility ──────────
  rsrc_orig_rva  := FNtHdrs64.OptionalHeader.DataDirectory[2].VirtualAddress;
  rsrc_orig_size := FNtHdrs64.OptionalHeader.DataDirectory[2].Size;
  rsrc_raw_off := -1; rsrc_raw_size := 0; rsrc_buf := nil;
  if (rsrc_orig_rva <> 0) and (rsrc_orig_size <> 0) then
    for k := 0 to Length(FSections)-1 do
      if (FSections[k].VirtualAddress <= rsrc_orig_rva) and
         (rsrc_orig_rva < FSections[k].VirtualAddress + FSections[k].VirtualSize) and
         (FSections[k].RawOffset > 0) and (FSections[k].RawSize > 0) then begin
        rsrc_raw_off  := FSections[k].RawOffset;
        rsrc_raw_size := FSections[k].RawSize;
        if rsrc_raw_off + Integer(rsrc_raw_size) > Length(FFileData) then
          rsrc_raw_size := Cardinal(Length(FFileData)) - Cardinal(rsrc_raw_off);
        SetLength(rsrc_buf, rsrc_raw_size);
        Move(FFileData[rsrc_raw_off], rsrc_buf[0], rsrc_raw_size);
        Break;
      end;

  hdr_size := AlignUp(SizeOf(TImageDosHeader) + SizeOf(TImageNtHeaders64)
              + 2 * IMAGE_SIZEOF_SECTION_HEADER, fa);
  upx0_va := rvamin; upx0_vs := AlignUp(full_len, sa);
  upx1_va := upx0_va + upx0_vs;
  upx1_rs := AlignUp(Cardinal(vkCompDataOff) + comp_len, fa);
  // append resources after compressed data in UPX1 so they are visible on disk
  rsrc_off_in_upx1 := 0; new_rsrc_rva := 0;
  if (rsrc_raw_size > 0) and (Length(rsrc_buf) > 0) then begin
    rsrc_off_in_upx1 := upx1_rs;
    new_rsrc_rva     := upx1_va + rsrc_off_in_upx1;
    rsrc_delta       := LongInt(new_rsrc_rva) - LongInt(rsrc_orig_rva);
    RelocRsrcDir(@rsrc_buf[0], rsrc_raw_size, 0, rsrc_delta);
    upx1_rs := AlignUp(rsrc_off_in_upx1 + rsrc_raw_size, fa);
  end;
  upx1_vs := AlignUp(upx1_rs, sa);

  SetLength(out_buf, hdr_size + upx1_rs);
  FillChar(out_buf[0], Length(out_buf), 0);
  upx1_raw := @out_buf[hdr_size];

  SetLE16(@out_buf[0], IMAGE_DOS_SIGNATURE);
  nt_off := SizeOf(TImageDosHeader); SetLE32(@out_buf[60], nt_off);

  FillChar(nt64, SizeOf(nt64), 0);
  nt64.Signature := IMAGE_NT_SIGNATURE; nt64.FileHeader.Machine := $8664;
  nt64.FileHeader.NumberOfSections := 2;
  nt64.FileHeader.SizeOfOptionalHeader := SizeOf(TImageOptionalHeader64);
  nt64.FileHeader.Characteristics := $002F;
  nt64.OptionalHeader.Magic := IMAGE_NT_OPTIONAL_HDR64_MAGIC;
  nt64.OptionalHeader.AddressOfEntryPoint := upx1_va;
  nt64.OptionalHeader.ImageBase := FNtHdrs64.OptionalHeader.ImageBase;
  if nt64.OptionalHeader.ImageBase = 0 then nt64.OptionalHeader.ImageBase := $140000000;
  nt64.OptionalHeader.SectionAlignment := sa; nt64.OptionalHeader.FileAlignment := fa;
  nt64.OptionalHeader.MajorSubsystemVersion := 6;
  nt64.OptionalHeader.Subsystem := FNtHdrs64.OptionalHeader.Subsystem;
  if nt64.OptionalHeader.Subsystem = 0 then nt64.OptionalHeader.Subsystem := 3;
  nt64.OptionalHeader.SizeOfHeaders := hdr_size;
  nt64.OptionalHeader.SizeOfImage := upx1_va + upx1_vs;
  nt64.OptionalHeader.NumberOfRvaAndSizes := 16;
  // Copy all original data dirs (resources, exception, debug, loadconfig, etc.)
  Move(FNtHdrs64.OptionalHeader.DataDirectory[0],
       nt64.OptionalHeader.DataDirectory[0],
       16 * SizeOf(TImageDataDirectory));
  // Override with stub-managed directories
  nt64.OptionalHeader.DataDirectory[1].VirtualAddress := upx1_va + Cardinal(vkIMPDirOff);
  nt64.OptionalHeader.DataDirectory[1].Size := 40;
  nt64.OptionalHeader.DataDirectory[12].VirtualAddress := upx1_va + Cardinal(vkIATOff);
  nt64.OptionalHeader.DataDirectory[12].Size := 24;
  // Zero stale/unsafe entries
  FillChar(nt64.OptionalHeader.DataDirectory[4],  SizeOf(TImageDataDirectory), 0); // Security (cert)
  FillChar(nt64.OptionalHeader.DataDirectory[9],  SizeOf(TImageDataDirectory), 0); // TLS (not supported yet)
  FillChar(nt64.OptionalHeader.DataDirectory[11], SizeOf(TImageDataDirectory), 0); // BoundImport (stale)
  // Override resource dir to point to UPX1 copy so icon/manifest are visible on disk
  if new_rsrc_rva <> 0 then begin
    nt64.OptionalHeader.DataDirectory[2].VirtualAddress := new_rsrc_rva;
    nt64.OptionalHeader.DataDirectory[2].Size := rsrc_orig_size;
  end;
  // Preserve original stack/heap sizes
  nt64.OptionalHeader.SizeOfStackReserve := FNtHdrs64.OptionalHeader.SizeOfStackReserve;
  if nt64.OptionalHeader.SizeOfStackReserve = 0 then nt64.OptionalHeader.SizeOfStackReserve := $200000;
  nt64.OptionalHeader.SizeOfStackCommit := FNtHdrs64.OptionalHeader.SizeOfStackCommit;
  if nt64.OptionalHeader.SizeOfStackCommit = 0 then nt64.OptionalHeader.SizeOfStackCommit := $1000;
  nt64.OptionalHeader.SizeOfHeapReserve  := $100000; nt64.OptionalHeader.SizeOfHeapCommit  := $1000;
  nt64.OptionalHeader.DllCharacteristics := FNtHdrs64.OptionalHeader.DllCharacteristics and not $0060;
  Move(nt64, out_buf[nt_off], SizeOf(nt64)); sec_off_hdr := nt_off + SizeOf(nt64);

  FillChar(sh, SizeOf(sh), 0);
  sh.Name[0]:='U'; sh.Name[1]:='P'; sh.Name[2]:='X'; sh.Name[3]:='0';
  sh.VirtualSize := upx0_vs; sh.VirtualAddress := upx0_va;
  sh.Characteristics := IMAGE_SCN_CNT_UNINITIALIZED_DATA or IMAGE_SCN_MEM_READ or IMAGE_SCN_MEM_WRITE or IMAGE_SCN_MEM_EXECUTE;
  Move(sh, out_buf[sec_off_hdr], SizeOf(sh)); Inc(sec_off_hdr, IMAGE_SIZEOF_SECTION_HEADER);

  FillChar(sh, SizeOf(sh), 0);
  sh.Name[0]:='U'; sh.Name[1]:='P'; sh.Name[2]:='X'; sh.Name[3]:='1';
  sh.VirtualSize := upx1_vs; sh.VirtualAddress := upx1_va;
  sh.SizeOfRawData := upx1_rs; sh.PointerToRawData := hdr_size;
  sh.Characteristics := IMAGE_SCN_CNT_INITIALIZED_DATA or IMAGE_SCN_MEM_READ or IMAGE_SCN_MEM_WRITE or IMAGE_SCN_MEM_EXECUTE;
  Move(sh, out_buf[sec_off_hdr], SizeOf(sh));

  case method of
    M_NRV2D_LE32: Move(STUB_PE64_NRV2D[0], stub[0], vkStubSize);
    M_NRV2E_LE32: Move(STUB_PE64_NRV2E[0], stub[0], vkStubSize);
  else             Move(STUB_PE64[0],        stub[0], vkStubSize); end;

  // patch stub (PE64 runtime patches)
  PatchS32(7,  vkCompDataOff - 7 - 4);  // LEA RSI → compressed data
  PatchS32(14, LongInt(rvamin) - LongInt(upx1_va) - LongInt(vkCompDataOff));  // LEA RDI → rvamin
  SetLE32(@stub[vkPtCI], flat_size);
  if import_dir_rva >= rvamin then SetLE32(@stub[vkPtSI], import_dir_rva - rvamin)
  else SetLE32(@stub[vkPtSI], 0);
  PatchS32(vkPtLA,  125);  // CALL [RIP+125] → LoadLibraryA IAT slot
  SetLE32(@stub[vkPtK32], 0);
  PatchS32(vkPtGPA,  73);  // CALL [RIP+73]  → GetProcAddress IAT slot
  PatchS32(vkPtEP,   61);  // JMP  [RIP+61]  → ExitProcess IAT slot
  PatchS32(vkPtOE, LongInt(orig_entry) - LongInt(upx1_va) - LongInt(vkPtOE) - 4);

  PackHeader_Reset(ph); ph.version:=13; ph.format:=UPX_F_W64PE_AMD64;
  ph.method:=method; ph.level:=level; ph.u_len:=full_len; ph.c_len:=comp_len;
  ph.u_adler:=u_adler; ph.c_adler:=c_adler; ph.u_file_size:=Cardinal(Length(FFileData));
  PackHeader_Put(ph, @stub[vkPtHead]);
  Move(stub[0], upx1_raw[0], vkStubSize);

  SetLE64(upx1_raw + vkIATOff +  0, QWord(upx1_va + Cardinal(vkHnLaOff)));
  SetLE64(upx1_raw + vkIATOff +  8, QWord(upx1_va + Cardinal(vkHnGpaOff)));
  SetLE64(upx1_raw + vkIATOff + 16, QWord(upx1_va + Cardinal(vkHnEpOff)));
  SetLE64(upx1_raw + vkINTOff +  0, QWord(upx1_va + Cardinal(vkHnLaOff)));
  SetLE64(upx1_raw + vkINTOff +  8, QWord(upx1_va + Cardinal(vkHnGpaOff)));
  SetLE64(upx1_raw + vkINTOff + 16, QWord(upx1_va + Cardinal(vkHnEpOff)));
  p_raw := upx1_raw + vkIMPDirOff;
  SetLE32(p_raw+ 0, upx1_va + Cardinal(vkINTOff)); SetLE32(p_raw+ 4, 0);
  SetLE32(p_raw+ 8, 0);
  SetLE32(p_raw+12, upx1_va + Cardinal(vkDllNmOff));
  SetLE32(p_raw+16, upx1_va + Cardinal(vkIATOff));
  WriteNameZ(upx1_raw + vkDllNmOff, 'kernel32.dll');
  SetLE16(upx1_raw + vkHnLaOff,  0); WriteNameZ(upx1_raw + vkHnLaOff  + 2, 'LoadLibraryA');
  SetLE16(upx1_raw + vkHnGpaOff, 0); WriteNameZ(upx1_raw + vkHnGpaOff + 2, 'GetProcAddress');
  SetLE16(upx1_raw + vkHnEpOff,  0); WriteNameZ(upx1_raw + vkHnEpOff  + 2, 'ExitProcess');
  Move(compressed[0], upx1_raw[vkCompDataOff], comp_len);
  // write resource section copy into UPX1 so icon/manifest are readable from disk
  if (new_rsrc_rva <> 0) and (Length(rsrc_buf) > 0) then
    Move(rsrc_buf[0], upx1_raw[rsrc_off_in_upx1], Length(rsrc_buf));

  try
    fs := TFileStream.Create(OutFile, fmCreate);
    try fs.Write(out_buf[0], Length(out_buf)); finally fs.Free; end;
    Result := True;
    WriteLn(Format('[PE64] Spakowano: %s -> %s  (%d -> %d bajtów, metoda %d, poziom %d)',
            [FFilePath, OutFile, Cardinal(Length(FFileData)), Length(out_buf), method, level]));
  except on E: Exception do raise Exception.CreateFmt('Nie można zapisać: %s', [E.Message]); end;
end;

function TPeFile.SaveFile(const FileName: string): Boolean;
var fs: TFileStream;
begin
  Result := False;
  try
    fs := TFileStream.Create(FileName, fmCreate);
    try fs.Write(FFileData[0], Length(FFileData)); finally fs.Free; end;
    Result := True;
  except end;
end;

end.
