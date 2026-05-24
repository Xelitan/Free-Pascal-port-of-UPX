{$mode delphi}
{$POINTERMATH ON}
unit upx_elf;

// UPX Pascal Port
// License: GNU GPL
// Author: www.xelitan.com
//
// ELF file handling (Linux 32/64-bit)
//  Translated from src/p_elf.h, src/p_lx_elf.h, src/p_lx_elf.cpp
//
//  Supports:
//    - ELF32 (i386, ARM32)
//    - ELF64 (AMD64, ARM64, RISC-V64)


interface

uses upx_types, upx_nrv, upx_packhead, upx_filter, SysUtils, Classes;

const
  ELFMAG0 = $7F;
  ELFMAG1 = Ord('E');
  ELFMAG2 = Ord('L');
  ELFMAG3 = Ord('F');
  ELFMAG  = #$7F'ELF';

  ELFCLASSNONE = 0;
  ELFCLASS32   = 1;
  ELFCLASS64   = 2;

  ELFDATANONE  = 0;
  ELFDATA2LSB  = 1; // little endian
  ELFDATA2MSB  = 2; // big endian

  ET_NONE = 0;
  ET_REL  = 1;
  ET_EXEC = 2;
  ET_DYN  = 3;
  ET_CORE = 4;

  EM_386    = 3;
  EM_PPC    = 20;
  EM_PPC64  = 21;
  EM_ARM    = 40;
  EM_X86_64 = 62;
  EM_AARCH64 = 183;
  EM_RISCV  = 243;

  PT_NULL    = 0;
  PT_LOAD    = 1;
  PT_DYNAMIC = 2;
  PT_INTERP  = 3;
  PT_NOTE    = 4;
  PT_SHLIB   = 5;
  PT_PHDR    = 6;

  PF_X = 1;
  PF_W = 2;
  PF_R = 4;

  SHT_NULL     = 0;
  SHT_PROGBITS = 1;
  SHT_SYMTAB   = 2;
  SHT_STRTAB   = 3;
  SHT_NOBITS   = 8;

  SHF_WRITE   = 1;
  SHF_ALLOC   = 2;
  SHF_EXECINSTR = 4;

type
  //  ELF identification (first 16 bytes) 
  TElfIdent = array[0..15] of Byte;

  //  ELF32 header 
  TElf32_Ehdr = packed record
    e_ident:     TElfIdent;
    e_type:      Word;
    e_machine:   Word;
    e_version:   Cardinal;
    e_entry:     Cardinal;
    e_phoff:     Cardinal;
    e_shoff:     Cardinal;
    e_flags:     Cardinal;
    e_ehsize:    Word;
    e_phentsize: Word;
    e_phnum:     Word;
    e_shentsize: Word;
    e_shnum:     Word;
    e_shstrndx:  Word;
  end;

  //  ELF64 header 
  TElf64_Ehdr = packed record
    e_ident:     TElfIdent;
    e_type:      Word;
    e_machine:   Word;
    e_version:   Cardinal;
    e_entry:     QWord;
    e_phoff:     QWord;
    e_shoff:     QWord;
    e_flags:     Cardinal;
    e_ehsize:    Word;
    e_phentsize: Word;
    e_phnum:     Word;
    e_shentsize: Word;
    e_shnum:     Word;
    e_shstrndx:  Word;
  end;

  //  ELF32 program header 
  TElf32_Phdr = packed record
    p_type:   Cardinal;
    p_offset: Cardinal;
    p_vaddr:  Cardinal;
    p_paddr:  Cardinal;
    p_filesz: Cardinal;
    p_memsz:  Cardinal;
    p_flags:  Cardinal;
    p_align:  Cardinal;
  end;

  //  ELF64 program header 
  TElf64_Phdr = packed record
    p_type:   Cardinal;
    p_flags:  Cardinal;
    p_offset: QWord;
    p_vaddr:  QWord;
    p_paddr:  QWord;
    p_filesz: QWord;
    p_memsz:  QWord;
    p_align:  QWord;
  end;

  //  ELF32 section header 
  TElf32_Shdr = packed record
    sh_name:      Cardinal;
    sh_type:      Cardinal;
    sh_flags:     Cardinal;
    sh_addr:      Cardinal;
    sh_offset:    Cardinal;
    sh_size:      Cardinal;
    sh_link:      Cardinal;
    sh_info:      Cardinal;
    sh_addralign: Cardinal;
    sh_entsize:   Cardinal;
  end;

  //  ELF64 section header 
  TElf64_Shdr = packed record
    sh_name:      Cardinal;
    sh_type:      Cardinal;
    sh_flags:     QWord;
    sh_addr:      QWord;
    sh_offset:    QWord;
    sh_size:      QWord;
    sh_link:      Cardinal;
    sh_info:      Cardinal;
    sh_addralign: QWord;
    sh_entsize:   QWord;
  end;

  //  internal segment representation 
  TElfSegment = record
    PType:   Cardinal;
    Offset:  QWord;
    VAddr:   QWord;
    PAddr:   QWord;
    FileSz:  QWord;
    MemSz:   QWord;
    Flags:   Cardinal;
    Align:   QWord;
    Data:    TBytes;
  end;

  //  ELF class 
  TElfFile = class
  private
    FIs64:    Boolean;
    FIsLE:    Boolean;
    FMachine: Word;
    FEhdr32:  TElf32_Ehdr;
    FEhdr64:  TElf64_Ehdr;
    FSegs:    array of TElfSegment;
    FFileData: TBytes;
    FFilePath: string;

    function GetLE16f(p: PByte): Word;
    function GetLE32f(p: PByte): Cardinal;
    function GetLE64f(p: PByte): QWord;
    function GetEntry: QWord;
  public
    constructor Create;
    destructor Destroy; override;
    function LoadFile(const FileName: string): Boolean;
    function IsValid: Boolean;
    function IsPackedUPX: Boolean;
    property Is64: Boolean read FIs64;
    property IsLE: Boolean read FIsLE;
    property FilePath: string read FFilePath;
    function Pack(const OutFile: string; method: Integer; level: Integer): Boolean;
    function Unpack(const OutFile: string): Boolean;
    function FindUPXHeader(out ph: TPackHeader; out segIdx: Integer): Boolean;

  private
    procedure ParseSegments;
    function DecompressSegment(const ph: TPackHeader; cdata: PByte; clen: Cardinal): TBytes;
  end;

implementation

// endianness helpers

function TElfFile.GetLE16f(p: PByte): Word;
begin
  if FIsLE then Result := GetLE16(p)
  else Result := (Word(p[0]) shl 8) or p[1];
end;

function TElfFile.GetLE32f(p: PByte): Cardinal;
begin
  if FIsLE then Result := GetLE32(p)
  else Result := GetBE32(p);
end;

function TElfFile.GetLE64f(p: PByte): QWord;
begin
  if FIsLE then Result := GetLE64(p)
  else begin
    Result := (QWord(GetBE32(p)) shl 32) or QWord(GetBE32(p+4));
    // reverse words
    Result := (QWord(GetBE32(p)) shl 32) or GetBE32(p+4);
  end;
end;

function TElfFile.GetEntry: QWord;
begin
  if FIs64 then Result := FEhdr64.e_entry
  else Result := FEhdr32.e_entry;
end;

//  constructor/destructor 

constructor TElfFile.Create;
begin
  inherited Create;
  FIs64 := False; FIsLE := True;
end;

destructor TElfFile.Destroy;
begin
  inherited Destroy;
end;

// file loading 

function TElfFile.LoadFile(const FileName: string): Boolean;
var fs: TFileStream; sz: Int64;
begin
  Result := False;
  FFilePath := FileName;
  try
    fs := TFileStream.Create(FileName, fmOpenRead or fmShareDenyWrite);
    try
      sz := fs.Size;
      SetLength(FFileData, sz);
      if sz > 0 then fs.Read(FFileData[0], sz);
    finally
      fs.Free;
    end;
  except
    Exit;
  end;
  if not IsValid then Exit;
  ParseSegments;
  Result := True;
end;

function TElfFile.IsValid: Boolean;
var ei: PByte;
begin
  Result := False;
  if Length(FFileData) < 16 then Exit;
  ei := @FFileData[0];
  if (ei[0] <> ELFMAG0) or (ei[1] <> ELFMAG1)
  or (ei[2] <> ELFMAG2) or (ei[3] <> ELFMAG3) then Exit;
  case ei[4] of
    ELFCLASS32: FIs64 := False;
    ELFCLASS64: FIs64 := True;
  else Exit;
  end;
  case ei[5] of
    ELFDATA2LSB: FIsLE := True;
    ELFDATA2MSB: FIsLE := False;
  else Exit;
  end;
  if FIs64 then
  begin
    if Length(FFileData) < SizeOf(TElf64_Ehdr) then Exit;
    Move(FFileData[0], FEhdr64, SizeOf(TElf64_Ehdr));
    FMachine := GetLE16f(@FEhdr64.e_machine);
  end else begin
    if Length(FFileData) < SizeOf(TElf32_Ehdr) then Exit;
    Move(FFileData[0], FEhdr32, SizeOf(TElf32_Ehdr));
    FMachine := GetLE16f(@FEhdr32.e_machine);
  end;
  Result := True;
end;

procedure TElfFile.ParseSegments;
var
  i: Integer;
  ph_off, ph_num, ph_entsz: QWord;
  p: PByte;
  seg: TElfSegment;
begin
  if FIs64 then
  begin
    ph_off   := FEhdr64.e_phoff;
    ph_num   := FEhdr64.e_phnum;
    ph_entsz := FEhdr64.e_phentsize;
  end else begin
    ph_off   := FEhdr32.e_phoff;
    ph_num   := FEhdr32.e_phnum;
    ph_entsz := FEhdr32.e_phentsize;
  end;

  SetLength(FSegs, ph_num);
  for i := 0 to Integer(ph_num) - 1 do
  begin
    p := @FFileData[ph_off + QWord(i) * ph_entsz];
    FillChar(seg, SizeOf(seg), 0);
    if FIs64 then
    begin
      seg.PType  := GetLE32f(p);
      seg.Flags  := GetLE32f(p+4);
      seg.Offset := GetLE64f(p+8);
      seg.VAddr  := GetLE64f(p+16);
      seg.PAddr  := GetLE64f(p+24);
      seg.FileSz := GetLE64f(p+32);
      seg.MemSz  := GetLE64f(p+40);
      seg.Align  := GetLE64f(p+48);
    end else begin
      seg.PType  := GetLE32f(p);
      seg.Offset := GetLE32f(p+4);
      seg.VAddr  := GetLE32f(p+8);
      seg.PAddr  := GetLE32f(p+12);
      seg.FileSz := GetLE32f(p+16);
      seg.MemSz  := GetLE32f(p+20);
      seg.Flags  := GetLE32f(p+24);
      seg.Align  := GetLE32f(p+28);
    end;
    if (seg.FileSz > 0) and (seg.Offset + seg.FileSz <= QWord(Length(FFileData))) then
    begin
      SetLength(seg.Data, seg.FileSz);
      Move(FFileData[seg.Offset], seg.Data[0], seg.FileSz);
    end;
    FSegs[i] := seg;
  end;
end;

//  UPX detection

function TElfFile.IsPackedUPX: Boolean;
var ph: TPackHeader; si: Integer;
begin
  Result := FindUPXHeader(ph, si);
end;

function TElfFile.FindUPXHeader(out ph: TPackHeader; out segIdx: Integer): Boolean;
var i: Integer; p: PByte; sz: Integer;
begin
  Result := False; segIdx := -1;
  for i := 0 to Length(FSegs) - 1 do
    if Length(FSegs[i].Data) > 0 then
    begin
      p  := @FSegs[i].Data[0];
      sz := Length(FSegs[i].Data);
      if PackHeader_Decode(ph, p, sz) then
      begin
        segIdx := i; Result := True; Exit;
      end;
    end;
  // search at the end of file
  if Length(FFileData) > 0 then
  begin
    p  := @FFileData[0];
    sz := Length(FFileData);
    if PackHeader_Decode(ph, p, sz) then
    begin
      segIdx := -2; // -2 = z całego fileu
      Result := True; Exit;
    end;
  end;
end;

function TElfFile.DecompressSegment(const ph: TPackHeader;
                                    cdata: PByte; clen: Cardinal): TBytes;
var udata: TBytes; udst_len: Cardinal; r: Integer;
begin
  Result := nil;
  SetLength(udata, ph.u_len + ph.u_len div 8 + 256);
  udst_len := Cardinal(Length(udata));
  r := nrv_decompress(cdata, clen, @udata[0], udst_len, ph.method);
  if udst_len <> ph.u_len then
    raise Exception.CreateFmt('NRV decompress błąd %d (expected %d bytes, got %d)',
                              [r, ph.u_len, udst_len]);
  if (r <> UPX_E_OK) and (r <> UPX_E_INPUT_NOT_CONSUMED)
     and (r <> UPX_E_LOOKBEHIND_OVERRUN) then
    raise Exception.CreateFmt('NRV decompress błąd %d (expected %d bytes, got %d)',
                              [r, ph.u_len, udst_len]);
  if ph.filter <> UPX_FILTER_NONE then
    ApplyUnfilter(@udata[0], udst_len, ph.filter, ph.filter_cto);
  if upx_adler32(@udata[0], udst_len) <> ph.u_adler then
    raise Exception.Create('Adler32 mismatch after ELF decompression');
  SetLength(Result, udst_len);
  Move(udata[0], Result[0], udst_len);
end;

//  unacking 

function TElfFile.Unpack(const OutFile: string): Boolean;
var
  ph: TPackHeader;
  segIdx: Integer;
  cdata: PByte;
  coff: Cardinal;
  result_data: TBytes;
  fs: TFileStream;
  src_ptr: PByte;
begin
  Result := False;
  if not FindUPXHeader(ph, segIdx) then
    raise Exception.Create('UPX header not found - not compressed with UPX');

  if segIdx >= 0 then
    src_ptr := @FSegs[segIdx].Data[0]
  else
    src_ptr := @FFileData[0];

  coff := ph.buf_offset + Cardinal(PackHeader_GetSize(ph));
  cdata := src_ptr + coff;

  result_data := DecompressSegment(ph, cdata, ph.c_len);

  try
    fs := TFileStream.Create(OutFile, fmCreate);
    try
      fs.Write(result_data[0], Length(result_data));
    finally
      fs.Free;
    end;
    // set execution rights (Unix)
    {$IFDEF UNIX}
    FpChmod(PAnsiChar(AnsiString(OutFile)), $755);
    {$ENDIF}
    Result := True;
  except
    on E: Exception do
      raise Exception.CreateFmt('Cannot save "%s": %s', [OutFile, E.Message]);
  end;
end;

//  packing 

function TElfFile.Pack(const OutFile: string; method: Integer; level: Integer): Boolean;
var
  combined_len: Cardinal;
  compressed: TBytes;
  comp_len: Cardinal;
  r: Integer;
  ph: TPackHeader;
  adler: Cardinal;
  filter_id: Integer;
  cto_out: Byte;
  to_compress: TBytes;
  // new ELF file
  out_buf: TBytes;
  out_pos: Cardinal;
  ehdr_sz, phdr_sz: Integer;
  load_vaddr: QWord;
  load_align: QWord;
  note_sz: Cardinal;
  total_sz: Cardinal;
  fs: TFileStream;
  magic_pos: Cardinal;

  procedure PutMagicLE32(p: PByte);
  begin
    SetLE32(p,   UPX_MAGIC_LE32);
    SetLE32(p+4, UPX_MAGIC2_LE32);
  end;

begin
  Result := False;
  if IsPackedUPX then
    raise Exception.Create('File already compressed with UPX');

  //  packing the whole file 
  combined_len := Cardinal(Length(FFileData));
  cto_out := 0;
  // ph.u_adler is calculated on ORIGINAL bytes (before filtering)
  adler := upx_adler32(@FFileData[0], combined_len);

  //  choose filter
  // x86/x86-64 < 16 MB → CTO E8E9 (0x26); ≥ 16 MB → CT32 bswap_le (0x16).
  // ARM32 LE → 0x50, ARM32 BE → 0x51, ARM64 → 0x52, RISC-V → 0x55.
  // PPC32/64 → 0xD0. Else: no filter.
  case FMachine of
    EM_386, EM_X86_64:
      if combined_len < $1000000 then filter_id := UPX_FILTER_CTO32_E8E9
      else                            filter_id := UPX_FILTER_CT32_E8E9_BSWPLE;
    EM_ARM:   filter_id := UPX_FILTER_CT24ARM_LE;
    EM_AARCH64: filter_id := UPX_FILTER_CT26ARM_LE;
    EM_RISCV: filter_id := UPX_FILTER_AUIPC;
    EM_PPC, EM_PPC64: filter_id := UPX_FILTER_PPC;
  else
    filter_id := UPX_FILTER_NONE;
  end;

  SetLength(to_compress, combined_len);
  Move(FFileData[0], to_compress[0], combined_len);
  if filter_id <> UPX_FILTER_NONE then
  begin
    if not ApplyFilter(@to_compress[0], combined_len, filter_id, cto_out) then
    begin
      // Filtring failed - back to no filter
      filter_id := UPX_FILTER_NONE;
      cto_out := 0;
      Move(FFileData[0], to_compress[0], combined_len);  // bring back unfiltered copy
    end;
  end;

  SetLength(compressed, combined_len + combined_len div 8 + 4096);
  comp_len := Cardinal(Length(compressed));
  r := nrv_compress(@to_compress[0], combined_len, @compressed[0], comp_len, method, level);
  if r = UPX_E_NOT_COMPRESSIBLE then
    raise Exception.Create('File cannot be compressed');
  if r <> UPX_E_OK then
    raise Exception.CreateFmt('Error when compressing with NRV: %d', [r]);

  //  UPX  header
  PackHeader_Reset(ph);
  ph.version     := 13;
  if FIs64 then
    ph.format := UPX_F_LINUX_ELF64_AMD64
  else
    ph.format := UPX_F_LINUX_ELF_i386;
  ph.method      := method;
  ph.level       := level;
  ph.u_len       := combined_len;
  ph.c_len       := comp_len;
  ph.u_adler     := adler;
  ph.c_adler     := upx_adler32(@compressed[0], comp_len);
  ph.u_file_size := combined_len;
  ph.filter      := filter_id;
  ph.filter_cto  := cto_out;
  ph.n_mru       := 0;

  //  build new ELF
  if FIs64 then begin ehdr_sz := SizeOf(TElf64_Ehdr); phdr_sz := SizeOf(TElf64_Phdr) end
  else begin ehdr_sz := SizeOf(TElf32_Ehdr); phdr_sz := SizeOf(TElf32_Phdr) end;

  load_vaddr := $08048000; // default loading address for i386
  if FIs64 then load_vaddr := $400000;
  load_align := $1000;

  note_sz := PACK_HEADER_SIZE + comp_len;
  total_sz := ehdr_sz + phdr_sz + note_sz;

  SetLength(out_buf, total_sz);
  FillChar(out_buf[0], total_sz, 0);

  // ELF id
  out_buf[0] := ELFMAG0; out_buf[1] := ELFMAG1;
  out_buf[2] := ELFMAG2; out_buf[3] := ELFMAG3;
  if FIs64 then out_buf[4] := ELFCLASS64 else out_buf[4] := ELFCLASS32;
  if FIsLE  then out_buf[5] := ELFDATA2LSB else out_buf[5] := ELFDATA2MSB;
  out_buf[6] := 1; // current version EV_CURRENT
  // other bytes ident = 0

  if not FIs64 then
  begin
    SetLE16(@out_buf[16], ET_EXEC);
    SetLE16(@out_buf[18], EM_386);
    SetLE32(@out_buf[20], 1);                        // version e
    SetLE32(@out_buf[24], Cardinal(load_vaddr) + ehdr_sz + phdr_sz); // entry point e
    SetLE32(@out_buf[28], ehdr_sz);                  // shift e_phoff
    SetLE32(@out_buf[32], 0);                        // shift e_shoff
    SetLE32(@out_buf[36], 0);                        // flag e
    SetLE16(@out_buf[40], ehdr_sz);                  // size e_ehsize
    SetLE16(@out_buf[42], phdr_sz);                  // size e_phentsize
    SetLE16(@out_buf[44], 1);                        // number of e_phnum
    SetLE16(@out_buf[46], SizeOf(TElf32_Shdr));      // sie e_shentsize
    SetLE16(@out_buf[48], 0);                        // number of e_shnum
    SetLE16(@out_buf[50], 0);                        // e_shstrndx index
    // nagłówek programu
    out_pos := ehdr_sz;
    SetLE32(@out_buf[out_pos],    PT_LOAD);
    SetLE32(@out_buf[out_pos+4],  0);                // shirt
    SetLE32(@out_buf[out_pos+8],  Cardinal(load_vaddr));
    SetLE32(@out_buf[out_pos+12], Cardinal(load_vaddr));
    SetLE32(@out_buf[out_pos+16], total_sz);         // filesize
    SetLE32(@out_buf[out_pos+20], total_sz);         // mem size
    SetLE32(@out_buf[out_pos+24], PF_R or PF_W or PF_X);
    SetLE32(@out_buf[out_pos+28], Cardinal(load_align));
  end else begin
    SetLE16(@out_buf[16], ET_EXEC);
    SetLE16(@out_buf[18], EM_X86_64);
    SetLE32(@out_buf[20], 1);
    SetLE64(@out_buf[24], load_vaddr + ehdr_sz + phdr_sz);
    SetLE64(@out_buf[32], ehdr_sz);
    SetLE64(@out_buf[40], 0);
    SetLE32(@out_buf[48], 0);
    SetLE16(@out_buf[52], ehdr_sz);
    SetLE16(@out_buf[54], phdr_sz);
    SetLE16(@out_buf[56], 1);
    SetLE16(@out_buf[58], SizeOf(TElf64_Shdr));
    SetLE16(@out_buf[60], 0);
    SetLE16(@out_buf[62], 0);
    out_pos := ehdr_sz;
    SetLE32(@out_buf[out_pos],   PT_LOAD);
    SetLE32(@out_buf[out_pos+4], PF_R or PF_W or PF_X);
    SetLE64(@out_buf[out_pos+8], 0);
    SetLE64(@out_buf[out_pos+16], load_vaddr);
    SetLE64(@out_buf[out_pos+24], load_vaddr);
    SetLE64(@out_buf[out_pos+32], total_sz);
    SetLE64(@out_buf[out_pos+40], total_sz);
    SetLE64(@out_buf[out_pos+48], load_align);
  end;

  // save UPX header and packed data
  magic_pos := ehdr_sz + phdr_sz;
  PutMagicLE32(@out_buf[magic_pos]);
  PackHeader_Put(ph, @out_buf[magic_pos]);
  Move(compressed[0], out_buf[magic_pos + PACK_HEADER_SIZE], comp_len);

  // save file 
  try
    fs := TFileStream.Create(OutFile, fmCreate);
    try
      fs.Write(out_buf[0], Length(out_buf));
    finally
      fs.Free;
    end;
    {$IFDEF UNIX}
    FpChmod(PAnsiChar(AnsiString(OutFile)), $755);
    {$ENDIF}
    Result := True;
    WriteLn(Format('[ELF] packed: %s -> %s  (%d -> %d bytes, method %d, level %d)',
            [FFilePath, OutFile, combined_len, Length(out_buf), method, level]));
  except
    on E: Exception do
      raise Exception.CreateFmt('Cannot save "%s": %s', [OutFile, E.Message]);
  end;
end;

end.
