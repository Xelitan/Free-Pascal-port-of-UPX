{$mode delphi}
{$POINTERMATH ON}
unit upx_macho;

// UPX Pascal Port
// License: GNU GPL
// Author: www.xelitan.com
//
// Mach-O (macOS 32/64-bit)
// Translated from src/p_mach.h, src/p_mach.cpp, src/p_mach_enum.h
//
// Supports:
//    - Mach-O 32-bit (i386, ARM, PowerPC32)
//    - Mach-O 64-bit (AMD64, ARM64, PowerPC64)
//    - Fat binary (chooses 1st architekture)


interface

uses upx_types, upx_nrv, upx_packhead, upx_filter, SysUtils, Classes;

const
  // magic numbers
  MH_MAGIC    = $FEEDFACE;   // 32-bit LE
  MH_CIGAM    = $CEFAEDFE;   // 32-bit BE (reversed)
  MH_MAGIC_64 = $FEEDFACF;   // 64-bit LE
  MH_CIGAM_64 = $CFFAEDFE;   // 64-bit BE
  FAT_MAGIC   = $CAFEBABE;   // Fat LE
  FAT_CIGAM   = $BEBAFECA;   // Fat BE

  // typy fileu
  MH_EXECUTE = 2;
  MH_DYLIB   = 6;
  MH_BUNDLE  = 8;

  // architektury
  CPU_TYPE_I386    = 7;
  CPU_TYPE_X86_64  = $01000007;
  CPU_TYPE_ARM     = 12;
  CPU_TYPE_ARM64   = $0100000C;
  CPU_TYPE_POWERPC = 18;
  CPU_TYPE_POWERPC64 = $01000012;

  // rozkazy ładowania
  LC_SEGMENT        = $1;
  LC_SEGMENT_64     = $19;
  LC_UNIXTHREAD     = $5;
  LC_THREAD         = $4;
  LC_LOAD_DYLINKER  = $E;
  LC_MAIN           = $80000028;
  LC_CODE_SIGNATURE = $1D;

  VM_PROT_NONE    = 0;
  VM_PROT_READ    = 1;
  VM_PROT_WRITE   = 2;
  VM_PROT_EXECUTE = 4;

type
  //  Fat header 
  TMachFatHeader = packed record
    magic:     Cardinal;
    nfat_arch: Cardinal;
  end;

  TMachFatArch = packed record
    cputype:    Integer;
    cpusubtype: Integer;
    offset:     Cardinal;
    size:       Cardinal;
    align:      Cardinal;
  end;

  //  Mach-O 32-bit header 
  TMachHeader = packed record
    magic:      Cardinal;
    cputype:    Integer;
    cpusubtype: Integer;
    filetype:   Cardinal;
    ncmds:      Cardinal;
    sizeofcmds: Cardinal;
    flags:      Cardinal;
  end;

  //  Mach-O 64-bit header 
  TMachHeader64 = packed record
    magic:      Cardinal;
    cputype:    Integer;
    cpusubtype: Integer;
    filetype:   Cardinal;
    ncmds:      Cardinal;
    sizeofcmds: Cardinal;
    flags:      Cardinal;
    reserved:   Cardinal;
  end;

  // Load command (common part)
  TMachLoadCommand = packed record
    cmd:     Cardinal;
    cmdsize: Cardinal;
  end;

  // Segment command 32-bit
  TMachSegmentCommand = packed record
    cmd:      Cardinal;
    cmdsize:  Cardinal;
    segname:  array[0..15] of AnsiChar;
    vmaddr:   Cardinal;
    vmsize:   Cardinal;
    fileoff:  Cardinal;
    filesize: Cardinal;
    maxprot:  Integer;
    initprot: Integer;
    nsects:   Cardinal;
    flags:    Cardinal;
  end;

  // Segment command 64-bit
  TMachSegmentCommand64 = packed record
    cmd:      Cardinal;
    cmdsize:  Cardinal;
    segname:  array[0..15] of AnsiChar;
    vmaddr:   QWord;
    vmsize:   QWord;
    fileoff:  QWord;
    filesize: QWord;
    maxprot:  Integer;
    initprot: Integer;
    nsects:   Cardinal;
    flags:    Cardinal;
  end;

  // Section 32-bit 
  TMachSection = packed record
    sectname:  array[0..15] of AnsiChar;
    segname:   array[0..15] of AnsiChar;
    addr:      Cardinal;
    size:      Cardinal;
    offset:    Cardinal;
    align:     Cardinal;
    reloff:    Cardinal;
    nreloc:    Cardinal;
    flags:     Cardinal;
    reserved1: Cardinal;
    reserved2: Cardinal;
  end;

  // Section 64-bit
  TMachSection64 = packed record
    sectname:  array[0..15] of AnsiChar;
    segname:   array[0..15] of AnsiChar;
    addr:      QWord;
    size:      QWord;
    offset:    Cardinal;
    align:     Cardinal;
    reloff:    Cardinal;
    nreloc:    Cardinal;
    flags:     Cardinal;
    reserved1: Cardinal;
    reserved2: Cardinal;
    reserved3: Cardinal;
  end;

  // internal segment represenation
  TMachSegInfo = record
    SegName:  string;
    VMAddr:   QWord;
    VMSize:   QWord;
    FileOff:  QWord;
    FileSz:   QWord;
    MaxProt:  Integer;
    InitProt: Integer;
    Data:     TBytes;
  end;

  //  Mach-O 
  TMachOFile = class
  private
    FIs64:       Boolean;
    FIsLE:       Boolean;
    FCpuType:    Integer;
    FFileType:   Cardinal;
    FHeader32:   TMachHeader;
    FHeader64:   TMachHeader64;
    FSegs:       array of TMachSegInfo;
    FLCData:     TBytes;     // raw load commands
    FFileData:   TBytes;
    FFilePath:   string;
    FFatOffset:  Cardinal;   // offset in fat binary (0 jeśli nie fat)

    function GetLE32f(p: PByte): Cardinal;
    function GetLE64f(p: PByte): QWord;
  public
    constructor Create;
    destructor Destroy; override;
    function LoadFile(const FileName: string): Boolean;
    function IsValid: Boolean;
    function IsPackedUPX: Boolean;
    property Is64: Boolean read FIs64;
    property IsLE: Boolean read FIsLE;
    property CpuType: Integer read FCpuType;
    property FilePath: string read FFilePath;
    function Pack(const OutFile: string; method: Integer; level: Integer): Boolean;
    function Unpack(const OutFile: string): Boolean;
    function FindUPXHeader(out ph: TPackHeader; out segIdx: Integer): Boolean;

  private
    function ParseHeader: Boolean;
    procedure ParseSegments;
    function Decompress(const ph: TPackHeader; cdata: PByte; clen: Cardinal): TBytes;
  end;

implementation

//  helpers 

function TMachOFile.GetLE32f(p: PByte): Cardinal;
begin
  if FIsLE then Result := GetLE32(p)
  else Result := GetBE32(p);
end;

function TMachOFile.GetLE64f(p: PByte): QWord;
begin
  if FIsLE then Result := GetLE64(p)
  else Result := (QWord(GetBE32(p)) shl 32) or QWord(GetBE32(p+4));
end;

//  constructor/destructor 

constructor TMachOFile.Create;
begin
  inherited Create;
  FIs64 := False; FIsLE := True; FFatOffset := 0;
end;

destructor TMachOFile.Destroy;
begin
  inherited Destroy;
end;

//  load the file 

function TMachOFile.LoadFile(const FileName: string): Boolean;
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

function TMachOFile.ParseHeader: Boolean;
var
  magic: Cardinal;
  p: PByte;
  fat_hdr: TMachFatHeader;
  fat_arch: TMachFatArch;
  i: Integer;
begin
  Result := False;
  if Length(FFileData) < 8 then Exit;
  magic := GetLE32(@FFileData[0]);

  // fat binary?
  if (magic = FAT_MAGIC) or (magic = FAT_CIGAM) then
  begin
    // Fat magic is always big-endian
    fat_hdr.magic     := GetBE32(@FFileData[0]);
    fat_hdr.nfat_arch := GetBE32(@FFileData[4]);
    // take the 1st architecture
    if fat_hdr.nfat_arch = 0 then Exit;
    p := @FFileData[8];
    for i := 0 to Integer(fat_hdr.nfat_arch) - 1 do
    begin
      fat_arch.cputype    := Integer(GetBE32(p));
      fat_arch.cpusubtype := Integer(GetBE32(p+4));
      fat_arch.offset     := GetBE32(p+8);
      fat_arch.size       := GetBE32(p+12);
      fat_arch.align      := GetBE32(p+16);
      Inc(p, SizeOf(TMachFatArch));
      // take the 1st
      FFatOffset := fat_arch.offset;
      magic := GetLE32(@FFileData[FFatOffset]);
      Break;
    end;
  end;

  p := @FFileData[FFatOffset];
  case magic of
    MH_MAGIC:    begin FIs64 := False; FIsLE := True  end;
    MH_CIGAM:    begin FIs64 := False; FIsLE := False end;
    MH_MAGIC_64: begin FIs64 := True;  FIsLE := True  end;
    MH_CIGAM_64: begin FIs64 := True;  FIsLE := False end;
  else
    Exit;
  end;

  if FIs64 then
  begin
    if FFatOffset + SizeOf(TMachHeader64) > Cardinal(Length(FFileData)) then Exit;
    Move(FFileData[FFatOffset], FHeader64, SizeOf(TMachHeader64));
    FCpuType  := GetLE32f(@FHeader64.cputype);
    FFileType := GetLE32f(@FHeader64.filetype);
  end else begin
    if FFatOffset + SizeOf(TMachHeader) > Cardinal(Length(FFileData)) then Exit;
    Move(FFileData[FFatOffset], FHeader32, SizeOf(TMachHeader));
    FCpuType  := GetLE32f(@FHeader32.cputype);
    FFileType := GetLE32f(@FHeader32.filetype);
  end;
  Result := True;
end;

function TMachOFile.IsValid: Boolean;
begin
  Result := ParseHeader;
end;

procedure TMachOFile.ParseSegments;
var
  ncmds, sizeofcmds: Cardinal;
  hdr_sz: Cardinal;
  lc_off: Cardinal;
  i: Cardinal;
  p: PByte;
  cmd, cmdsize: Cardinal;
  seg: TMachSegInfo;
  seg_cmd: Cardinal;
  fsz: QWord;
begin
  if FIs64 then
  begin
    ncmds      := GetLE32f(@FHeader64.ncmds);
    sizeofcmds := GetLE32f(@FHeader64.sizeofcmds);
    hdr_sz     := SizeOf(TMachHeader64);
    seg_cmd    := LC_SEGMENT_64;
  end else begin
    ncmds      := GetLE32f(@FHeader32.ncmds);
    sizeofcmds := GetLE32f(@FHeader32.sizeofcmds);
    hdr_sz     := SizeOf(TMachHeader);
    seg_cmd    := LC_SEGMENT;
  end;

  // save load commands
  SetLength(FLCData, sizeofcmds);
  if FFatOffset + hdr_sz + sizeofcmds <= Cardinal(Length(FFileData)) then
    Move(FFileData[FFatOffset + hdr_sz], FLCData[0], sizeofcmds);

  SetLength(FSegs, 0);
  lc_off := 0;
  for i := 0 to ncmds - 1 do
  begin
    if lc_off + 8 > sizeofcmds then Break;
    p       := @FLCData[lc_off];
    cmd     := GetLE32f(p);
    cmdsize := GetLE32f(p+4);
    if cmdsize < 8 then Break;

    if cmd = seg_cmd then
    begin
      FillChar(seg, SizeOf(seg), 0);
      if FIs64 then
      begin
        seg.SegName  := TrimRight(string(AnsiString(PAnsiChar(p+8))));
        seg.VMAddr   := GetLE64f(p+24);
        seg.VMSize   := GetLE64f(p+32);
        seg.FileOff  := GetLE64f(p+40);
        seg.FileSz   := GetLE64f(p+48);
        seg.MaxProt  := Integer(GetLE32f(p+56));
        seg.InitProt := Integer(GetLE32f(p+60));
      end else begin
        seg.SegName  := TrimRight(string(AnsiString(PAnsiChar(p+8))));
        seg.VMAddr   := GetLE32f(p+24);
        seg.VMSize   := GetLE32f(p+28);
        seg.FileOff  := GetLE32f(p+32);
        seg.FileSz   := GetLE32f(p+36);
        seg.MaxProt  := Integer(GetLE32f(p+40));
        seg.InitProt := Integer(GetLE32f(p+44));
      end;
      fsz := seg.FileSz;
      if (fsz > 0) and (FFatOffset + seg.FileOff + fsz <= QWord(Length(FFileData))) then
      begin
        SetLength(seg.Data, fsz);
        Move(FFileData[FFatOffset + seg.FileOff], seg.Data[0], fsz);
      end;
      SetLength(FSegs, Length(FSegs) + 1);
      FSegs[High(FSegs)] := seg;
    end;
    Inc(lc_off, cmdsize);
  end;
end;

//  UPX detection 

function TMachOFile.IsPackedUPX: Boolean;
var ph: TPackHeader; si: Integer;
begin
  Result := FindUPXHeader(ph, si);
end;

function TMachOFile.FindUPXHeader(out ph: TPackHeader; out segIdx: Integer): Boolean;
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
  // binary seek in the whole file
  if Length(FFileData) > 0 then
  begin
    p  := @FFileData[0];
    sz := Length(FFileData);
    if PackHeader_Decode(ph, p, sz) then
    begin
      segIdx := -2; Result := True; Exit;
    end;
  end;
end;

function TMachOFile.Decompress(const ph: TPackHeader;
                               cdata: PByte; clen: Cardinal): TBytes;
var udata: TBytes; udst_len: Cardinal; r: Integer;
begin
  Result := nil;
  SetLength(udata, ph.u_len + ph.u_len div 8 + 256);
  udst_len := Cardinal(Length(udata));
  r := nrv_decompress(cdata, clen, @udata[0], udst_len, ph.method);
  if udst_len <> ph.u_len then
    raise Exception.CreateFmt('NRV decompress error %d (expected %d, got %d)',
                              [r, ph.u_len, udst_len]);
  if (r <> UPX_E_OK) and (r <> UPX_E_INPUT_NOT_CONSUMED)
     and (r <> UPX_E_LOOKBEHIND_OVERRUN) then
    raise Exception.CreateFmt('NRV decompress error %d (expected %d, got %d)',
                              [r, ph.u_len, udst_len]);
  // Reverse call/jump filter before verifying adler32.
  if ph.filter <> UPX_FILTER_NONE then
    ApplyUnfilter(@udata[0], udst_len, ph.filter, ph.filter_cto);
  if upx_adler32(@udata[0], udst_len) <> ph.u_adler then
    raise Exception.Create('Adler32 mismatch after Mach-O decompression');
  SetLength(Result, udst_len);
  Move(udata[0], Result[0], udst_len);
end;

//  unpacking 

function TMachOFile.Unpack(const OutFile: string): Boolean;
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
    raise Exception.Create('UPX header not found – not compressed with UPX');

  if segIdx >= 0 then
    src_ptr := @FSegs[segIdx].Data[0]
  else
    src_ptr := @FFileData[0];

  coff  := ph.buf_offset + Cardinal(PackHeader_GetSize(ph));
  cdata := src_ptr + coff;

  result_data := Decompress(ph, cdata, ph.c_len);

  try
    fs := TFileStream.Create(OutFile, fmCreate);
    try
      fs.Write(result_data[0], Length(result_data));
    finally
      fs.Free;
    end;
    {$IFDEF UNIX}
    FpChmod(PAnsiChar(AnsiString(OutFile)), $755);
    {$ENDIF}
    Result := True;
  except
    on E: Exception do
      raise Exception.CreateFmt('cannot saveać "%s": %s', [OutFile, E.Message]);
  end;
end;

//  packing 

function TMachOFile.Pack(const OutFile: string; method: Integer; level: Integer): Boolean;
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
  out_buf: TBytes;
  hdr_sz: Integer;
  lc_size: Cardinal;
  seg_cmd_sz: Integer;
  total_sz: Cardinal;
  data_off: Cardinal;
  magic_pos: Cardinal;
  seg_vmaddr: QWord;
  fs: TFileStream;

  procedure PutMagicLE32(p: PByte);
  begin
    SetLE32(p,   UPX_MAGIC_LE32);
    SetLE32(p+4, UPX_MAGIC2_LE32);
  end;

  procedure PutStr16(p: PByte; const s: string);
  var i: Integer;
  begin
    FillChar(p[0], 16, 0);
    for i := 1 to Length(s) do
      if i <= 16 then p[i-1] := Byte(s[i]);
  end;

begin
  Result := False;
  if IsPackedUPX then
    raise Exception.Create('file is already compressed with UPX');


  combined_len := Cardinal(Length(FFileData));
  cto_out := 0;
  // ph.u_adler is on the ORIGINAL bytes; unfilter is applied before checking it.
  adler := upx_adler32(@FFileData[0], combined_len);

  //  filter selection based on architecture 
  case FCpuType of
    CPU_TYPE_I386, CPU_TYPE_X86_64:
      if combined_len < $1000000 then filter_id := UPX_FILTER_CTO32_E8E9
      else                            filter_id := UPX_FILTER_CT32_E8E9_BSWPLE;
    CPU_TYPE_ARM:    filter_id := UPX_FILTER_CT24ARM_LE;
    CPU_TYPE_ARM64:  filter_id := UPX_FILTER_CT26ARM_LE;
    CPU_TYPE_POWERPC, CPU_TYPE_POWERPC64: filter_id := UPX_FILTER_PPC;
  else
    filter_id := UPX_FILTER_NONE;
  end;

  SetLength(to_compress, combined_len);
  Move(FFileData[0], to_compress[0], combined_len);
  if filter_id <> UPX_FILTER_NONE then
  begin
    if not ApplyFilter(@to_compress[0], combined_len, filter_id, cto_out) then
    begin
      filter_id := UPX_FILTER_NONE;
      cto_out := 0;
      Move(FFileData[0], to_compress[0], combined_len);
    end;
  end;

  SetLength(compressed, combined_len + combined_len div 8 + 4096);
  comp_len := Cardinal(Length(compressed));
  r := nrv_compress(@to_compress[0], combined_len, @compressed[0], comp_len, method, level);
  if r = UPX_E_NOT_COMPRESSIBLE then
    raise Exception.Create('file cannot be compressed');
  if r <> UPX_E_OK then
    raise Exception.CreateFmt('error when compressing with NRV: %d', [r]);

  //  header UPX 
  PackHeader_Reset(ph);
  ph.version     := 13;
  if FIs64 then begin
    if FCpuType = CPU_TYPE_ARM64 then ph.format := UPX_F_MACH_ARM64
    else ph.format := UPX_F_MACH_AMD64;
  end else begin
    if FCpuType = CPU_TYPE_POWERPC then ph.format := UPX_F_MACH_PPC32
    else if FCpuType = CPU_TYPE_ARM then ph.format := UPX_F_MACH_ARM
    else ph.format := UPX_F_MACH_i386;
  end;
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

  //  build new Mach-O with one segment 
  if FIs64 then begin
    hdr_sz    := SizeOf(TMachHeader64);
    seg_cmd_sz := SizeOf(TMachSegmentCommand64);
  end else begin
    hdr_sz    := SizeOf(TMachHeader);
    seg_cmd_sz := SizeOf(TMachSegmentCommand);
  end;
  lc_size  := Cardinal(seg_cmd_sz);
  data_off := hdr_sz + lc_size;
  total_sz := data_off + PACK_HEADER_SIZE + comp_len;
  seg_vmaddr := $1000; // default virtual offset

  SetLength(out_buf, total_sz);
  FillChar(out_buf[0], total_sz, 0);

  // Mach-O header
  if FIs64 then
  begin
    if FIsLE then SetLE32(@out_buf[0], MH_MAGIC_64)
    else SetBE32(@out_buf[0], MH_MAGIC_64);
    SetLE32(@out_buf[4],  Cardinal(FCpuType));
    SetLE32(@out_buf[8],  0);                        // cpusubtype
    SetLE32(@out_buf[12], MH_EXECUTE);
    SetLE32(@out_buf[16], 1);                        // ncmds
    SetLE32(@out_buf[20], lc_size);
    SetLE32(@out_buf[24], 0);                        // flags
    SetLE32(@out_buf[28], 0);                        // reserved
  end else begin
    if FIsLE then SetLE32(@out_buf[0], MH_MAGIC)
    else SetBE32(@out_buf[0], MH_MAGIC);
    SetLE32(@out_buf[4],  Cardinal(FCpuType));
    SetLE32(@out_buf[8],  0);
    SetLE32(@out_buf[12], MH_EXECUTE);
    SetLE32(@out_buf[16], 1);
    SetLE32(@out_buf[20], lc_size);
    SetLE32(@out_buf[24], 0);
  end;

  // Segment command
  if FIs64 then
  begin
    SetLE32(@out_buf[hdr_sz],   LC_SEGMENT_64);
    SetLE32(@out_buf[hdr_sz+4], Cardinal(seg_cmd_sz));
    PutStr16(@out_buf[hdr_sz+8], '__TEXT');
    SetLE64(@out_buf[hdr_sz+24], seg_vmaddr);
    SetLE64(@out_buf[hdr_sz+32], total_sz);
    SetLE64(@out_buf[hdr_sz+40], 0);               // fileoff
    SetLE64(@out_buf[hdr_sz+48], total_sz);         // filesize
    SetLE32(@out_buf[hdr_sz+56], VM_PROT_READ or VM_PROT_EXECUTE);
    SetLE32(@out_buf[hdr_sz+60], VM_PROT_READ or VM_PROT_EXECUTE);
    SetLE32(@out_buf[hdr_sz+64], 0);               // nsects
    SetLE32(@out_buf[hdr_sz+68], 0);               // flags
  end else begin
    SetLE32(@out_buf[hdr_sz],   LC_SEGMENT);
    SetLE32(@out_buf[hdr_sz+4], Cardinal(seg_cmd_sz));
    PutStr16(@out_buf[hdr_sz+8], '__TEXT');
    SetLE32(@out_buf[hdr_sz+24], Cardinal(seg_vmaddr));
    SetLE32(@out_buf[hdr_sz+28], total_sz);
    SetLE32(@out_buf[hdr_sz+32], 0);
    SetLE32(@out_buf[hdr_sz+36], total_sz);
    SetLE32(@out_buf[hdr_sz+40], VM_PROT_READ or VM_PROT_EXECUTE);
    SetLE32(@out_buf[hdr_sz+44], VM_PROT_READ or VM_PROT_EXECUTE);
    SetLE32(@out_buf[hdr_sz+48], 0);
    SetLE32(@out_buf[hdr_sz+52], 0);
  end;

  //  UPX header and packed data 
  magic_pos := data_off;
  PutMagicLE32(@out_buf[magic_pos]);
  PackHeader_Put(ph, @out_buf[magic_pos]);
  Move(compressed[0], out_buf[magic_pos + PACK_HEADER_SIZE], comp_len);

  //  save a file 
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
    WriteLn(Format('[Mach-O] packed: %s -> %s  (%d -> %d bytes, method %d, level %d)',
            [FFilePath, OutFile, combined_len, Length(out_buf), method, level]));
  except
    on E: Exception do
      raise Exception.CreateFmt('cannot save "%s": %s', [OutFile, E.Message]);
  end;
end;

end.
