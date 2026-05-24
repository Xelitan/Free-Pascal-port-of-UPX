{$mode delphi}
{$POINTERMATH ON}
program upx_main;


// UPX Pascal Port
// License: GNU GPL
// Author: www.xelitan.com
//
//  Translated from src/main.cpp, src/options.cpp, src/packmast.cpp
//
//  Usage:
//    upx [options] <file>...
//
//  Options:
//    -1 .. -9        compression level (default: -8)
//    --best          = -10
//    --fast          = -1
//    -d, --decompress  unpack file
//    -t, --test        test (check if correctly packed)
//    -l, --list        list information about packed file
//    --nrv2b         NRV2B method (default)
//    --nrv2d         NRV2D method
//    --nrv2e         NRV2E method
//    -o <file>       output file (instead of overwriting)
//    -v, --verbose   more information
//    --version       display version
//
//  Supported formats:
//    Windows: PE32 (i386), PE32+ (AMD64)
//    Linux:   ELF32, ELF64
//    macOS:   Mach-O 32/64


uses
  SysUtils, Classes,
  upx_types,
  upx_nrv,
  upx_packhead,
  upx_pe,
  upx_elf,
  upx_macho;

// ── file types ────────────────────────────────────────────────────────────────
type
  TFileFormat = (ffUnknown, ffPE32, ffPE64, ffELF32, ffELF64, ffMachO32, ffMachO64);
  TMode = (mPack, mUnpack, mTest, mList);

// ── file format detection ─────────────────────────────────────────────────────

function DetectFormat(const FileName: string): TFileFormat;
var
  fs: TFileStream;
  buf: array[0..63] of Byte;
  hdr_buf: array[0..511] of Byte;
  n, hn: Integer;
  magic32: Cardinal;
  nt_off: Integer;
  opt_magic: Word;
begin
  Result := ffUnknown;
  try
    fs := TFileStream.Create(FileName, fmOpenRead or fmShareDenyWrite);
    try
      n := fs.Read(buf[0], SizeOf(buf));
    finally
      fs.Free;
    end;
  except
    Exit;
  end;
  if n < 4 then Exit;

  magic32 := GetLE32(@buf[0]);

  // ELF
  if (buf[0] = $7F) and (buf[1] = Ord('E')) and (buf[2] = Ord('L')) and (buf[3] = Ord('F')) then
  begin
    if n >= 5 then
      case buf[4] of
        1: Result := ffELF32;
        2: Result := ffELF64;
      end;
    Exit;
  end;

  // Mach-O
  case magic32 of
    MH_MAGIC, MH_CIGAM:       begin Result := ffMachO32; Exit end;
    MH_MAGIC_64, MH_CIGAM_64: begin Result := ffMachO64; Exit end;
    FAT_MAGIC, FAT_CIGAM:     begin Result := ffMachO32; Exit end; // fat – guess 32
  end;

  // PE (MZ header)
  if (buf[0] = Ord('M')) and (buf[1] = Ord('Z')) and (n >= 64) then
  begin
    nt_off := Integer(GetLE32(@buf[60]));
    if (nt_off > 0) and (nt_off < 65536) then
    begin
      try
        fs := TFileStream.Create(FileName, fmOpenRead or fmShareDenyWrite);
        try
          hn := fs.Read(hdr_buf[0], SizeOf(hdr_buf));
          if hn > nt_off + 24 then
          begin
            opt_magic := GetLE16(@hdr_buf[nt_off + 24]);
            case opt_magic of
              $010B: Result := ffPE32;
              $020B: Result := ffPE64;
            end;
          end;
        finally
          fs.Free;
        end;
      except
      end;
    end;
    Exit;
  end;
end;

// ── packed file information ───────────────────────────────────────────────────

procedure PrintPackedInfo(const FileName: string);
var
  fmt: TFileFormat;
  ph: TPackHeader;
  found: Boolean;
  si: Integer;
  pe: TPeFile;
  elf: TElfFile;
  mo: TMachOFile;
begin
  fmt := DetectFormat(FileName);
  found := False;

  case fmt of
    ffPE32, ffPE64:
    begin
      pe := TPeFile.Create;
      try
        if pe.LoadFile(FileName) and pe.FindUPXHeader(ph, si) then
        begin
          WriteLn(Format('%-25s  %7d -> %7d  method=%d lvl=%d  %s',
            [ExtractFileName(FileName), ph.u_len, ph.c_len,
             ph.method, ph.level, 'PE']));
          found := True;
        end;
      finally
        pe.Free;
      end;
    end;
    ffELF32, ffELF64:
    begin
      elf := TElfFile.Create;
      try
        if elf.LoadFile(FileName) and elf.FindUPXHeader(ph, si) then
        begin
          WriteLn(Format('%-25s  %7d -> %7d  method=%d lvl=%d  %s',
            [ExtractFileName(FileName), ph.u_len, ph.c_len,
             ph.method, ph.level, 'ELF']));
          found := True;
        end;
      finally
        elf.Free;
      end;
    end;
    ffMachO32, ffMachO64:
    begin
      mo := TMachOFile.Create;
      try
        if mo.LoadFile(FileName) and mo.FindUPXHeader(ph, si) then
        begin
          WriteLn(Format('%-25s  %7d -> %7d  method=%d lvl=%d  %s',
            [ExtractFileName(FileName), ph.u_len, ph.c_len,
             ph.method, ph.level, 'Mach-O']));
          found := True;
        end;
      finally
        mo.Free;
      end;
    end;
  end;

  if not found then
    WriteLn(FileName + ': not packed by UPX or unknown format');
end;

// ── file processing ───────────────────────────────────────────────────────────

procedure ProcessFile(const InFile, OutFile: string;
                      mode: TMode; method: Integer; level: Integer;
                      verbose: Boolean);
var
  fmt: TFileFormat;
  outname: string;
  pe: TPeFile;
  elf: TElfFile;
  mo: TMachOFile;
begin
  fmt := DetectFormat(InFile);

  if mode = mList then
  begin
    PrintPackedInfo(InFile);
    Exit;
  end;

  if OutFile <> '' then outname := OutFile
  else outname := InFile;

  if verbose then
    WriteLn(Format('Processing: %s  (format: %d)', [InFile, Ord(fmt)]));

  case fmt of
    ffPE32, ffPE64:
    begin
      pe := TPeFile.Create;
      try
        if not pe.LoadFile(InFile) then
          raise Exception.CreateFmt('Cannot load PE file: %s', [InFile]);
        case mode of
          mPack:
          begin
            pe.Pack(outname, method, level);
          end;
          mUnpack:
          begin
            pe.Unpack(outname);
            WriteLn('[PE] Unpacked: ' + InFile + ' -> ' + outname);
          end;
          mTest:
          begin
            if pe.IsPackedUPX then WriteLn(InFile + ': OK - UPX packed')
            else WriteLn(InFile + ': not packed by UPX');
          end;
        end;
      finally
        pe.Free;
      end;
    end;

    ffELF32, ffELF64:
    begin
      elf := TElfFile.Create;
      try
        if not elf.LoadFile(InFile) then
          raise Exception.CreateFmt('Cannot load ELF file: %s', [InFile]);
        case mode of
          mPack:   elf.Pack(outname, method, level);
          mUnpack:
          begin
            elf.Unpack(outname);
            WriteLn('[ELF] Unpacked: ' + InFile + ' -> ' + outname);
          end;
          mTest:
          begin
            if elf.IsPackedUPX then WriteLn(InFile + ': OK - UPX packed')
            else WriteLn(InFile + ': not packed by UPX');
          end;
        end;
      finally
        elf.Free;
      end;
    end;

    ffMachO32, ffMachO64:
    begin
      mo := TMachOFile.Create;
      try
        if not mo.LoadFile(InFile) then
          raise Exception.CreateFmt('Cannot load Mach-O file: %s', [InFile]);
        case mode of
          mPack:   mo.Pack(outname, method, level);
          mUnpack:
          begin
            mo.Unpack(outname);
            WriteLn('[Mach-O] Unpacked: ' + InFile + ' -> ' + outname);
          end;
          mTest:
          begin
            if mo.IsPackedUPX then WriteLn(InFile + ': OK - UPX packed')
            else WriteLn(InFile + ': not packed by UPX');
          end;
        end;
      finally
        mo.Free;
      end;
    end;
  else
    raise Exception.CreateFmt('Unknown or unsupported file format: %s', [InFile]);
  end;
end;

// ── print help ────────────────────────────────────────────────────────────────

procedure PrintHelp;
begin
  WriteLn('UPX ' + UPX_VERSION_STRING + ' Pascal port');
  WriteLn('  NRV2B/2D/2E compression/decompression for PE, ELF, Mach-O');
  WriteLn;
  WriteLn('Usage: upx [options] <file>...');
  WriteLn;
  WriteLn('Modes:');
  WriteLn('  (none)         pack file');
  WriteLn('  -d, --decompress  unpack file');
  WriteLn('  -t, --test        test (check if OK)');
  WriteLn('  -l, --list        list info');
  WriteLn;
  WriteLn('Compression:');
  WriteLn('  -1 .. -9        level (1=fast, 9=slow)');
  WriteLn('  --best          = -10 (maximum)');
  WriteLn('  --fast          = -1');
  WriteLn;
  WriteLn('Methods:');
  WriteLn('  --nrv2b         NRV2B-LE32 (default)');
  WriteLn('  --nrv2d         NRV2D-LE32');
  WriteLn('  --nrv2e         NRV2E-LE32');
  WriteLn('  --nrv2b-8       NRV2B-8bit');
  WriteLn('  --nrv2b-le16    NRV2B-LE16');
  WriteLn;
  WriteLn('Other:');
  WriteLn('  -o <file>       output file');
  WriteLn('  -v, --verbose   more information');
  WriteLn('  --version       version');
  WriteLn('  -h, --help      this help');
end;

// ── main program ──────────────────────────────────────────────────────────────

var
  mode: TMode;
  method: Integer;
  level: Integer;
  verbose: Boolean;
  outFile: string;
  files: TStringList;
  i: Integer;
  arg: string;
  errorCount: Integer;
  infile, outf: string;

begin
  mode    := mPack;
  method  := M_NRV2B_LE32;
  level   := 8;
  verbose := False;
  outFile := '';
  errorCount := 0;

  files := TStringList.Create;
  try
    // ── argument parsing ──────────────────────────────────────────────────
    i := 1;
    while i <= ParamCount do
    begin
      arg := ParamStr(i);

      if (arg = '-h') or (arg = '--help') then
      begin
        PrintHelp; Halt(0);
      end else if arg = '--version' then
      begin
        WriteLn('UPX ' + UPX_VERSION_STRING + ' Pascal port (NRV2B/2D/2E)');
        Halt(0);
      end else if (arg = '-d') or (arg = '--decompress') then
        mode := mUnpack
      else if (arg = '-t') or (arg = '--test') then
        mode := mTest
      else if (arg = '-l') or (arg = '--list') then
        mode := mList
      else if (arg = '-v') or (arg = '--verbose') then
        verbose := True
      else if arg = '--best' then
        level := 10
      else if arg = '--fast' then
        level := 1
      else if arg = '--nrv2b' then
        method := M_NRV2B_LE32
      else if arg = '--nrv2b-8' then
        method := M_NRV2B_8
      else if arg = '--nrv2b-le16' then
        method := M_NRV2B_LE16
      else if arg = '--nrv2d' then
        method := M_NRV2D_LE32
      else if arg = '--nrv2d-8' then
        method := M_NRV2D_8
      else if arg = '--nrv2d-le16' then
        method := M_NRV2D_LE16
      else if arg = '--nrv2e' then
        method := M_NRV2E_LE32
      else if arg = '--nrv2e-8' then
        method := M_NRV2E_8
      else if arg = '--nrv2e-le16' then
        method := M_NRV2E_LE16
      else if (arg = '-o') or (arg = '--output') then
      begin
        Inc(i);
        if i > ParamCount then
        begin
          WriteLn(StdErr, 'Error: missing filename after -o');
          Halt(1);
        end;
        outFile := ParamStr(i);
      end else if (Length(arg) = 2) and (arg[1] = '-')
              and (arg[2] >= '1') and (arg[2] <= '9') then
        level := Ord(arg[2]) - Ord('0')
      else if arg = '--' then
      begin
        // rest are files
        Inc(i);
        while i <= ParamCount do begin files.Add(ParamStr(i)); Inc(i) end;
        Break;
      end else if (Length(arg) > 0) and (arg[1] <> '-') then
        files.Add(arg)
      else begin
        WriteLn(StdErr, 'Unknown option: ' + arg);
        Halt(1);
      end;
      Inc(i);
    end;

    if files.Count = 0 then
    begin
      PrintHelp;
      Halt(1);
    end;

    if verbose then
      WriteLn(Format('Method: %d, Level: %d, Mode: %d', [method, level, Ord(mode)]));

    // ── file processing ───────────────────────────────────────────────────
    for i := 0 to files.Count - 1 do
    begin
      infile := files[i];
      outf   := outFile;

      // if -o not provided, use the same name
      if outf = '' then
        outf := infile;

      try
        ProcessFile(infile, outf, mode, method, level, verbose);
      except
        on E: Exception do
        begin
          WriteLn(StdErr, Format('ERROR [%s]: %s', [infile, E.Message]));
          Inc(errorCount);
        end;
      end;
    end;

  finally
    files.Free;
  end;

  if errorCount > 0 then
    Halt(1)
  else
    Halt(0);
end.
