{$mode delphi}
program upx;

// UPX Pascal Port
// License: GNU GPL
// Author: www.xelitan.com


uses
  upx_types,
  upx_nrv,
  upx_packhead,
  upx_pe,
  upx_elf,
  upx_macho;

{$R *.res}

// All code is in upx_main.pas
// This unit just glues everything together.
// Compile: fpc upx_main.pas to get a command-line app.
end.
