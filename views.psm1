if (!(Test-Path variable:VwResources)) {
  Set-Variable -Name VwResources -Value ([PSCustomObject]@{
    IMAGE_FILE_MACHINE = @{
      UNKNOWN = 0x0000; TARGET_HOST = 0x0001; I386 = 0x014c; R3000 = 0x0162; R4000 = 0x0166; R10000 = 0x0168;
      WCEMIPSV2 = 0x0169; ALPHA = 0x0184; SH3 = 0x01a2; SH3DSP = 0x01a3; SH3E = 0x01a4; SH4 = 0x01a6; SH5 = 0x01a8;
      ARM = 0x01c0; THUMB = 0x01c2; ARMNT = 0x01c4; AM33 = 0x01d3; POWERPC = 0x01F0; POWERPCFP = 0x01f1;
      IA64 = 0x0200; MIPS16 = 0x0266; ALPHA64 = 0x0284; MIPSFPU = 0x0366; MIPSFPU16 = 0x0466; TRICORE = 0x0520;
      CEF = 0x0CEF; EBC = 0x0EBC; AMD64 = 0x8664; M32R = 0x9041; ARM64 = 0xAA64; CEE = 0xC0EE
    }
    IMAGE_FILE_CHARACTERISTICS = @{
      RELOCS_STRIPPED = 0x0001; EXECUTABLE_IMAGE = 0x0002; LINE_NUMS_STRIPPED = 0x0004; LOCAL_SYMS_STRIPPED = 0x0008;
      AGGRESIVE_WS_TRIM = 0x0010; LARGE_ADDRESS_AWARE = 0x0020; BYTES_REVERSED_LO = 0x0080; '32BIT_MACHINE' = 0x0100;
      DEBUG_STRIPPED = 0x0200; REMOVABLE_RUN_FROM_SWAP = 0x0400; NET_RUN_FROM_SWAP = 0x0800; SYSTEM = 0x1000;
      DLL = 0x2000; UP_SYSTEM_ONLY = 0x4000; BYTES_REVERSED_HI = 0x8000
    }
    IMAGE_SUBSYSTEM = @(
       'Unknown', 'Native', 'Windows GUI', 'Windows CUI', '???_4', 'OS2 CUI', '???_6', 'POSIX CUI', 'Native Windows',
       'Windows CE GUI', 'EFI Application', 'EFI Boot Service Driver', 'EFI Runtime Driver', 'EFI Rom', 'Xbox',
       '???_15', 'Windows Boot Application', 'Xbox Code Catalog'
    )
    IMAGE_DLLCHARACTERISTICS = @{
      HIGH_ENTROPY_VA =  0x0020; DYNAMIC_BASE = 0x0040; FORCE_INTEGRITY = 0x0080; NX_COMPAT = 0x0100;
      NO_ISOLATION = 0x0200; NO_SEH = 0x0400; NO_BIND = 0x0800; APPCONTAINER = 0x1000; WDM_DRIVER = 0x2000;
      GUARD_CF = 0x4000; TERMINAL_SERVER_AWARE =0x8000
    }
    IMAGE_SCN = @{
      TYPE_NO_PAD = 0x00000008; CNT_CODE = 0x00000020; CNT_INITIALIZED_DATA = 0x00000040;
      CNT_UNINITIALIZED_DATA = 0x00000080; LNK_OTHER = 0x00000100; LNK_INFO = 0x00000200; LNK_REMOVE = 0x00000800;
      LNK_COMDAT = 0x00001000; NO_DEFER_SPEC_EXC = 0x00004000; GPREL = 0x00008000; MEM_FARDATA = 0x00008000;
      MEM_PURGEABLE = 0x00020000; MEM_16BIT = 0x00020000; MEM_LOCKED = 0x00040000; MEM_PRELOAD = 0x00080000;
      ALIGN_1BYTES = 0x00100000; ALIGN_2BYTES = 0x00200000; ALIGN_4BYTES = 0x00300000; ALIGN_8BYTES = 0x00400000;
      ALIGN_16BYTES = 0x00500000; ALIGN_32BYTES = 0x00600000; ALIGN_64BYTES = 0x00700000; ALIGN_128BYTES = 0x00800000;
      ALIGN_256BYTES = 0x00900000; ALIGN_512BYTES = 0x00A00000; ALIGN_1024BYTES = 0x00B00000; ALIGN_2048BYTES = 0x00C00000;
      ALIGN_4096BYTES = 0x00D00000; ALIGN_8192BYTES = 0x00E00000; ALIGN_MASK = 0x00F00000; LNK_NRELOC_OVFL = 0x01000000;
      MEM_DISCARDABLE = 0x02000000; MEM_NOT_CACHED = 0x04000000; MEM_NOT_PAGED = 0x08000000; MEM_SHARED = 0x10000000;
      MEM_EXECUTE = 0x20000000; MEM_READ = 0x40000000; MEM_WRITE = [BitConverter]::ToUInt32(
        [BitConverter]::GetBytes(0x80000000), 0
      )
    }
    IMAGE_RESOURCE_NAME = @(
      '???_0', 'CURSOR', 'BITMAP', 'ICON', 'MENU', 'DIALOG', 'STRING', 'FONTDIR', 'FONT', 'ACCELERATORS', 'RCDATA',
      'MESSAGETABLE', 'GROUP_CURSOR', '???_13', 'GROUP_ICON', '???_15', 'VERSION', 'DLGINCLUDE', '???_18', 'PLUGPLAY',
      'VXD', 'ANICURSOR', 'ANICON', 'HTML', 'MANIFEST'
    )
  }) -Scope Global -Option ReadOnly
}

$MyInvocation.MyCommand.ScriptBlock.Module.OnRemove = {
  Remove-Variable -Name VwResources -Scope Global -Force
}

('lib', 'usr').ForEach{
  (Get-ChildItem -Path "$PSScriptRoot\$_" -Filter *.ps1).ForEach{.$_.FullName}
}
