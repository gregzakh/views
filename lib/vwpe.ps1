using namespace System.Management.Automation

function Get-PeView {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [String]$Path,

    [Parameter()][Alias('h')][Switch]$Headers,
    [Parameter()][Alias('e')][Switch]$Export,
    [Parameter()][Alias('i')][Switch]$Import,
    [Parameter()][Alias('r')][Switch]$Resources,
    [Parameter()][Alias('x')][Switch]$Exception,
    [Parameter()][Alias('s')][Switch]$Certificates,
    [Parameter()][Alias('b')][Switch]$BaseRelocation,
    [Parameter()][Alias('d')][Switch]$Debugs, # plural in case to prevent `Debug` duplication
    [Parameter()][Alias('y')][Switch]$DelayImport,
    [Parameter()][Alias('c')][Switch]$ComDescriptor,

    [Parameter()]
    [ValidateScript({![String]::IsNullOrEmpty($_)})]
    [ScriptBlock]$ProxyCallback
  )

  begin {
    $exclude = ,'Path' + ('', 'Optional').ForEach{ [PSCmdlet]::"$($_)CommonParameters" }
    if ($PSBoundParameters.Callback) { [void]$PSBoundParameters.Remove('Callback') }
    $selector, $RvaAnsSizes = $PSBoundParameters.Keys.Where{$_ -notin $exclude}[0], ('Export',
      'Import', 'Resources', 'Exception', 'Certificates', 'BaseRelocation', 'Debugs',
      'Architecture', 'GlobalPointer', 'ThreadStorage', 'LoadConfiguration', 'BoundImport',
      'ImportAddressTable', 'DelayImport', 'ComDescriptor', 'Reserved'
    )
  }
  # process {}
  end {
    Invoke-ProxyReader -Path $Path -Callback {
      if ($br.ReadUInt16() -ne 0x5A4D) { # ignore obsolete IMAGE_DOS_HEADER fields
        throw [InvalidOperationException]::new('DOS signature has not been found.')
      }
      $fs.Position = 0x3C # IMAGE_DOS_HEADER->e_lfanew
      $fs.Position = $br.ReadInt32() # jump to IMAGE_NT_HEADERS
      if ($br.ReadUInt32() -ne 0x4550) {
        throw [InvalidOperationException]::new('PE signature has not been found.')
      }
      Get-Block IMAGE_FILE_HEADER {
        UInt16 Machine
        UInt16 NumberOfSections
        UInt32 TimeDateStamp
        UInt32 PointerToSymbolTable
        UInt32 NumberOfSymbols
        UInt16 SizeOfOptionalHeader
        UInt16 Characteristics
      }
      $Bitness = (0x20, 0x40)[$IMAGE_FILE_HEADER.SizeOfOptionalHeader / 0x10 - 0x0E]
      Get-Block IMAGE_OPTIONAL_HEADER {
        UInt16 Magic
        Byte   MajorLinkerVersion
        Byte   MinorLinkerVersion
        UInt32 SizeOfCode
        UInt32 SizeOfInitializedData
        UInt32 SizeOfUninitializedData
        UInt32 AddressOfEntryPoint
        UInt32 BaseOfCode
      }
      if ($Bitness -eq 0x20) { Get-Block IMAGE_OPTIONAL_HEADER {UInt32 BaseOfData} }
      Get-Block IMAGE_OPTIONAL_HEADER {
        UIntPtr ImageBase
        UInt32  SectionAlignment
        UInt32  FileAlignment
        UInt16  MajorOperatingSystemVersion
        UInt16  MinorOperatingSystemVersion
        UInt16  MajorImageVersion
        UInt16  MinorImageVersion
        UInt16  MajorSubsystemVersion
        UInt16  MinorSubsystemVersion
        UInt32  Win32VersionValue
        UInt32  SizeOfImage
        UInt32  SizeOfHeaders
        UInt32  Checksum
        UInt16  Subsystem
        UInt16  DllCharacteristics
        UIntPtr SizeOfStackReserve
        UIntPtr SizeOfStackCommit
        UIntPtr SizeOfHeapReserve
        UIntPtr SizeOfHeapCommit
        UInt32  LoaderFlags
        UInt32  NumberOfRvaAndSizes
      }
      if ($IMAGE_OPTIONAL_HEADER.NumberOfRvaAndSizes -ne 0x10) {
        throw [InvalidOperationException]::new('PE directories are abnornal.')
      }
      $script:DataDirectories = (1..$IMAGE_OPTIONAL_HEADER.NumberOfRvaAndSizes).ForEach{
        [PSCustomObject]@{
          Name = $RvaAnsSizes[$_ - 1]
          RVA = $br.ReadUInt32()
          Size = $br.ReadInt32()
        }
      }
      $script:Sections = (1..$IMAGE_FILE_HEADER.NumberOfSections).ForEach{
        [PSCustomObject]@{
          Name = [String]::new($br.ReadBytes(0x08)).Trim("`0")
          VirtualSize = $br.ReadUInt32()
          VirtualAddress = $br.ReadUInt32()
          SizeOfRawData = $br.ReadUInt32()
          PointerToRawData = $br.ReadUInt32()
          PointerToRelocations = $br.ReadUInt32()
          PointerToLinenumbers = $br.ReadUInt32()
          NumberOfRelocations = $br.ReadUInt16()
          NumberOfLinenumbers = $br.ReadUInt16()
          Characteristics = $br.ReadUInt32()
        }
      }
      if ($selector -ne 'Headers') {
        if (!($Data = $DataDirectories.Where{$_.Name -ceq $selector}).RVA) {
          throw [InvalidOperationException]::new("$selector is empty.")
        }
        & $ProxyCallback
      }
    } -Verbose:$(!!$PSBoundParameters.Verbose)

    if ($selector -eq 'Headers') { $DataDirectories, $Sections }
  }
}
