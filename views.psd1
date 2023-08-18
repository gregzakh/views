@{
  RootModule = 'views.psm1'
  ModuleVersion = '1.0.0.0'
  CompatiblePSEditions = 'Core'
  GUID = '8f3640c1-185e-4b20-9e9f-c3c6e66452bc'
  Author = 'greg zakharov'
  Copyright = 'MIT'
  Description = 'Visual representation of...'
  PowerShellVersion = '7.3'
  FunctionsToExport = @(
    'Get-PeExport'
    'Get-PeHeaders',
    'Get-PeResources'
  )
  FileList = @(
    'lib\proxy.ps1',
    'lib\vwpe.ps1',
    'usr\Get-PeExport.ps1',
    'usr\Get-PeHeaders.ps1',
    'usr\Get-PeResources.ps1',
    'views.psd1',
    'views.psm1'
  )
}
