using namespace System.Linq

function Get-PeExport {
  [CmdletBinding()]param($Path)

  end {
    Get-PeView -Path $Path -Export -ProxyCallback {
      $fs.Position = Convert-RvaToRaw $Data.RVA
      Get-Block IMAGE_EXPORT_DIRECTORY {
        UInt32 Characteristics
        UInt32 TimeDateStamp
        UInt16 MajorVersion
        UInt16 MinorVersion
        UInt32 Name
        UInt32 Base
        UInt32 NumberOfFunctions
        UInt32 NumberOfNames
        UInt32 AddressOfFunctions
        UInt32 AddressOfNames
        UInt32 AddressOfNameOrdinals
      }
      if (!$IMAGE_EXPORT_DIRECTORY.NumberOfFunctions -and !$IMAGE_EXPORT_DIRECTORY.NumberOfNames) {
        throw [InvalidOperationException]::new('Export table is abnormal.')
      }
      $fs.Position = Convert-RvaToRaw $IMAGE_EXPORT_DIRECTORY.AddressOfFunctions
      $funcs = @{}
      (1..$IMAGE_EXPORT_DIRECTORY.NumberOfFunctions).ForEach{
        $fwd = Convert-RvaToRaw ($adr = $br.ReadUInt32())
        $funcs[$IMAGE_EXPORT_DIRECTORY.Base + $_ - 1] = (
          ($Data.RVA -le $adr) -and ($adr -lt ($Data.RVA + $Data.Size))
        ) ? @{Address = ''; Forward = Get-RawString $fwd -NoMove} : @{
          Address = $adr.ToString('X8'); Forward = ''
        }
      }
      if ($IMAGE_EXPORT_DIRECTORY.AddressOfNameOrdinals) {
        $ords = Convert-RvaToRaw $IMAGE_EXPORT_DIRECTORY.AddressOfNameOrdinals
        $fs.Position = Convert-RvaToRaw $IMAGE_EXPORT_DIRECTORY.AddressOfNames
        ($named = (1..$IMAGE_EXPORT_DIRECTORY.NumberOfNames).ForEach{
          $cursor = $fs.Position
          $fs.Position = $ords
          $ord = $br.ReadUInt16() + $IMAGE_EXPORT_DIRECTORY.Base
          $ords = $fs.Position
          $fs.Position = $cursor

          [PSCustomObject]@{
            Ordinal = $ord
            Address = $funcs.$ord.Address
            Name = Get-RawString (Convert-RvaToRaw ($br.ReadUInt32())) -NoMove
            ForwardedTo = $funcs.$ord.Forward
          }
        }) + [Enumerable]::Reverse($funcs.Keys.Where{
          $_ -notin $named.Ordinal -and $funcs.$_.Address -ne '00000000'
        }).ForEach{
          [PSCustomObject]@{
            Ordinal = $_
            Address = $funcs.$_.Address
            Name = '[NONAME]'
            ForwardedTo = $funcs.$_.Forward
          }
        }
      }
      else {
        ($zip = [Enumerable]::Zip(
          [UInt16[]]$funcs.Keys, [String[]]$funcs.Values.Address,
          [Func[UInt16, String, PSCustomObject]]{
            [PSCustomObject]@{Ordinal = $args[0]; Address = $args[1]; Name = '[NONAME]'}
          }
        )) | Sort-Object Ordinal
        $zip.Dispose()
      }
    } -Verbose:(!!$PSBoundParameters.Verbose)
  }
}

Export-ModuleMember -Function Get-PeExport
