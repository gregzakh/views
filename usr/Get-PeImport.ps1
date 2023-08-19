using namespace System.Linq

function Get-PeImport {
  [CmdletBinding()]param($Path)

  end {
    Get-PeView -Path $Path -Import -ProxyCallback {
      $fs.Position = Convert-RvaToRaw $Data.RVA
      Format-Table -InputObject $(while (1) {
        Get-Block IMAGE_IMPORT_DESCRIPTOR {
          UInt32 Characteristics
          UInt32 TimeDateStamp
          UInt32 ForwardedChain
          UInt32 Name
          UInt32 FirstThunk
        }
        if ([Enumerable]::All( # the situation when there is no data
          [UInt32[]]$IMAGE_IMPORT_DESCRIPTOR.Values, [Func[UInt32, Boolean]]{$args[0] -eq 0}
        )) { break }
        $module = Get-RawString (Convert-RvaToRaw $IMAGE_IMPORT_DESCRIPTOR.Name) -NoMove

        $cursor = $fs.Position
        $thunk = Convert-RvaToRaw $IMAGE_IMPORT_DESCRIPTOR.FirstThunk

        while (1) {
          if (!($fs.Position = $thunk)) { break }
          Get-Block IMAGE_THUNK_DATA {
            UIntPtr AddressOfData
          }

          if (!$IMAGE_THUNK_DATA.AddressOfData) { break }
          $thunk = $fs.Position
          $ord, $name = ($IMAGE_THUNK_DATA.AddressOfData -band 0xF0000000) ? (
            $null, "`e[33;1mOrdinal@$($IMAGE_THUNK_DATA.AddressOfData -band 0xFFFF)`e[0m"
          ) : $(
            $fs.Position = Convert-RvaToRaw $IMAGE_THUNK_DATA.AddressOfData
            $br.ReadUInt16().ToString('X'), (Get-RawString $fs.Position)
          )
          [PSCustomObject]@{
            Module = $module
            Ordinal = $ord
            Name = $name
          }
          $IMAGE_THUNK_DATA = @{}
        }

        $fs.Position = $cursor
        $IMAGE_IMPORT_DESCRIPTOR = @{}
      }) -AutoSize
    } -Verbose:$(!!$PSBoundParameters.Verbose)
  }
}

Export-ModuleMember -Function Get-PeImport
