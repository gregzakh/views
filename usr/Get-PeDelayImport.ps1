function Get-PeDelayImport {
  [CmdletBinding()]param($Path)

  end {
    Get-PeView -Path $Path -DelayImport -ProxyCallback {
      $fs.Position = Convert-RvaToRaw $Data.RVA $IMAGE_OPTIONAL_HEADER.SectionAlignment
      (1..($Data.Size / 0x20 - 1)).ForEach{ # sizeof(IMAGE_DELAYLOAD_DESCRIPTOR)
        Get-Block IMAGE_DELAYLOAD_DESCRIPTOR {
          UInt32 Attributes
          UInt32 DllNameRVA
          UInt32 ModuleHandleRVA
          UInt32 ImportAddressTableRVA
          UInt32 ImportNameTableRVA
          UInt32 BoundImportAddressTableRVA
          UInt32 UnloadInformationTableRVA
          UInt32 TimeDateStamp
        }
        $module = Get-RawString (Convert-RvaToRaw $IMAGE_DELAYLOAD_DESCRIPTOR.DllNameRVA) -NoMove

        $cursor = $fs.Position
        $impad = Convert-RvaToRaw $IMAGE_DELAYLOAD_DESCRIPTOR.ImportAddressTableRVA
        $thunk = Convert-RvaToRaw $IMAGE_DELAYLOAD_DESCRIPTOR.ImportNameTableRVA

        while (1) {
          if (!($fs.Position = $impad)) { break }
          Get-Block IMAGE_THUNK_DATA {
            UIntPtr AddressOfData
          }
          if (!($IMAGE_THUNK_DATA.AddressOfData)) { break }
          $hexadr = $IMAGE_THUNK_DATA.AddressOfData.ToString('X')
          $impad = $fs.Position

          $fs.Position = $thunk
          Get-Block IMAGE_THUNK_DATA {
            UIntPtr AddressOfData
          }

          if (!($IMAGE_THUNK_DATA.AddressOfData)) { break }
          $thunk = $fs.Position
          $ord, $name = ($IMAGE_THUNK_DATA.AddressOfData -band 0xF0000000) ? (
            $null, "`e[33;1mOrdinal@$($IMAGE_THUNK_DATA.AddressOfData -band 0xFFFF)`e[0m"
          ) : $(
            $fs.Position = Convert-RvaToRaw $IMAGE_THUNK_DATA.AddressOfData
            $br.ReadUInt16().ToString('X'), (Get-RawString $fs.Position)
          )
          [PSCustomObject]@{
            Module = $module
            Address = $hexadr
            Ordinal = $ord
            Name = $name
          }

          $IMAGE_THUNK_DATA = @{}
        }

        $fs.Position = $cursor
        $IMAGE_DELAYLOAD_DESCRIPTOR = @{}
      }
    } -Verbose:$(!!$PSBoundParameters.Verbose)
  }
}

Export-ModuleMember -Function Get-PeDelayImport
