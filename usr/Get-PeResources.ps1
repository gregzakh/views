function Get-PeResources {
  [CmdletBinding()]param($Path)

  end {
    Get-PeView -Path $Path -Resources -ProxyCallback {
      $rsrc, $entry = ($fs.Position = Convert-RvaToRaw $Data.RVA), {
        param([UInt16]$name, [UInt16]$id, [Boolean]$top)
        end {
          (1..($name + $id)).ForEach{
            [PSCustomObject]@{
              Name = ($$ = $br.ReadUInt32()) -band 0x80000000 ? $(
                $cursor = $fs.Position
                $fs.Position = $rsrc + ($$ -band 0x7FFFFFFF)
                [Text.Encoding]::Unicode.GetString(($br.ReadBytes($br.ReadUInt16() * 2)))
                $fs.Position = $cursor
              ) : $($top ? ($VwResources.IMAGE_RESOURCE_NAME[$$] ?? $$) : $$)
              OffsetToData = $rsrc + ($br.ReadUInt32() -band 0x7FFFFFFF)
            }
          }
        }
      }
      $fmt = "$(,([Char]32)*2){0,-27} (RVA:{1:X8}, Offset:{2:X8}, Size:0x{3:X})"
      $fs.Position += 0x0C # skipping unnecessary fields of IMAGE_RESOURCE_DIRECTORY
      (& $entry $br.ReadUInt16() $br.ReadUInt16() $true).ForEach{
        $_.Name
        $cursor = $fs.Position
        $fs.Position = $_.OffsetToData + 0x0C
        (& $entry $br.ReadUInt16() $br.ReadUInt16()).ForEach{
          $back = $fs.Position
          $fs.Position = $_.OffsetToData + 0x14
          $fs.Position = $rsrc + $br.ReadUInt32() # IMAGE_RESOURCE_DATA_ENTRY
          $fmt -f $_.Name, ($$ = $br.ReadUInt32()), (
            Convert-RvaToRaw $$ $IMAGE_OPTIONAL_HEADER.FileAlignment
          ), $br.ReadUInt32()
          $fs.Position= $back
        }
        $fs.Position = $cursor
      }
    } -Verbose:$(!!$PSBoundParameters.Verbose)
  }
}

Export-ModuleMember -Function Get-PeResources
