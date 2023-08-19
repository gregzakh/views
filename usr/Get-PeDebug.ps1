function Get-PeDebug {
  [CmdletBinding()]param($Path)

  begin {
    $DebugType = ('unknown', 'coff', 'cv', 'fpo', 'misc', 'exception', 'fixup',
    'omap to src', 'omap from src', 'borland', 'rsrvd10', 'clsid', 'vc', 'pogo',
    'iltcg', 'mpx', 'repro', '???', 'spgo', '???', 'dllchar') # winnt.h
  }
  end {
    Get-PeView -Path $Path -Debugs -ProxyCallback {
      $fs.Position = Convert-RvaToRaw $Data.RVA
      Format-Table -InputObject (1..($Data.Size / 0x1C)).ForEach{
        Get-Block IMAGE_DEBUG_DIRECTORY {
          UInt32 Characteristics
          UInt32 TimeDateStamp
          UInt16 MajorVersion
          UInt16 MinorVersion
          UInt32 Type
          UInt32 SizeOfData
          UInt32 AddressOfRawData
          UInt32 PointerToRawData
        }
        $cursor = $fs.Position
        $fs.Position = $IMAGE_DEBUG_DIRECTORY.PointerToRawData
        [PSCustomObject]@{
          Time = $IMAGE_DEBUG_DIRECTORY.TimeDateStamp.ToString('X')
          Type = $DebugType[$IMAGE_DEBUG_DIRECTORY.Type]
          Size = $IMAGE_DEBUG_DIRECTORY.SizeOfData.ToString('X')
          RVA  = $IMAGE_DEBUG_DIRECTORY.AddressOfRawData.ToString('X')
          Pointer = $IMAGE_DEBUG_DIRECTORY.PointerToRawData.ToString('X')
          Info = switch ($IMAGE_DEBUG_DIRECTORY.Type) {
            2  { # IMAGE_DEBUG_TYPE_CODEVIEW
              ($sig = [String]::new($br.ReadChars(0x04))) -ceq 'RSDS' ? (
                "Format: $sig, {$([Guid]::new($br.ReadBytes(0x10)))}, $($br.ReadUInt32()), $(
                  [String]::new($br.ReadBytes($IMAGE_DEBUG_DIRECTORY.SizeOfData - 0x18))
                )"
              ) : "Format: $sig, Offset: $($br.ReadUInt32())"
            }
            12 { # IMAGE_DEBUG_TYPE_VC_FEATURE
              "Counts: Pre-VC++ 11.00=$($br.ReadUInt32()), C\C++=$($br.ReadUInt32()), /GC=$(
              $br.ReadUInt32()), /sdl=$($br.ReadUInt32()), guardN=$($br.ReadUInt32())"
            }
            13 { # IMAGE_DEBUG_TYPE_POGO
              [String]::new([Linq.Enumerable]::Reverse($br.ReadChars(0x04)))
            }
            16 { # IMAGE_DEBUG_TYPE_REPRO
              $fs.Position += 0x04
              $br.ReadBytes($IMAGE_DEBUG_DIRECTORY.SizeOfData - 0x04).ForEach{$_.ToString('X2')} -join ' '
            }
            default { '???' }
          } # debug directory description
        }
        $fs.Position = $cursor
        $IMAGE_DEBUG_DIRECTORY = @{}
      }
    } -Verbose:$(!!$PSBoundParameters.Verbose)
  }
}

Export-ModuleMember -Function Get-PeDebug
