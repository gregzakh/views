function Get-PeRich {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [ValidateScript({!!($script:file = Convert-Path -Path $_ -ErrorAction 0)})]
    [ValidateNotNullOrEmpty()]
    [String]$Path
  )

  begin {
    $block = {
      [OutputType([Byte[]])]param([UInt16]$o, [UInt16]$c)
      end { (Format-Hex -Path ($Path = $file) -Offset $o -Count $c).Bytes }
    }
  }
  # process {}
  end {
    try {
      if ((Format-Hex -Path $Path -Count 2).Ascii -ne 'MZ') { # checkpoint
        throw [InvalidOperationException]::new('MZ signature has not been found.')
      }

      if (($pe = [BitConverter]::ToUInt32($block.Invoke(0x3C, 0x04), 0)) -eq 0x80 -or $pe -lt 0x80) {
        throw [InvalidOperationException]::new('Rich block has not been found.')
      }

      if (($fix = ($pe - 0x80) % 4)) { $pe -= 0x80 - $fix }
      $raw = ($block.Invoke(0x80, $pe - 0x80) | Group-Object {
        [Math]::Floor($script:i++ / 4)
      }).ForEach{[BitConverter]::ToUInt32($_.Group, 0)}.Where{$_}

      if ($raw[-2] -ne 0x68636952) {
        throw [InvalidOperationException]::new('Rich signature has not been found.')
      }

      $i, $fix, $raw = 0, $raw[-1], $raw[0..($raw.Count - 3)]
      $raw = $raw.ForEach{$_ -bxor $fix}
      if ($raw[0] -ne 0x536E6144) {
        throw [InvalidOperationException]::new('DanS signature has not begin found.')
      }
      ($raw[4..$raw.Count] | Group-Object {[Math]::Floor($script:i++ / 2)}).ForEach{
        [PSCustomObject][Ordered]@{
          ProdId = ($_.Group[0] -shr 0x10) -band 0xFFFF
          Build  = $_.Group[0] -band 0xFFFF
          Count  = $_.Group[1]
        }
      }
    }
    catch { Write-Warning $_ }
  }
}

Export-ModuleMember -Function Get-PeRich
