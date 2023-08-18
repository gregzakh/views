function Get-PeBaseReloc {
  [CmdletBinding()]param($Path)

  end {
    Get-PeView -Path $Path -BaseRelocation -ProxyCallback {
      $fs.Position = Convert-RvaToRaw $Data.RVA
      while (1) {
        if (!($va = $br.ReadUInt32())) { break }
        [PSCustomObject]@{
          VirtualAddress = '0x{0:X8}' -f $va
          SizeOfBlock = '0x{0:X8}' -f ($sz = $br.ReadUInt32())
          Entries = ($on = $sz / 0x02 - 0x04)
        }
        $fs.Position += $on * 0x02
      }
    } -Verbose:(!!$PSBoundParameters.Verbose)
  }
}

Export-ModuleMember -Function Get-PeBaseReloc
