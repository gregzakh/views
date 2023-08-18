function Get-PeException {
  [CmdletBinding()]param($Path)

  end {
    Get-PeView -Path $Path -Exception -ProxyCallback {
      $fs.Position = Convert-RvaToRaw $Data.RVA
      while (1) {
        if (!($va = $br.ReadUInt32())) { break }
        [PSCustomObject]@{
          Begin = $va.ToString('X8')
          End = $br.ReadUInt32().ToString('X8')
          Unwind = $br.ReadUInt32().ToString('X8')
        }
      }
    } -Verbose:$(!!$PSBoundParameters.Verbose)
  }
}

Export-ModuleMember -Function Get-PeException
