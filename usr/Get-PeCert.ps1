using namespace System.Reflection
using namespace System.Security.Cryptography.X509Certificates

function Get-PeCert {
  [CmdletBinding()]param($Path)

  begin {
    function Get-DNComponents([String]$val) {
      end {
        [DirectoryServices.SortOption].Assembly.GetType(
          'System.DirectoryServices.ActiveDirectory.Utils'
        ).GetMethod(
          'GetDNComponents', [BindingFlags]'NonPublic, Static'
        ).Invoke($null, @($crt.$val)).Where{$_.Name -eq 'CN'}.Value
      }
    }
  }
  # process {}
  end {
    Get-PeView -Path $Path -Certificates -ProxyCallback {
      $fs.Position = $Data.RVA
      try {
        [PSCustomObject]@{
          Size = $br.ReadUInt32()
          Revision = '0x{0:X4}' -f $br.ReadUInt16()
          Type = $br.ReadUInt16()
          Valid = ($script:crt = [X509Certificate2]::new(
            $br.ReadBytes($Data.Size - 0x08)
          )).Verify()
          NotBefore = $crt.NotBefore
          NotAfter = $crt.NotAfter
          Issuer = Get-DNComponents Issuer
          Subject = Get-DNComponents Subject
          Thumbprint = $crt.Thumbprint
        }
      }
      catch { Write-Verbose $_ }
      finally {
        if ($crt) { $crt.Dispose() }
      }
    } -Verbose:$(!!$PSBoundParameters.Verbose)
  }
}

Export-ModuleMember -Function Get-PeCert
