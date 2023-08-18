using namespace System.IO

function Invoke-ProxyReader {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory, Position=0)]
    [ValidateScript({!!($script:file = Convert-Path -Path $_ -ErrorAction 0)})]
    [ValidateNotNullOrEmpty()]
    [String]$Path,

    [Parameter(Mandatory, Position=1)]
    [ValidateScript({![String]::IsNullOrEmpty($_)})]
    [ScriptBlock]$Callback
  )

  begin {
    $Path = $file
    if ($PSBoundParameters.Callback) { [void]$PSBoundParameters.Remove('Callback') }

    function script:Get-Block([String]$Name, [ScriptBlock]$Fields) {
      end {
        if (!($var = $ExecutionContext.SessionState.PSVariable.Get($Name)).Value) {
          $var = Set-Variable -Name $Name -Value ([Ordered]@{}) -Scope Script -PassThru
        }

        $Fields.Ast.FindAll({$args[0].CommandElements}, $true).ToArray().ForEach{
          $type, $desc, $pack, $dest = $_.CommandElements.Value[0..3]
          $type = $type -creplace 'Ptr', $Bitness # derives from calling function
          if ($pack -isnot [Int32]) { $dest = $pack && Remove-Variable pack }
          $var.Value[$desc] = $type.EndsWith('s') -and $pack ? $br."Read$($type)"($pack) : $(
            $pack ? $((1..$pack).ForEach{$br."Read$($type)"()}) : $br."Read$($type)"()
          )
        }
      }
    }

    function script:Convert-RvaToRaw([UInt32]$Rva, [UInt32]$Align=$IMAGE_OPTIONAL_HEADER.SectionAlignment) {
      end {
        [ScriptBlock]$Aligner = {
          param([UInt32]$Size) ($Size -band ($Align - 1)) ? (($Size -band ($Align * -1)) + $Align) : $Size
        }

        $Sections.ForEach{
          if (($Rva -ge $_.VirtualAddress) -and ($Rva -lt ($_.VirtualAddress + (& $Aligner $_.VirtualSize)))) {
            return ($Rva - ($_.VirtualAddress - $_.PointerToRawData))
          }
        }
      }
    }

    function script:Get-RawString([UInt32]$Offset, [Switch]$NoMove) {
      end {
        $cur = $fs.Position
        $fs.Position = $Offset
        while (($c = $br.ReadByte())) { $str += [Char]$c }
        if ($NoMove) { $fs.Position = $cur }
        $str
      }
    }
  }
  process {}
  end {
    try {
      $br = [BinaryReader]::new(($fs = [File]::OpenRead($Path)))
      & $Callback
    }
    catch { Write-Verbose $_ }
    finally {
      ($br, $fs).ForEach{ if ($_) { $_.Dispose() } }
    }
  }
}
