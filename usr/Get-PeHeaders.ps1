function Get-PeHeaders {
  [CmdletBinding()]param($Path)

  end {
    $Directories, $Sections = Get-PeView -Path $Path -Headers -Verbose:$(!!$PSBoundParameters.Verbose)
    'FILE HEADER VALUES'
    $IMAGE_FILE_HEADER.Keys.ForEach{
      $tmp = $IMAGE_FILE_HEADER.$_
      switch -regex (($desc = ($_ -creplace '(\B[A-Z])', ' $1').ToLower())) {
        '^mach' { '{0,16} {1}' -f (ConvertTo-StringProperty -Name IMAGE_FILE_MACHINE -Value $tmp), $desc }
        '^char' { "{0,16:X} {1}`n`t`t   {2}" -f $tmp, $desc, ((
          ConvertTo-StringProperty -Name IMAGE_FILE_CHARACTERISTICS -Value $tmp -Flags
        ) -join "`n`t`t   ") }
        default { '{0,16:X} {1}' -f $tmp, $desc }
      }
    }
    'OPTIONAL HEADER VALUES'
    $IMAGE_OPTIONAL_HEADER.Keys.ForEach{
      $tmp = $IMAGE_OPTIONAL_HEADER.$_
      switch -regex (($desc = ($_ -creplace '(\B[A-Z])', ' $1').ToLower())) {
        '^magic'  { '{0,16:X} {1} # (PE32{2})' -f $tmp, $desc, ($tmp -eq 0x20B ? '+' : '')}
        '^dll ch' { "{0,16:X} {1}`n`t`t   {2}" -f $tmp, $desc, ((
          ConvertTo-StringProperty -Name IMAGE_DLLCHARACTERISTICS -Value $tmp -Flags
        ) -join "`n`t`t   ") }
        '^subsys' { '{0,16} {1}' -f $VwResources.IMAGE_SUBSYSTEM[$tmp], $desc }
        'version' { '{0,16} {1}' -f $tmp, $desc }
        default { '{0,16:X} {1}' -f $tmp, $desc }
      }
    }
    $Directories.ForEach{
      '{0,16:X} [{1,8:X}] RVA [size] of {2} Directory' -f $_.RVA, $_.Size, ($_.Name -creplace '(\B[A-Z])', ' $1')
    }
    'SECTIONS'
    Format-Table -InputObject $Sections -Property Name, @{
      Name='VirtSize'; Expression={$_.VirtualSize.ToString('X8')}; Align='Right'
    }, @{Name='VirtAddr'; Expression={$_.VirtualAddress.ToString('X8')}; Align='Right'}, @{
      Name='DataSize'; Expression={$_.SizeOfRawData.ToString('X8')}; Align='Right'
    }, @{Name='RawData'; Expression={$_.PointerToRawData.ToString('X8')}}, @{
      Name='Characteristics'; Expression={
        $(foreach ($key in $VwResources.IMAGE_SCN.Keys) { # prevent `Format-Table` issue
          if (($_.Characteristics -band $VwResources.IMAGE_SCN.$key) -eq $VwResources.IMAGE_SCN.$key) { $key }
        }) -join ', '
      }
    }

    Get-Variable IMAGE_* -Scope Script | Remove-Variable -Scope Script # prevent ghost fields
  }
}

Export-ModuleMember -Function Get-PeHeaders
