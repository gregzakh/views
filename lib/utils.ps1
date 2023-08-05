function ConvertTo-StringProperty {
  param([String]$Name, [Int32]$Value, [Switch]$Flags)
  end {
    $map = $VwResources.$Name
    if ($Flags) {
      $map.Keys.ForEach{
        if (($Value -band $map.$_) -eq $map.$_) { $_ }
      }
      return
    }
    $map.Keys.Where{$map.$_ -eq $Value}
  }
}
