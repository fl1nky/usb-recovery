# Measure logical backup bytes before allocating a new package staging tree.
function Assert-PackageBackupBudget([string[]]$Directories, [long]$MaximumBytes) {
    $remaining = $MaximumBytes
    $pending = New-Object 'System.Collections.Generic.Stack[string]'
    foreach ($directory in $Directories) {
        if ([IO.Directory]::Exists($directory)) { $pending.Push($directory) }
    }
    while ($pending.Count) {
        $directory = Get-Item -LiteralPath $pending.Pop() -Force -ErrorAction Stop
        if ($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Linked package backup path.' }
        foreach ($entry in $directory.EnumerateFileSystemInfos()) {
            if ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Linked package backup entry.' }
            if ($entry -is [IO.DirectoryInfo]) { $pending.Push($entry.FullName); continue }
            if ($entry.Length -gt $remaining) {
                throw "Package backup budget exceeded ($MaximumBytes bytes). Review .build/previous-packages and .build/packages or set -MaximumPreviousPackageBytes explicitly. Existing packages are preserved."
            }
            $remaining -= $entry.Length
        }
    }
}
