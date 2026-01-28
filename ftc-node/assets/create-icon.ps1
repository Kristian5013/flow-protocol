# Create a simple FTC Node icon
Add-Type -AssemblyName System.Drawing

$size = 256
$bitmap = New-Object System.Drawing.Bitmap($size, $size)
$graphics = [System.Drawing.Graphics]::FromImage($bitmap)
$graphics.SmoothingMode = 'AntiAlias'

# Background - dark blue
$bgBrush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(255, 13, 17, 23))
$graphics.FillRectangle($bgBrush, 0, 0, $size, $size)

# Circle - accent blue
$circleBrush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(255, 88, 166, 255))
$graphics.FillEllipse($circleBrush, 20, 20, 216, 216)

# Inner circle - dark
$innerBrush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(255, 22, 27, 34))
$graphics.FillEllipse($innerBrush, 40, 40, 176, 176)

# FTC text
$font = New-Object System.Drawing.Font("Arial", 60, [System.Drawing.FontStyle]::Bold)
$textBrush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(255, 88, 166, 255))
$format = New-Object System.Drawing.StringFormat
$format.Alignment = 'Center'
$format.LineAlignment = 'Center'
$rect = New-Object System.Drawing.RectangleF(0, 0, $size, $size)
$graphics.DrawString("F", $font, $textBrush, $rect, $format)

# Save as PNG first
$pngPath = "$PSScriptRoot\ftc-node.png"
$bitmap.Save($pngPath, [System.Drawing.Imaging.ImageFormat]::Png)

# Convert to ICO
$icon = [System.Drawing.Icon]::FromHandle($bitmap.GetHicon())
$icoPath = "$PSScriptRoot\ftc-node.ico"
$stream = [System.IO.File]::Create($icoPath)
$icon.Save($stream)
$stream.Close()

$graphics.Dispose()
$bitmap.Dispose()

Write-Host "Created: $icoPath"
