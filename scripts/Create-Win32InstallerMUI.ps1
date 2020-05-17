param([Parameter(Mandatory=$true)]$productName, 
	[Parameter(Mandatory=$true)]$version, 
	[Parameter(Mandatory=$true)]$systemName
)

$cultures = "cs-CZ",
	"da-DK",
	"en-US",
	"nl-NL",
	"fi-FI",
	"fr-FR",
	"de-DE",
	"el-GR",
	"it-IT",
	"ja-JP",
	"nb-NO",
	"pl-PL",
	"pt-PT",
	"ru-RU",
	"es-ES",
	"sv-SE",
	"tr-TR",
	"zh-CN",
	"zh-TW"

# requires WiX install and the env var
$wixBinaryDir = $env:WIX + "bin"
$installerName = "$productName-$version-$systemName"

if(-Not (Test-Path -Path ".\EmbedTransform.exe")) {
	Write-Host "Downloading EmbedTransform from FireGiant (WiX)..."

	try {
		Invoke-WebRequest https://www.firegiant.com/system/files/samples/EmbedTransform.zip -OutFile ".\EmbedTransform.zip"
	}
	
	catch {
		Write-Host "URL for FireGiant has been removed or is not available. Aborting..."
		exit 1
	}

	Write-Host "Extracting EmbedTransform archive..."

	try {
		Expand-Archive -Path ".\EmbedTransform.zip" -DestinationPath "."
	}

	catch {
		Write-Host "EmbedTransform archive missing or corrupt. Aborting..."
		exit 1
	}
}

# create final release msi file
cpack -C Release -D CPACK_PACKAGE_FILE_NAME=$installerName-MUI

foreach($culture in $cultures) {
	if(-Not ($PSCulture -eq $culture)) {
		Write-Host "Creating installer for $culture..."
		cpack -C Release -D CPACK_PACKAGE_FILE_NAME=$installerName-$culture -D CPACK_WIX_CULTURES=$culture
		Write-Host "Creating language transform for $culture..."
		& $wixBinaryDir\torch.exe -p -t language .\$installerName-MUI.msi .\$installerName-$culture.msi -out .\$culture.mst
		Write-Host "Embedding transform for $culture..."
		& $wixBinaryDir\EmbedTransform.exe .\$installerName-MUI.msi .\$culture.mst
	}
}
