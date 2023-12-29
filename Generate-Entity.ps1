Set-Location -Path '.\WebService.Database';

$EntityDir = "Entities";
$ContextName = "ApplicationDbContext";

$DbHost = "localhost";
$DbPort = "1433";
$DbName = "App";
$UserName = "SA";
$Password = "P@ssw0rd";

# Npgsql.EntityFrameworkCore.PostgreSQL
# $ConnectionString = "Host=$($DbHost); Port=$($DbPort); Database=$($DbName); Username=$($UserName); Password=$($Password);";

# Microsoft.EntityFrameworkCore.SqlServer
$ConnectionString = "Server=$($DbHost),$($DbPort); Database=$($DbName); User Id=$($UserName); Password=$($Password); TrustServerCertificate=True;";

# Remove folder
Remove-Item -Recurse $EntityDir;

dotnet-ef dbcontext scaffold $ConnectionString Microsoft.EntityFrameworkCore.SqlServer --context $ContextName --data-annotations --force --verbose --output-dir $EntityDir --no-onconfiguring;

# Remove default constructor
# See: https://github.com/dotnet/efcore/issues/12604
(Get-Content "./$($EntityDir)/$($ContextName).cs" -Raw) -replace "(?ms)$($ContextName)\(\).*?public ", "" | Set-Content "./$($EntityDir)/$($ContextName).cs"

Set-Location -Path '..\';
