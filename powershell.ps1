# Check to see if any ACLs are granted to other groups 
function Get-VulnACL {
  $all_groups = get-adgroup -filter * | ForEach {$_.DistinguishedName}
  $my_groups = (Get-ADPrincipalGroupMembership (Get-ADUser $env:username).distinguishedName).Name
  $my_groups | ForEach-Object {
    $my_group = $_; $all_groups | ForEach-Object {
      if ( ((Get-Acl -Path "AD:$_").Access).IdentityReference -like "*$my_group") {
        Write-Output "$_" 
      }
    }
  }
