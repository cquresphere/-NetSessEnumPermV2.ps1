#Registry Key Information
$key = "HKLM:SYSTEM\CurrentControlSet\Services\LanmanServer\DefaultSecurity"
$name = "SrvsvcSessionInfo"

#Get the Registry Key and Value
$Reg_Key = Get-Item -Path $key
$ByteValue = $reg_Key.GetValue($name, $null)

#Create a CommonSecurityDescriptor Object using the Byte Value
$Security_Descriptor = New-Object -TypeName System.Security.AccessControl.CommonSecurityDescriptor -ArgumentList $true, $false, $ByteValue, 0

# Resolve SIDs
$TableContent = @()
$Security_DescriptorDACL = $Security_Descriptor.DiscretionaryAcl

Foreach($i in $Security_DescriptorDACL){
    $SID =$i.SecurityIdentifier
    $objSID = New-Object System.Security.Principal.SecurityIdentifier($SID)

    try{

        $objUser = $objSID.Translate([System.Security.Principal.NTAccount]) 
        $UserName = $objUser.Value
    }
    catch {
        $UserName = 'Unidentified'
    }
    

    $Item = [Pscustomobject] @{
        'UserName' = $UserName
        'SecurityIdentifier' = $i.SecurityIdentifier
        'AceType' = $i.AceType
        'IsInherited' = $i.IsInherited 
    }
    $TableContent += $Item
}

#Output of the ACL to make it simple to see for document.
$TableContent | Select-Object UserName, SecurityIdentifier, ACEType, IsInherited  | Format-Table -AutoSize
