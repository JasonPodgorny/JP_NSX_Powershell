function Get-NsxTagListing {
	Param(
	  [Parameter(Mandatory=$true)]
	  [string]$nsxManager,

	  [Parameter(Mandatory=$true)]
	  [System.Management.Automation.PSCredential]$Credential
	)

	begin {

		# Extract Username and Password From Credentials
		$username = $Credential.username
		$password = $Credential.GetNetworkCredential().Password
		# Connect to NSX server
		$retryCount = 0
		while ( !$session -and $retryCount -lt 5 ) {
			$session = Connect-JpNsxManager -Server $nsxManager -username $username -password $password
			$retryCount += 1
		}

	}

	process {

		# Get list of tags
		$tags = Get-JpNsxSecurityTags

		# Go through each tag, get list of VM's assigned against it
		# output an object that lists each tag/virtual machine combination
		foreach ( $tag in $tags ) {

			$tag_vm_list = Get-JpNsxSecurityTagAssignment -id $tag.id
	
			foreach ( $vm in $tag_vm_list ) {

				$tagobject = new-object -typename psobject
				$tagobject | Add-Member -MemberType NoteProperty -Name TagName -Value $tag.name
				$tagobject | Add-Member -MemberType NoteProperty -Name VirtualMachine -Value $vm.name
				write-output $tagobject

			}
	
		}

	}

	end {

		# Disconnect from NSX and vCenter servers
		Disconnect-JpNsxManager
	
	}

}


function Get-VmTagListing {
	Param(
	  [Parameter(Mandatory=$true)]
	  [PSobject]$tag_list,

	  [Parameter(Mandatory=$true)]
	  [string]$vmname
	)

	begin {}

	process {

		$tag_list | where { $_.VirtualMachine -like $vmname } | select TagName

	}

	end {	}

}

function Get-TagArrays {
	Param(
	  [Parameter(Mandatory=$true)]
	  [PSobject]$tag_list,

	  [Parameter(Mandatory=$true)]
	  [PSObject]$vm_list
	)

	begin {}

	process {

		$hash = @{}

		foreach ( $tag in $tag_list ) {

			$tagname = $tag.TagName
			$vmname = $tag.VirtualMachine
			if ( $vmname ) {
				if ( $hash[$vmname] ) {
					$hash[$vmname] += ",$tagname"
				}
				else {
					$hash[$vmname] += $tagname
				}
			}
		}

		foreach ( $key in $hash.Keys ) {  
			$vmname = $key
			$taglist = $hash[$key]
	
			$vm_tag_arrays_obj = new-object -typename psobject
			$vm_tag_arrays_obj | Add-Member -MemberType NoteProperty -Name VirtualMachine -Value $vmname
			$vm_tag_arrays_obj | Add-Member -MemberType NoteProperty -Name Tags -Value $taglist
			write-output $vm_tag_arrays_obj
		}

	}

	end {	}

}




# Set Variables
$nsx_manager = "examplensxmanager.example.com"

$date = get-date
$date_string = $date.ToString("MMddyyyy_HHmm")

# Get Credentials
# To allow for aotumated execution, a set of credentials with appropriate permissions can be
# exported to an XML file.    Using Get-Credential it needs to be entered manually each
# time the script is executed.
#$cred = Import-CliXml c:\temp\testcred.xml
#$cred = $(Get-Credential)

$password = get-content credentials.txt | convertto-securestring
$cred = new-object -typename system.management.automation.pscredential -argumentlist "DOMAIN\UserName",$password


# Execute Script
Write-Output "Gathering NSX Tags..."
# Get tags for PROD site
$prod_tags = Get-NsxTagListing -nsxManager $nsx_manager -Credential $cred

Write-Output "Getting list of VM's that have NSX tags..."
$vm_list = $prod_tags | select virtualmachine -Unique

Write-Output "Creating Virtual Machine Tag Applied Arrays..."
$vm_tag_arrays = Get-TagArrays -tag_list $prod_tags -vm_list $vm_list

Write-Output "Sending Arrays To CSV File... "
$vm_tag_arrays | sort -property virtualmachine | Export-Csv csv_files\nsx_tags.$date_string.csv