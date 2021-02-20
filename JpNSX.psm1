## JP NSX Module - Powershell 4.0 + PowerCLI 5.8 release 1

function Ignore-SSL-Errors {
	### Ignore TLS/SSL errors	
	add-type @"
	    using System.Net;
	    using System.Security.Cryptography.X509Certificates;
	    public class TrustAllCertsPolicy : ICertificatePolicy {
	        public bool CheckValidationResult(
	            ServicePoint srvPoint, X509Certificate certificate,
	            WebRequest request, int certificateProblem) {
	            return true;
	        }
	    }
"@
	[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
}

function Connect-JpNSXManager {
	<#
		.SYNOPSIS
			Connects to a NSX Manager Server.
		.DESCRIPTION
			Connects to a NSX Manager Server. The cmdlet starts a new session with a NSX Manager Server using the specified parameters.
		.PARAMETER  Server
			Specify the IP address or the DNS name of the vSphere server to which you want to connect.
		.PARAMETER  Username
			Specify the user name you want to use for authenticating with the server. 
		.PARAMETER  Password
			Specifies the password you want to use for authenticating with the server.
		.EXAMPLE
			PS C:\> Connect-JpNSXManager -server "192.168.0.88" -username "admin" -password "default"
	#>
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory=$True,
            ValueFromPipeline=$True,
            HelpMessage="NSX Manager IP or FQDN")]
		[string]$Server,
		[Parameter(Mandatory=$True)]
		[string]$Username,
		[Parameter(Mandatory=$True)]
		[string]$Password
	)
	
	begin {
		Ignore-SSL-Errors	
	}
	
	process {
		Write-Debug "Connecting to NSX Manager at $server"
		if ($Global:DefaultNSXManager) {
			$current_server_name = ($Global:DefaultNSXManager.name)
			Write-Warning "Cannot connect - already connected to NSX Manager $current_server_name"
			return		
		}	
		try {	
			$connection_ok = $true
			#Building the headers
			$auth = $Username + ':' + $Password
			$Encoded = [System.Text.Encoding]::UTF8.GetBytes($auth)
			$EncodedPassword = [System.Convert]::ToBase64String($Encoded)
			$headers = @{"Authorization"="Basic $($EncodedPassword)";}
			$heartbeat_uri = "https://" + "$server" + "/api/2.0/global/heartbeat"
			$session = Invoke-RestMethod -Headers $headers -Uri $heartbeat_uri -Method Get -ContentType Application/xml -Timeout 10
		} catch {
			Write-Warning "Failed to connect to NSX Manager $server"
			Write-Debug "$_"
			$connection_ok = $false
		}
		if ($connection_ok) {
			Write-Debug "Successfully connected to NSX Manager at $server"					
			$obj = New-Object -TypeName PSObject -Property @{
				Name = $server
				ServerUri = "https://$server/"
				Authorization = $headers
			}	
			$Global:DefaultNSXManager = $obj
			Write-Output $obj
		}
	}	
}

function Disconnect-JpNSXManager {
	<#
		.SYNOPSIS
			Disconnects NSX Manager Session.
		.DESCRIPTION
			Disconnects from a NSX Manager Server. The cmdlet stops a session with a NSX Manager Server.
		.EXAMPLE
			PS C:\> Disconnect-JpNSXManager 
	#>
	[CmdletBinding()]
	Param ()
	
	begin {}
	
	process {
		
		if ($Global:DefaultNSXManager) {
			$current_server_name = ($Global:DefaultNSXManager.name)
			Write-Debug "Disconnecting from NSX Manager $current_server_name"
			$Global:DefaultNSXManager = $null
			return		
		} else { 
			Write-Warning "Not connected to a NSX Manager"
		}
	
	}
	
}

#Declare the GET function
Function Calling-Get {
	[CmdletBinding()]
	param (
		$Url
	)
	begin {
		Ignore-SSL-Errors	
	}
	process {	
		Write-Debug "Invoking REST GET at URL $url"	
		if ( !$Global:DefaultNSXManager ) {		
			Write-Warning "Must connect to NSX Manager before attempting GET"
			return
		}	
		try {
			$headers = ($Global:DefaultNSXManager.Authorization)		
			Invoke-RestMethod -Headers $headers -Uri $url -Method Get -ContentType Application/xml 
		} catch { 
			Write-Warning "$_"
			Write-Warning "Get Failed at - $url"
		}		
	
	}
}

Function Calling-Put {
	[CmdletBinding()]
	param (
		$Url,
		$Body
	)
	begin {	
		Ignore-SSL-Errors
	}
	process { 
		Write-Debug "Invoking REST PUT at URL $url"	
		if ( !$Global:DefaultNSXManager ) {
			Write-Warning "Must connect to NSX Manager before attempting PUT"
			return
		}
		try {
		    $headers = ($Global:DefaultNSXManager.Authorization)	

			Invoke-RestMethod -Headers $headers -Uri $url -Body $Body -Method Put -ContentType Application/xml 
		} catch { 
			Write-Warning "$_"
			Write-Warning "Put Failed at - $url"
		}
	}
}

#Declare the POST function
Function Calling-Post {
	[CmdletBinding()]
	param (
		$Url,
		$Body
	)
	begin {
		Ignore-SSL-Errors	
	}
	process {
		Write-Debug "Invoking REST POST at URL $url"	
		if ( !$Global:DefaultNSXManager ) {
			Write-Warning "Must connect to NSX Manager before attempting POST"
			return
		}
		try {
		    $headers = ($Global:DefaultNSXManager.Authorization)
			Invoke-RestMethod -Headers $headers -Uri $url -Body $Body -Method Post -ContentType Application/xml -TimeOutSec 300
		} catch { 
			Write-Warning "$_" 
			Write-Warning "Post Failed at - $url"
		}
	}
}

#Declare the DELETE function
Function Calling-Delete {
	[CmdletBinding()]
	param (
		$Url
	)
	begin {
		Ignore-SSL-Errors	
	}
	process {	
		Write-Debug "Invoking REST DELETE at URL $url"	
		if ( !$Global:DefaultNSXManager ) {		
			Write-Warning "Must connect to NSX Manager before attempting DELETE"
			return
		}	
		try {
			$headers = ($Global:DefaultNSXManager.Authorization)		
			Invoke-RestMethod -Headers $headers -Uri $url -Method Delete -ContentType Application/xml 
		} catch { 
			Write-Warning "$_"
			Write-Warning "Delete Failed at - $url"
		}		
	
	}
}

function Get-JpNSXSecurityTags {
	<#
		.SYNOPSIS
			Gets NSX Security Tag Information
		.DESCRIPTION
			Gets NSX Security Tag Information
		.PARAMETER  Name
			NSX Security Tag Name(s) to list.  Lists all security tags if left blank
		.EXAMPLE
			PS C:\> Get-JpNSXSecurityTags
		.EXAMPLE
			PS C:\> Get-JpNSXSecurityTags -name NSX-edge-1,NSX-edge-2
	#>
	[CmdletBinding()]
	param(
		[Parameter(ValueFromPipeline=$True,
            HelpMessage="NSX Security Tag Names")]
		[string[]]$Name
	)
	
	begin {} 
	
	process { 
		Write-Debug "Getting NSX Security Tags"
		$url = "$($Global:DefaultNSXManager.ServerURI)api/2.0/services/securitytags/tag"
		[xml]$security_tag_list = Calling-Get -url $url
		foreach ($security_tag in $security_tag_list.securityTags.securityTag) {
			$obj = New-Object -type PSObject -Property @{
				"name" = $security_tag.name
				"id" = $security_tag.objectId
				"vmcount" = $security_tag.vmCount
			}
			if ( $name ) { 
				foreach ( $tag_name in $name ) {
					if ($obj.name -eq $tag_name) {
						write-output $obj
					}
				}
			} else {
				write-output $obj
			}
		}
	}
	
}

function Get-JpNSXSecurityTagAssignment {
	<#
		.SYNOPSIS
			Gets NSX Security Tag Assignment Information
		.DESCRIPTION
			Gets NSX Security Tag Assignment Information
		.PARAMETER  Name
			NSX Security Tag Name(s) to list.  Lists all security tags if left blank
		.EXAMPLE
			PS C:\> Get-JpNSXSecurityTagAssignment -id securitytag-001
		.EXAMPLE
			PS C:\> Get-JpNSXSecurityTagAssignment -name security-tag-1
	#>
	[CmdletBinding()]
	param(
		[Parameter(ValueFromPipeline=$True,
            HelpMessage="NSX Security Tag Names")]
		[string[]]$Id,

		[Parameter(ValueFromPipeline=$True,
            HelpMessage="NSX Security Tag Names")]
		[string[]]$Name

	)
	
	begin {} 
	
	process { 	
		Write-Debug "Getting VMs Assigned To Security Tag"
		if ( $name ) {
			$tag = Get-JpNSXSecurityTags -name $name
			$tag_id = $tag.id
			$url = "$($Global:DefaultNSXManager.ServerURI)api/2.0/services/securitytags/tag/$($tag_id)/vm"
			[xml]$assigned_vm_list = Calling-Get -url $url
			foreach ($assigned_vm in $assigned_vm_list.basicinfolist.basicinfo) {
				$obj = New-Object -type PSObject -Property @{
					"name" = $assigned_vm.name
					"id" = $assigned_vm.objectId
				}
				write-output $obj
			}
			
		} elseif ( $id ) { 
			$url = "$($Global:DefaultNSXManager.ServerURI)api/2.0/services/securitytags/tag/$($id)/vm"
			[xml]$assigned_vm_list = Calling-Get -url $url
			foreach ($assigned_vm in $assigned_vm_list.basicinfolist.basicinfo) {
				$obj = New-Object -type PSObject -Property @{
					"name" = $assigned_vm.name
					"id" = $assigned_vm.objectId
				}
				write-output $obj
			}
		} else {
			Write-Debug "Must Specify Tag ID or Name"
		}
	}
	
}

function Get-JpNSXEdge {
	<#
		.SYNOPSIS
			Gets NSX Edge Information
		.DESCRIPTION
			Gets NSX Edge Information
		.PARAMETER  Name
			NSX Edge Name(s) to list.  Lists all Edge devices if left blank
		.EXAMPLE
			PS C:\> Get-JpNSXEdge
		.EXAMPLE
			PS C:\> Get-JpNSXEdge -name NSX-edge-1,NSX-edge-2
	#>
	[CmdletBinding()]
	param(
		[Parameter(ValueFromPipeline=$True,
            HelpMessage="NSX Edge Names")]
		[string[]]$Name
	)
	
	begin {} 
	
	process { 
		Write-Debug "Getting NSX Edge Devices"
		$url = "$($Global:DefaultNSXManager.ServerURI)api/3.0/edges"
		[xml]$xml_edge_list = Calling-Get -url $url
		foreach ($edge in $xml_edge_list.pagedEdgeList.edgePage.edgeSummary) {
			$obj = New-Object -type PSObject -Property @{
				"name" = $edge.name
				"id" = $edge.id
				"state" = $edge.state
			}
			if ( $name ) { 
				foreach ( $edge_name in $name ) {
					if ($obj.name -eq $edge_name) {
						write-output $obj
					}
				}
			} else {
				write-output $obj
			}
		}
	}
	
}

#Function to deploy the Edge    
Function Add-JpNSXEdge {
	<#
		.SYNOPSIS
			Adds a NSX Edge Device.
		.DESCRIPTION
			Adds a NSX Edge Device using the specified parameters.
		.PARAMETER  Name
			Name of the NSX Edge Device.
		.PARAMETER  Desc
			Description of the NSX Edge Device 
		.PARAMETER  Rootpw
			Root password of the NSX Edge Device.
		.PARAMETER  Dc_id
			ID of Datacenter to deploy Edge Device into.
		.PARAMETER  Respool_id
			ID of Resource Pool to deploy Edge Device into.
		.PARAMETER  Ds_id
			ID of Datastore to deploy Edge Device into.
		.PARAMETER  Int_pg_id
			ID of DVPortGroup for internal interface.
		.PARAMETER  Int_ip
			IP address for internal interface.
		.PARAMETER  Int_netmask
			Netmask for internal interface.
		.PARAMETER  Dmz_ip
			IP address for DMZ interface.
		.PARAMETER  Dmz_netmask
			Netmask for DMZ interface.
		.PARAMETER  Ext_pg_id
			ID of DVPortGroup for external interface.
		.PARAMETER  Ext_ip_pri
			Primary IP address for external interface.
		.PARAMETER  Ext_ip_sec
			Secondary IP address for external interface.
		.PARAMETER  Ext_netmask
			Netmask for external interface.
		.EXAMPLE
			PS C:\> Add-JpNSXEdge -name $name -desc $description -rootpw $rootpw -dc_id $dc_id -respool_id $respool_id -ds_id $ds_id -int_pg_id $int_pg_id -int_ip $int_ip -int_netmask $int_netmask -ext_pg_id  $ext_pg_id -ext_ip  $ext_ip -ext_netmask $ext_netmask
	#>
	[CmdletBinding()]
	param(
		[Parameter(Mandatory=$True,
            HelpMessage="NSX Edge Name")]
		[string]$Name,
		
		[Parameter(Mandatory=$True,
            HelpMessage="NSX Edge Description")]
		[string]$Desc,
		
		[Parameter(Mandatory=$True,
            HelpMessage="NSX Edge Root Password")]
		[string]$Rootpw,
		
		[Parameter(Mandatory=$True,
            HelpMessage="NSX Edge Datacenter ID")]
		[string]$Dc_id,
		
		[Parameter(Mandatory=$True,
            HelpMessage="NSX Edge Resource Pool ID")]
		[string]$Respool_id,
		
		[Parameter(Mandatory=$True,
            HelpMessage="NSX Edge Datastore ID")]
		[string]$Ds_id,
		
		[Parameter(Mandatory=$True,
            HelpMessage="NSX Edge Internal Portgroup ID")]
		[string]$Int_pg_id,
		
		[Parameter(Mandatory=$True,
            HelpMessage="NSX Edge Internal IP Address")]
		[string]$Int_ip,
		
		[Parameter(Mandatory=$True,
            HelpMessage="NSX Edge Internal Netmask")]
		[string]$Int_netmask,
		
		[Parameter(Mandatory=$True,
            HelpMessage="NSX Edge DMZ IP Address")]
		[string]$Dmz_ip,
		
		[Parameter(Mandatory=$True,
            HelpMessage="NSX Edge DMZ Netmask")]
		[string]$Dmz_netmask,
		
		[Parameter(Mandatory=$True,
            HelpMessage="NSX Edge External Portgroup ID")]
		[string]$Ext_pg_id,
		
		[Parameter(Mandatory=$True,
            HelpMessage="NSX Edge Primary External IP Address")]
		[string]$Ext_ip_pri,
		
		[Parameter(Mandatory=$True,
            HelpMessage="NSX Edge Secondary External IP Address")]
		[string]$Ext_ip_sec,
		
		[Parameter(Mandatory=$True,
            HelpMessage="NSX Edge External Netmask")]
		[string]$Ext_netmask
	
	)
	
	write-debug "Deploying edge device $name"

$Body = @"
<edge>
<datacenterMoid>${dc_id}</datacenterMoid>
<name>${name}</name>
<description>${desc}</description>
<fqdn>${name}</fqdn>
<vseLogLevel>info</vseLogLevel>
<appliances>
<applianceSize>large</applianceSize>
<appliance>
<resourcePoolId>${respool_id}</resourcePoolId>
<datastoreId>${ds_id}</datastoreId>
</appliance>
</appliances>
<vnics>
<vnic>
<index>0</index>
<name>vnic0</name>
<type>uplink</type>
<portgroupId>${int_pg_id}</portgroupId>
<addressGroups>
<addressGroup>
<primaryAddress>${int_ip}</primaryAddress>
<subnetMask>${int_netmask}</subnetMask>
</addressGroup>
<addressGroup>
<primaryAddress>${dmz_ip}</primaryAddress>
<subnetMask>${dmz_netmask}</subnetMask>
</addressGroup>
</addressGroups>
<isConnected>true</isConnected>
</vnic>
<vnic>
<index>1</index>
<name>vnic1</name>
<type>uplink</type>
<portgroupId>${ext_pg_id}</portgroupId>
<addressGroups>
<addressGroup>
<primaryAddress>${ext_ip_pri}</primaryAddress>
<secondaryAddresses>
<ipAddress>${ext_ip_sec}</ipAddress>
</secondaryAddresses>
<subnetMask>${ext_netmask}</subnetMask>
</addressGroup>
</addressGroups>
<isConnected>true</isConnected>
</vnic>
</vnics>
<cliSettings>
<userName>admin</userName>
<password>${rootpw}</password>
<remoteAccess>true</remoteAccess>
</cliSettings>
<autoConfiguration>
<enabled>true</enabled>
<rulePriority>high</rulePriority>
</autoConfiguration>
</edge>
"@

	$url = "$($Global:DefaultNSXManager.ServerURI)api/3.0/edges"
	Calling-Post -url $url -Body $Body

}

function Remove-JpNSXEdge {
	<#
		.SYNOPSIS
			Removes a NSX Edge Device
		.DESCRIPTION
			Removes a NSX Edge Device
		.PARAMETER  Name
			NSX Edge Name(s) to remove. 
		.EXAMPLE
			PS C:\> Remove-JpNSXEdge -name NSX-edge-1,NSX-edge-2
	#>
	[CmdletBinding()]
	param(
		[Parameter(Mandatory=$True,
			ValueFromPipeline=$True,
            HelpMessage="NSX Edge Names")]
		[string[]]$Name
	)
	
	begin {} 
	
	process { 
		Write-Debug "Removing NSX Edge Devices"
		foreach ( $edge_name in $name ) {
			$edge_id = (Get-JpNSXEdge -name $edge_name).id
			$url = "$($Global:DefaultNSXManager.ServerURI)api/3.0/edges/$($edge_id)"
			Calling-Delete -url $url
				
		}
	}
}

function Get-JpNSXEdgeDefaultRoute {
	<#
		.SYNOPSIS
			Gets the Default Route for a NSX Edge Device
		.DESCRIPTION
			Gets the Default Route for a NSX Edge Device
		.PARAMETER  Name
			NSX Edge Name to query. 
		.EXAMPLE
			PS C:\> Get-JpNSXEdgeDefaultRoute -name NSX-edge-1
	#>
	[CmdletBinding()]
	param(
		[Parameter(Mandatory=$True,
			ValueFromPipeline=$True,
            HelpMessage="NSX Edge Name")]
		[string]$Name
	)
	
	begin {} 
	
	process { 
		Write-Debug "Getting Default Route for device $name"
		$edge_id = (Get-JpNSXEdge -name $name).id
		$url = "$($Global:DefaultNSXManager.ServerURI)api/3.0/edges/$($edge_id)/routing/config"
		[xml]$xml_route_list = Calling-Get -url $url
		write-output $xml_route_list.staticrouting.defaultroute
	}
}

function Add-JpNSXEdgeDefaultRoute {
	<#
		.SYNOPSIS
			Adds the Default Route for a NSX Edge Device
		.DESCRIPTION
			Adds the Default Route for a NSX Edge Device
		.PARAMETER  Name
			NSX Edge Name to add route to. 
		.PARAMETER  vNic
			ID of vNic of route. 
		.PARAMETER  Address
			Address of Next Hop. 
		.EXAMPLE
			PS C:\> Add-JpNSXEdgeDefaultRoute -name NSX-edge-1 -vNic 1 -Address 192.168.10.10
	#>
	[CmdletBinding()]
	param(
		[Parameter(Mandatory=$True,
			ValueFromPipeline=$True,
            HelpMessage="NSX Edge Name")]
		[string]$Name,

		[Parameter(Mandatory=$True,
			ValueFromPipeline=$True,
            HelpMessage="vNIC")]
		[string]$vNic,

		[Parameter(Mandatory=$True,
			ValueFromPipeline=$True,
            HelpMessage="Next Hop Address")]
		[string]$Address
	)
	
	begin {} 
	
	process { 
		Write-Debug "Adding Default Route to device $name"
		$edge_id = (Get-JpNSXEdge -name $name).id
		$url = "$($Global:DefaultNSXManager.ServerURI)api/3.0/edges/$($edge_id)/routing/config/defaultroute"

$Body += @"
<defaultRoute>
<vnic>${vNic}</vnic>
<gatewayAddress>${Address}</gatewayAddress>
<mtu>1500</mtu>
</defaultRoute>
"@

		$gateway = Calling-Put -url $url -Body $Body

	}
}

function Get-JpNSXEdgeNATRule {
	<#
		.SYNOPSIS
			Gets the NAT rules for a NSX Edge Device
		.DESCRIPTION
			Gets the NAT rules for a NSX Edge Device
		.PARAMETER  Name
			NSX Edge Name to query. 
		.EXAMPLE
			PS C:\> Get-JpNSXEdgeNATRule -name NSX-edge-1
	#>
	[CmdletBinding()]
	param(
		[Parameter(Mandatory=$True,
			ValueFromPipeline=$True,
            HelpMessage="NSX Edge Name")]
		[string]$Name
	)
	
	begin {} 
	
	process { 
		Write-Debug "Getting NAT Rules for device $name"
		$Rules = @()
		$edge_id = (Get-JpNSXEdge -name $name).id
		$url = "$($Global:DefaultNSXManager.ServerURI)api/3.0/edges/$($edge_id)/nat/config"
		[xml]$xml_natrule_list = Calling-Get -url $url
		foreach ($natrule in $xml_natrule_list.nat.natrules.natrule) {
			$CurrentRule = "" | Select ruleid, ruletag, ruletype, action, vnic, original_address, translated_address, loggingenabled, enabled, description, protocol, original_port, translated_port
			$CurrentRule.ruleid = $natrule.ruleid
			$CurrentRule.ruletag = $natrule.ruletag
			$CurrentRule.ruletype = $natrule.ruletype
			$CurrentRule.action = $natrule.action
			$CurrentRule.vnic = $natrule.vnic
			$CurrentRule.original_address = $natrule.originaladdress
			$CurrentRule.translated_address = $natrule.translatedaddress
			$CurrentRule.loggingenabled = $natrule.loggingenabled
			$CurrentRule.enabled = $natrule.enabled
			$CurrentRule.description = $natrule.description
			$CurrentRule.protocol = $natrule.protocol
			$CurrentRule.original_port = $natrule.originalport
			$CurrentRule.translated_port = $natrule.translatedport
			$Rules += $CurrentRule
		}
		write-output $Rules
	}
}

function Add-JpNSXEdgeNATRule {
	<#
		.SYNOPSIS
			Adds a NAT rule to a NSX Edge Device
		.DESCRIPTION
			Adds a NAT rule to a NSX Edge Device
		.PARAMETER  Name
			Name of NSX Edge device to receive rule. 
		.PARAMETER  Description
			Description of NAT rule. 
		.PARAMETER  Type
			Type of NAT rule - snat or dnat. 
		.PARAMETER  Description
			Description of NAT rule. 
		.PARAMETER  vNIC
			vNIC of NAT rule. 
		.PARAMETER  Original_Address
			Original IP Address(es).
		.PARAMETER  Translated_Address
			Translated IP Address(es). 
		.PARAMETER  Protocol
			Network Protocol. 
		.PARAMETER  Original_Port
			Original Network Port. 
		.PARAMETER  Translated_Port
			Translated Network Port. 
		.PARAMETER  LoggingEnabled
			Logging status of rule. 		
		.PARAMETER  Enabled
			Enabled status of rule. 	
		.PARAMETER  Above_Rule_Id
			ID of rule to insert ahead of. 				
	#>
	[CmdletBinding()]
	param(
		[Parameter(Mandatory=$True,
			ValueFromPipeline=$True,
            HelpMessage="NSX Edge Name")]
		[string]$Name,
		
		[Parameter(ValueFromPipeline=$True,
            HelpMessage="Description of rule")]
		[string]$Description = "",
		
		[Parameter(Mandatory=$True,
			ValueFromPipeline=$True,
            HelpMessage="Type of NAT rule")]
		[string]$Type,
		
		[Parameter(Mandatory=$True,
			ValueFromPipeline=$True,
            HelpMessage="vNIC to apply rule to")]
		[string]$vNic,
		
		[Parameter(Mandatory=$True,
			ValueFromPipeline=$True,
            HelpMessage="Original IP address(es)")]
		[string]$Original_Address,
		
		[Parameter(Mandatory=$True,
			ValueFromPipeline=$True,
            HelpMessage="Translated IP address(es)")]
		[string]$Translated_Address,
				
		[Parameter(Mandatory=$True,
			ValueFromPipeline=$True,
            HelpMessage="Network Protocol")]
		[string]$Protocol,
		
		[Parameter(Mandatory=$True,
			ValueFromPipeline=$True,
            HelpMessage="Original Network Port")]
		[string]$Original_Port,
		
		[Parameter(Mandatory=$True,
			ValueFromPipeline=$True,
            HelpMessage="Translated Network Port")]
		[string]$Translated_Port,
				
		[Parameter(Mandatory=$True,
			ValueFromPipeline=$True,
            HelpMessage="Logging status of rule")]
		[string]$LoggingEnabled,
		
		[Parameter(Mandatory=$True,
			ValueFromPipeline=$True,
            HelpMessage="Enabled status of rule")]
		[string]$Enabled,
		
		[Parameter(ValueFromPipeline=$True,
            HelpMessage="Rule ID to place NAT rule above")]
		[string]$Above_Rule_Id
		
	)
	
	begin {} 
	
	process { 
		Write-Debug "Adding NAT Rule to device $name"
		$Body = ""
		$edge_id = (Get-JpNSXEdge -name $name).id
		$url = "$($Global:DefaultNSXManager.ServerURI)api/3.0/edges/$($edge_id)/nat/config/rules"
		if ( $above_rule_id ) {
			$url = "$($url)?aboveRuleId=$($above_rule_id)"
		} else {
$Body += @"
<natRules>

"@

		}
		
$Body += @"
<natRule>
<action>${Type}</action>
<vnic>${vNic}</vnic>
<originalAddress>${Original_Address}</originalAddress>
<translatedAddress>${Translated_Address}</translatedAddress>
<loggingEnabled>${LoggingEnabled}</loggingEnabled>
<enabled>${Enabled}</enabled>
<description>${Description}</description>
<protocol>${Protocol}</protocol>
<translatedPort>${Translated_Port}</translatedPort>
<originalPort>${Original_Port}</originalPort>
</natRule>
"@


		if ( !$above_rule_id ) {

$Body += @"

</natRules>
"@		

		}

		$natrule = Calling-Post -url $url -Body $Body
	
	}

}

function Remove-JpNSXEdgeNATRule {
	<#
		.SYNOPSIS
			Removes a NSX Edge NAT Rule
		.DESCRIPTION
			Removes a NSX Edge NAT Rule
		.PARAMETER  Name
			NSX Edge Name to configure. 
		.PARAMETER  Rule_Id
			ID of NAT rule to remove. 
		.EXAMPLE
			PS C:\> Remove-JpNSXEdgeNATRule -name NSX-edge-1 -rule_id 1234
	#>
	[CmdletBinding()]
	param(
		[Parameter(Mandatory=$True,
			ValueFromPipeline=$True,
            HelpMessage="NSX Edge Name")]
		[string]$Name,
		[Parameter(Mandatory=$True,
			ValueFromPipeline=$True,
            HelpMessage="NAT Rule ID")]
		[string]$Rule_Id
	)
	
	begin {} 
	
	process { 
		Write-Debug "Removing Rule $Rule_Id from NSX Edge Device $Name"
		$edge_id = (Get-JpNSXEdge -name $name).id
		$url = "$($Global:DefaultNSXManager.ServerURI)api/3.0/edges/$($edge_id)/nat/config/rules/$($rule_id)"
		Calling-Delete -url $url		
	}
}

function Get-JpNSXEdgeIPSet {
	<#
		.SYNOPSIS
			Gets the IP Sets for a NSX Edge Device
		.DESCRIPTION
			Gets the IP Sets for a NSX Edge Device
		.PARAMETER  Name
			NSX Edge Name to query. 
		.PARAMETER  IPSet_Name
			Name of IP Set to list. 
		.EXAMPLE
			PS C:\> Get-JpNSXEdgeIPSet -name NSX-edge-1
	#>
	[CmdletBinding()]
	param(
		[Parameter(Mandatory=$True,
			ValueFromPipeline=$True,
            HelpMessage="NSX Edge Name")]
		[string]$Name,
		[Parameter(ValueFromPipeline=$True,
            HelpMessage="IP Set Name")]
		[string]$IPSet_Name = $null
	)
	
	begin {} 
	
	process { 
		Write-Debug "Getting IP Sets for device $name"
		$IPSets = @()
		$edge_id = (Get-JpNSXEdge -name $name).id
		$url = "$($Global:DefaultNSXManager.ServerURI)api/2.0/services/ipset/scope/$($edge_id)"
		[xml]$xml_ipset_list = Calling-Get -url $url
		foreach ($ipset in $xml_ipset_list.list.ipset) {
			$CurrentSet = "" | Select objectid,type,name,value
			$CurrentSet.name = $ipset.name
			$CurrentSet.objectid = $ipset.objectid
			$CurrentSet.type = $ipset.type
			$CurrentSet.value = $ipset.value
			$IPSets += $CurrentSet
		}
		if ( $IPSet_Name ) {
			$IPSets = $IPSets | where { $_.name -eq $IPSet_Name }
		}
		write-output $IPSets
	}
}

function Add-JpNSXEdgeIPSet {
	<#
		.SYNOPSIS
			Adds an IP Set to a NSX Edge Device
		.DESCRIPTION
			Adds an IP Set to a NSX Edge Device
		.PARAMETER  Name
			NSX Edge Name to add IP Set to. 
		.PARAMETER  IPSet_Name
			Name of IP Set. 
		.PARAMETER  Description
			Description of IP Set. 
		.PARAMETER  Address
			IP addresses to include in IP set. 
		.EXAMPLE
			PS C:\> Add-JpNSXEdgeIPSet -name NSX-edge-1 -name test -description test -address 192.168.10.0/24
		.EXAMPLE
			PS C:\> Add-JpNSXEdgeIPSet -name NSX-edge-1 -name test -description test -address 192.168.10.100
	#>
	[CmdletBinding()]
	param(
		[Parameter(Mandatory=$True,
			ValueFromPipeline=$True,
            HelpMessage="NSX Edge Name")]
		[string]$Name,

		[Parameter(Mandatory=$True,
			ValueFromPipeline=$True,
            HelpMessage="IP Set Name")]
		[string]$IPSet_Name,

		[Parameter(Mandatory=$True,
			ValueFromPipeline=$True,
            HelpMessage="IP Set Description")]
		[string]$Description,

		[Parameter(Mandatory=$True,
			ValueFromPipeline=$True,
            HelpMessage="IP addresses in set")]
		[string]$Address
	)
	
	begin {} 
	
	process { 
		Write-Debug "Adding IP Set to device $name"
		$Body = ""
		$edge_id = (Get-JpNSXEdge -name $name).id
		$url = "$($Global:DefaultNSXManager.ServerURI)api/2.0/services/ipset/$($edge_id)"

$Body += @"
<ipset>
<objectId /> 
<type>
<typeName /> 
</type>
<description>${Description}</description>
<name>${IPSet_Name}</name> 
<revision>0</revision> 
<objectTypeName /> 
<value>${Address}</value> 
</ipset>
"@

		$ipset = Calling-Post -url $url -Body $Body
	}
}

function Get-JpNSXEdgeFWRule {
	<#
		.SYNOPSIS
			Gets the Firewall rules for a NSX Edge Device
		.DESCRIPTION
			Gets the Firewall rules for a NSX Edge Device
		.PARAMETER  Name
			NSX Edge Name to query. 
		.EXAMPLE
			PS C:\> Get-JpNSXEdgeFWRule -name NSX-edge-1
	#>
	[CmdletBinding()]
	param(
		[Parameter(Mandatory=$True,
			ValueFromPipeline=$True,
            HelpMessage="NSX Edge Name")]
		[string]$Name
	)
	
	begin {} 
	
	process { 
		Write-Debug "Getting FW Rules for device $name"
		$Rules = @()
		$edge_id = (Get-JpNSXEdge -name $name).id
		$url = "$($Global:DefaultNSXManager.ServerURI)api/3.0/edges/$($edge_id)/firewall/config"
		[xml]$xml_fwrule_list = Calling-Get -url $url
		foreach ($fwrule in $xml_fwrule_list.firewall.firewallrules.firewallrule) {
			$CurrentRule = "" | Select ruleid, ruletag, name, ruletype, source, destination, action, enabled, loggingenabled, description, matchtranslated
			$CurrentRule.ruleid = $fwrule.id
			$CurrentRule.ruletag = $fwrule.ruletag
			$CurrentRule.name = $fwrule.name
			$CurrentRule.ruletype = $fwrule.ruletype
			$CurrentRule.source = $fwrule.source
			$CurrentRule.destination = $fwrule.destination
			$CurrentRule.action = $fwrule.action
			$CurrentRule.enabled = $fwrule.enabled
			$CurrentRule.loggingenabled = $fwrule.loggingenabled
			$CurrentRule.description = $fwrule.description
			$CurrentRule.matchtranslated = $fwrule.matchtranslated
			$Rules += $CurrentRule
		}
		write-output $Rules
	}
}

function Add-JpNSXEdgeFWRule {
	<#
		.SYNOPSIS
			Adds a Firewall to a NSX Edge Device
		.DESCRIPTION
			Adds a Firewall to a NSX Edge Device
		.PARAMETER  Name
			Name of NSX Edge device to receive rule. 
		.PARAMETER  Rule_Name
			Name of Firewall Rule. 
		.PARAMETER  Description
			Description of Firewall rule. 
		.PARAMETER  Source
			Name of IP Set for Source Addresses. 
		.PARAMETER  Destination
			Name of IP Set for Destination Addresses. 
		.PARAMETER  Action
			Whether rule should accept or deny 			
	#>
	[CmdletBinding()]
	param(
		[Parameter(Mandatory=$True,
			ValueFromPipeline=$True,
            HelpMessage="NSX Edge Name")]
		[string]$Name,

		[Parameter(Mandatory=$True,
			ValueFromPipeline=$True,
            HelpMessage="FW Rule Name")]
		[string]$Rule_Name,
		
		[Parameter(ValueFromPipeline=$True,
            HelpMessage="Description of rule")]
		[string]$Description = "",
		
		[Parameter(Mandatory=$True,
			ValueFromPipeline=$True,
            HelpMessage="Name of IP Set to use for source addresses")]
		[string]$Source,
		
		[Parameter(Mandatory=$True,
			ValueFromPipeline=$True,
            HelpMessage="Name of IP Set to use for destination addresses")]
		[string]$Destination,

		[Parameter(ValueFromPipeline=$True,
            HelpMessage="Name of Application to apply to firewall rule")]
		[string]$App_Name = "any",
		
		[Parameter(ValueFromPipeline=$True,
            HelpMessage="Name of Application Group to apply to firewall rule")]
		[string]$AppGroup_Name = "any",
		
		[Parameter(Mandatory=$True,
			ValueFromPipeline=$True,
            HelpMessage="Action - Accept or Deny")]
		[string]$Action
		
	)
	
	begin {} 
	
	process { 
		Write-Debug "Adding FW Rule to device $name"
		$Body = ""
		$edge_id = (Get-JpNSXEdge -name $name).id
		$url = "$($Global:DefaultNSXManager.ServerURI)api/3.0/edges/$($edge_id)/firewall/config/rules"
		if ( $Source -eq "any" ) {
			$source_ipset_id = "any"
		} else {
			$source_ipset_id = (Get-JpNSXEdgeIPSet -name $name -ipset_name $Source).objectid
		}
		if ( $Destination -eq "any" ) {
			$dest_ipset_id = "any"
		} else {
			$dest_ipset_id = (Get-JpNSXEdgeIPSet -name $name -ipset_name $Destination).objectid
		}
		if ( $App_Name -eq "any" ) {
			$app_id = "any"
		} else {
			$app_id = (Get-JpNSXEdgeApplication -name $name -app_name $App_Name).objectid
		}
		if ( $AppGroup_Name -eq "any" ) {
			$appgroup_id = "any"
		} else {
			$appgroup_id = (Get-JpNSXEdgeApplicationGroup -name $name -appgroup_name $AppGroup_Name).objectid
		}

$Body += @"
<firewallRules>
<firewallRule>
<name>${Rule_Name}</name>

"@

if ( $source_ipset_id -ne "any" ) {
$Body += @"
<source>
<groupingObjectId>${source_ipset_id}</groupingObjectId>
</source>

"@
}

if ( $dest_ipset_id -ne "any" ) {
$Body += @"
<destination> 
<groupingObjectId>${dest_ipset_id}</groupingObjectId>
</destination>

"@
}

if ( $app_id -ne "any" ) {
$Body += @"
<application>
<applicationId>${app_id}</applicationId>
</application>

"@
}

if ( $appgroup_id -ne "any" ) {
$Body += @"
<application>
<applicationId>${appgroup_id}</applicationId>
</application>

"@
}

$Body += @"
<matchTranslated>false</matchTranslated>
<action>${Action}</action>
<description>${Description}</description> 
</firewallRule>
</firewallRules>

"@

		$fwrule = Calling-Post -url $url -Body $Body
	
	}

}

function Get-JpNSXEdgeApplication {
	<#
		.SYNOPSIS
			Gets the Applications for a NSX Edge Device
		.DESCRIPTION
			Gets the Applications for a NSX Edge Device
		.PARAMETER  Name
			NSX Edge Name to query. 
		.PARAMETER  App_Name
			Application Name to query. 
		.EXAMPLE
			PS C:\> Get-JpNSXEdgeApplication -name NSX-edge-1
	#>
	[CmdletBinding()]
	param(
		[Parameter(Mandatory=$True,
			ValueFromPipeline=$True,
            HelpMessage="NSX Edge Name")]
		[string]$Name,

		[Parameter(ValueFromPipeline=$True,
            HelpMessage="Application Name")]
		[string]$App_Name
	)
	
	begin {} 
	
	process { 
		Write-Debug "Getting Application List for device $name"
		$Applications = @()
		$edge_id = (Get-JpNSXEdge -name $name).id
		$url = "$($Global:DefaultNSXManager.ServerURI)api/2.0/services/application/scope/$($edge_id)"
		[xml]$xml_application_list = Calling-Get -url $url
		foreach ($application in $xml_application_list.list.application) {
			$CurrentApplication = "" | Select name, objectid, protocol, port
			$CurrentApplication.name = $application.name
			$CurrentApplication.objectid = $application.objectid
			$CurrentApplication.protocol = $application.element.ApplicationProtocol
			$CurrentApplication.port = $application.element.value
			$Applications += $CurrentApplication
		}
		if ( $App_Name ) {
			$Applications = $Applications | where { $_.name -eq $App_Name }
		}
		write-output $Applications
	}
}

function Add-JpNSXEdgeApplication {
	<#
		.SYNOPSIS
			Adds an Application to a NSX Edge Device
		.DESCRIPTION
			Adds an Application  to a NSX Edge Device
		.PARAMETER  Name
			Name of NSX Edge device to receive Application. 
		.PARAMETER  App_Name
			Name of Application. 
		.PARAMETER  Description
			Description of Application. 
		.PARAMETER  Protocol
			Protocol of Application. 
		.PARAMETER  Port
			Port(s) of Application. 			
	#>
	[CmdletBinding()]
	param(
		[Parameter(Mandatory=$True,
			ValueFromPipeline=$True,
            HelpMessage="NSX Edge Name")]
		[string]$Name,

		[Parameter(Mandatory=$True,
			ValueFromPipeline=$True,
            HelpMessage="Application Name")]
		[string]$App_Name,
		
		[Parameter(ValueFromPipeline=$True,
            HelpMessage="Description of rule")]
		[string]$Description = "",
		
		[Parameter(Mandatory=$True,
			ValueFromPipeline=$True,
            HelpMessage="Protocol")]
		[string]$Protocol,
		
		[Parameter(Mandatory=$True,
			ValueFromPipeline=$True,
            HelpMessage="Port")]
		[string]$Port
		
	)
	
	begin {} 
	
	process { 
		Write-Debug "Adding Application to device $name"
		$Body = ""
		$edge_id = (Get-JpNSXEdge -name $name).id
		$url = "$($Global:DefaultNSXManager.ServerURI)api/2.0/services/application/$($edge_id)"
		
$Body += @"
<application>
  <objectId/>
  <type>
    <typeName/>
  </type>
  <description>${Description}</description>
  <name>${App_Name}</name>
  <revision>0</revision>
  <objectTypeName/>
  <element>
    <applicationProtocol>${Protocol}</applicationProtocol>
    <value>${Port}</value>
  </element>
</application>
"@

		$application = Calling-Post -url $url -Body $Body
	
	}

}

function Get-JpNSXEdgeApplicationGroup {
	<#
		.SYNOPSIS
			Gets the Application Groups for a NSX Edge Device
		.DESCRIPTION
			Gets the Application Groups for a NSX Edge Device
		.PARAMETER  Name
			NSX Edge Name to query. 
		.PARAMETER  AppGroup_Name
			Name of Application Group to list 
		.EXAMPLE
			PS C:\> Get-JpNSXEdgeApplicationGroup -name NSX-edge-1
	#>
	[CmdletBinding()]
	param(
		[Parameter(Mandatory=$True,
			ValueFromPipeline=$True,
            HelpMessage="NSX Edge Name")]
		[string]$Name,

		[Parameter(ValueFromPipeline=$True,
            HelpMessage="Application Group")]
		[string]$AppGroup_Name
	)
	
	begin {} 
	
	process { 
		Write-Debug "Getting Application Group List for device $name"
		$Application_Groups = @()
		$edge_id = (Get-JpNSXEdge -name $name).id
		$url = "$($Global:DefaultNSXManager.ServerURI)api/2.0/services/applicationgroup/scope/$($edge_id)"
		[xml]$xml_applicationgroup_list = Calling-Get -url $url
		foreach ($applicationgroup in $xml_applicationgroup_list.list.applicationgroup) {
			$CurrentApplicationGroup = "" | Select name, objectid, member
			$CurrentApplicationGroup.name = $applicationgroup.name
			$CurrentApplicationGroup.objectid = $applicationgroup.objectid
			$CurrentApplicationGroup.member = $applicationgroup.member
			$Application_Groups += $CurrentApplicationGroup
		}
		if ( $AppGroup_Name ) {
			$Application_Groups = $Application_Groups | where { $_.name -eq $AppGroup_Name }
		}
		write-output $Application_Groups
	}
}

function Add-JpNSXEdgeApplicationGroup {
	<#
		.SYNOPSIS
			Adds an Application Group to a NSX Edge Device
		.DESCRIPTION
			Adds an Application Group to a NSX Edge Device
		.PARAMETER  Name
			Name of NSX Edge device to receive Application Group. 
		.PARAMETER  AppGroup_Name
			Name of Application Group. 
		.PARAMETER  Description
			Description of Application Group. 			
	#>
	[CmdletBinding()]
	param(
		[Parameter(Mandatory=$True,
			ValueFromPipeline=$True,
            HelpMessage="NSX Edge Name")]
		[string]$Name,

		[Parameter(Mandatory=$True,
			ValueFromPipeline=$True,
            HelpMessage="Application Name")]
		[string]$AppGroup_Name,
		
		[Parameter(ValueFromPipeline=$True,
            HelpMessage="Description of rule")]
		[string]$Description = ""
		
	)
	
	begin {} 
	
	process { 
		Write-Debug "Adding Application Group to device $name"
		$Body = ""
		$edge_id = (Get-JpNSXEdge -name $name).id
		$url = "$($Global:DefaultNSXManager.ServerURI)api/2.0/services/applicationgroup/$($edge_id)"
		
$Body += @"
<applicationGroup>
<description>${Description}</description>
<name>${AppGroup_Name}</name>
<revision>0</revision>
<inheritanceAllowed>false</inheritanceAllowed> 
</applicationGroup>
"@

		$appgroup = Calling-Post -url $url -Body $Body
	
	}

}

function Add-JpNSXEdgeApplicationGroupMember {
	<#
		.SYNOPSIS
			Adds an Application to an Application Group on a NSX Edge Device
		.DESCRIPTION
			Adds an Application to an Application Group on a NSX Edge Device
		.PARAMETER  Name
			Name of NSX Edge device to receive Application Group Member. 
		.PARAMETER  AppGroup_Name
			Name of Application Group to add member to. 
		.PARAMETER  App_Name
			Name of Application to add to Application Group. 			
	#>
	[CmdletBinding()]
	param(
		[Parameter(Mandatory=$True,
			ValueFromPipeline=$True,
            HelpMessage="NSX Edge Name")]
		[string]$Name,

		[Parameter(Mandatory=$True,
			ValueFromPipeline=$True,
            HelpMessage="Name of Application Group")]
		[string]$AppGroup_Name,
		
		[Parameter(ValueFromPipeline=$True,
            HelpMessage="Name of Application")]
		[string]$App_Name
		
	)
	
	begin {} 
	
	process { 
		Write-Debug "Adding Member to Application Group $AppGroup_Name on device $name"
		$Body = ""
		$edge_id = (Get-JpNSXEdge -name $name).id
		$appgroup_id = (Get-JpNSXEdgeApplicationGroup -name $name -appgroup_name $appgroup_name).objectid
		$app_id = (Get-JpNSXEdgeApplication -name $name -app_name $app_name).objectid
		$url = "$($Global:DefaultNSXManager.ServerURI)api/2.0/services/applicationgroup/$($appgroup_id)/members/$($app_id)"

		$appgroup = Calling-Put -url $url -Body $Body
	
	}

}


function Get-JpTestXML {
	<#
		.SYNOPSIS
			Function to test output of REST gets.
		.DESCRIPTION
			Function to test output of REST gets.
		.PARAMETER  Name
			NSX Edge Name to query. 
		.EXAMPLE
			PS C:\> Get-JpTestXML -name NSX-edge-1
	#>
	[CmdletBinding()]
	param(
		[Parameter(Mandatory=$True,
			ValueFromPipeline=$True,
            HelpMessage="NSX Edge Name")]
		[string]$Name
	)
	
	begin {} 
	
	process { 
		Write-Debug "Getting test XML device $name"
		$edge_id = (Get-JpNSXEdge -name $name).id
		$url = "$($Global:DefaultNSXManager.ServerURI)api/2.0/services/applicationgroup/scope/$($edge_id)"
		[xml]$xml_test_output = Calling-Get -url $url
		write-output $xml_test_output
	}
}

export-modulemember -Function Connect-JpNSXManager
export-modulemember -Function Disconnect-JpNSXManager
export-modulemember -Function Get-JpNSXSecurityTags
export-modulemember -Function Get-JpNSXSecurityTagAssignment
export-modulemember -Function Get-JpNSXEdge
export-modulemember -Function Add-JpNSXEdge
export-modulemember -Function Remove-JpNSXEdge
export-modulemember -Function Get-JpNSXEdgeDefaultRoute
export-modulemember -Function Add-JpNSXEdgeDefaultRoute
export-modulemember -Function Get-JpNSXEdgeNATRule
export-modulemember -Function Add-JpNSXEdgeNATRule
export-modulemember -Function Remove-JpNSXEdgeNATRule
export-modulemember -Function Get-JpNSXEdgeIPSet
export-modulemember -Function Add-JpNSXEdgeIPSet
export-modulemember -Function Get-JpNSXEdgeFWRule
export-modulemember -Function Add-JpNSXEdgeFWRule
export-modulemember -Function Get-JpNSXEdgeApplication
export-modulemember -Function Add-JpNSXEdgeApplication
export-modulemember -Function Get-JpNSXEdgeApplicationGroup
export-modulemember -Function Add-JpNSXEdgeApplicationGroup
export-modulemember -Function Add-JpNSXEdgeApplicationGroupMember

export-modulemember -Function Get-JpTestXML