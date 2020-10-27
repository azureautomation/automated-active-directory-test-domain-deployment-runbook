<#
    .SYNOPSIS
        This Azure Automation runbook creates a new Active Directory domain controller for a new forest/domain in a Microsoft Azure virtual machine
        along with dedicated cloud service, storage account, and virtual network. 

    .DESCRIPTION
        The runbook automates the provisioning of a new AD forest in Azure for testing purposes. Given an Azure subscription and an account that has
        access, the runbook creates a new Cloud Service and Virtual Machine along with a new storage account and virtual network. The names are generated
        automatically based upon the specified domain name e.g. "mydomain.local". Once the Azure resources are created and the VM is provisioned, 
        the runbook connects to the VM remotely via WinRM to the PowerShell endpoint, installs Active Directory and promotes to a new domain controller
        of a new forest/domain.

        By default, the runbook looks for an Azure Automation credential asset that defines the username and password for the account used to connect
        to the Azure subscription in which the resources will be created. The subscription name is by default provided by a Variable asset/setting. You can also
        specify these per-execution in lieu of creating the default settings.

        When the runbook completes, a new VM is created with the specified name with AD and DNS installed. You can then connect using RDP as normal. Adding additional
        members to the domain can be done by creating them as VMs in the same virtual network within the "Member-Subnet" subnet.

    .PARAMETER  AzureCredentialName
        The name of the PowerShell credential asset in the Automation account that contains username and password
        for the account used to connect to target Azure subscription. This user must be configured as co-administrator
        of the subscription. 

        By default, the runbook will use the credential with name "Default Automation Credential"
    
    .PARAMETER  AzureSubscriptionName
        The name of Azure subscription in which the resources will be created. By default, the runbook will use 
        the value defined in the Variable setting named "Default Azure Subscription"

    .PARAMETER  Location
        The Azure region to deploy resources. Must be a value in the official list of regions. See Get-AzureLocation for current list.
        
        Defaults to "Central US".

    .PARAMETER  DomainName
        The fully-qualified domain name for new domain, e.g. "mydomain.local". The first part of the value will be used to generate unique
        resource names in Azure.

    .PARAMETER  VMName
        Name of virtual machine to create as domain controller. Defaults to "DC1". Doesn't need to be unique.

    .PARAMETER  VMAdminUsername
        Username for new local and domain administrator. Recommended to use nonstandard account name, not "admin" or "administrator".

    .PARAMETER  VMAdminPassword
        Initial password for new administrator. Recorded in plain text in the job logs, so recommended to change upon first access. Use
        a strong password.

    .EXAMPLE
        To run, import into an Automation account in the desired Azure subscription. Once imported, publish the runbook. Then use the "Run" action
        and specify at least the username and password and optionally change the other default parameters. Any errors or result outputs are shown in the
        job details view. Expected execution time ~20 minutes.

    .INPUTS
        None.

    .OUTPUTS
        The VM object resulting from the created virtual machine.

    .NOTES
        For more details and implementation guidance, see the associated documentation at https://automys.com
#>

workflow New-AzureTestADDomain
{
    Param
    (
		[parameter(Mandatory=$false)]
        [String] $AzureCredentialName = "Use *Default Automation Credential* Asset",

        [parameter(Mandatory=$false)]
        [String] $AzureSubscriptionName = "Use *Default Azure Subscription* Variable Value",

        [parameter(Mandatory=$false)]
        [String] $Location = "Central US",

        [parameter(Mandatory=$false)]
        [String] $DomainName = "domain.local",
        
        [parameter(Mandatory=$false)]
        [String] $VMName = "DC1",  
        
        [parameter(Mandatory=$true)]
        [String] $VMAdminUsername, 

        [parameter(Mandatory=$true)]
        [String] $VMAdminPassword 
    )
    
    # Verbose output by default
    $VerbosePreference = "Continue"
    
    # Retrieve credential name from variable asset if not specified
    if($AzureCredentialName -eq "Use *Default Automation Credential* asset")
    {
        $azureCredential = Get-AutomationPSCredential -Name "Default Automation Credential"
        if($azureCredential -eq $null)
        {
            Write-Output "ERROR: No automation credential name was specified, and no credential asset with name 'Default Automation Credential' was found. Either specify a stored credential name or define the default using a credential asset"
            return
        }
    }
    else
    {
        $azureCredential = Get-AutomationPSCredential -Name $AzureCredentialName
        if($azureCredential -eq $null)
        {
            Write-Output "ERROR: Failed to get credential with name [$AzureCredentialName]"
            return
        }
    }
    
    # Connect to Azure using credential asset
    $addAccountResult = Add-AzureAccount -Credential $azureCredential

    # Retrieve subscription name from variable asset if not specified
    if($AzureSubscriptionName -eq "Use *Default Azure Subscription* Variable Value")
    {
        $AzureSubscriptionName = Get-AutomationVariable -Name "Default Azure Subscription"
        if($AzureSubscriptionName.length -eq 0)
        {
            Write-Output "ERROR: No subscription name was specified, and no variable asset with name 'Default Azure Subscription' was found. Either specify an Azure subscription name or define the default using a variable setting"
            return
        }
    }
    
    # Validate subscription
    InlineScript 
    {
        $subscription = Get-AzureSubscription -Name $Using:AzureSubscriptionName
        if($subscription -eq $null)
        {
            Write-Output "ERROR: No subscription found with name [$Using:AzureSubscriptionName] that is accessible to user [$($Using:azureCredential.UserName)]"
            return
        }
    }
    
	# Select the Azure subscription we will be working against
    $subscriptionResult = Select-AzureSubscription -SubscriptionName $AzureSubscriptionName
    
    # Set prefix for resources to the first part of specified domain name
    $netBiosName  =($DomainName -split "\." | select -First 1)
    $resourcePrefix = $netBiosName + (Get-Date -Format "yyMMddHHmm")
    $dnsServerNameName = $netBiosName + "DC1"

    # Create new cloud service with unique named based on specified domain name
    Write-Verbose "Creating cloud service for deployment"
    $cloudServiceName = $resourcePrefix
    $cloudServiceResult = New-AzureService -ServiceName $cloudServiceName -Location $Location -Description "Cloud Service for test Active Directory domain deployment [$DomainName]"
    
    # Check result
    if($cloudServiceResult -eq $null -or $cloudServiceResult.OperationStatus -ne "Succeeded")
    {
        throw "Failed to create cloud service for new deployment"
    }

    # Create new storage account for deployment based on cloud service name
    Write-Verbose "Creating storage account for deployment"
    $storageAccountName = $resourcePrefix.ToLower() + "st"
    $storageAccountResult = New-AzureStorageAccount -StorageAccountName $storageAccountName -Location $Location -Description "Storage for test Active Directory domain deployment [$DomainName] in cloud service [$cloudServiceName]"
    if($storageAccountResult -eq $null -or $storageAccountResult.OperationStatus -ne "Succeeded")
    {
        throw "Failed to create storage account for deployment"
    }
    Write-Verbose "Created storage account [$storageAccountName]"
    
    # Reference the new storage account to target deployment of virtual machines
    $subscriptionResult = Set-AzureSubscription -SubscriptionName $AzureSubscriptionName -CurrentStorageAccount $storageAccountName

    # Create virtual network file
    $vNetName = $resourcePrefix + "vNet"
    $netConfigFilePath = Create-AzurevNetCfgFile -NetworkName $vNetName -Location $Location -DNSServerName $dnsServerNameName
    Write-Verbose "New virtual network config file path = [$netConfigFilePath]"
    
    # Save a backup of the current network configuration for subscription in storage account
    $currentNetworkConfig = Get-AzureVNetConfig
    $filePath = "$env:temp" + "\NetworkConfigBackup.xml"
    $currentNetworkConfig.XMLConfiguration | Out-File $filePath
    $createContainerResult = New-AzureStorageContainer "deploymentbackups"
    $uploadResult = Set-AzureStorageBlobContent -Container "deploymentbackups" -File $filePath -ErrorAction Stop
    
    # Configure virtual network for subscription
    Update-AzurevNetConfig -vNetName "$($resourcePrefix)vNet" -DNSServerName $dnsServerNameName -NetCfgFile $netConfigFilePath -Verbose
    $AzureDns = New-AzureDns -IPAddress "10.0.0.4" -Name $dnsServerNameName
    
    # Provision virtual machine
    Write-Verbose "Creating new VM instance from latest OS image"
    InlineScript 
    { 
        $image = Get-AzureVMImage | Where-Object {$_.Label -like "Windows Server 2012 R2 Datacenter*"} |
                    sort PublishedDate -Descending | select -First 1 -ExpandProperty ImageName
        $VMConfig = New-AzureVMConfig -Name $Using:vmName -InstanceSize "Small" -ImageName $image 
        Add-AzureProvisioningConfig -VM $VMConfig -Windows -AdminUsername $Using:VMAdminUsername -Password $Using:VMAdminPassword |
                    Set-AzureSubnet -SubnetNames "DC-Subnet" |
                    Set-AzureStaticVNetIP -IPAddress "10.0.0.4" | Out-Null
       
        # Provision virtual machine
        $vmSettings = @{
            ServiceName = $Using:cloudServiceName
            VNetName = $Using:vNetName
            VMs = $VMConfig
            DnsSettings = $Using:AzureDns
            WaitForBoot = $false
        }
        
        # Create VM
        $newVMREsult = New-AzureVM @vmSettings
        if($newVMREsult -eq $null -or $newVMREsult.OperationStatus -ne "Succeeded")
        {
            throw "Failed to create virtual machine for deployment. Returned status was [$($newVMREsult.OperationStatus)]"
        }

        # Wait  for VM provisioning to complete (or time out)
        $timeOut = (Get-Date).AddMinutes(20)
        While ((Get-Date) -lt $timeOut)
        {
            $VMStatus = Get-AzureVM -ServiceName $Using:cloudServiceName -Name $Using:VMName -Verbose:$false | select -ExpandProperty InstanceStatus
            Write-Verbose "Waiting for VM to finish provisioning. Current status is [$VMStatus]"
            if($VMStatus -eq "ReadyRole") 
            {
                break
            } 
            Start-Sleep -Seconds 60
        }

        if($VMStatus -ne "ReadyRole")
        {
            throw "Timed out waiting for VM to provision. Last detected VM status was [$VMStatus]"
        }
    }

    # Import certificate for remote connection to VM
    InlineScript 
    { 
		Write-Verbose "Getting the WinRM certificate thumbprint for  the VM from Azure"
        $vm = Get-AzureVM -ServiceName $Using:cloudServiceName -Name $Using:VMName
        $winRMCertThumbprint = $vm.VM.DefaultWinRMCertificateThumbprint
        if($winRMCertThumbprint.Length -eq 0)
        {
            throw "Failed to retrieve certificate thumbprint for VM $Using:VMName"
        }

        Write-Verbose "Geting the certificate for VM"
        $certContent = (Get-AzureCertificate -ServiceName $Using:cloudServiceName -Thumbprint $winRMCertThumbprint -ThumbprintAlgorithm sha1).Data
        if($certContent.Length -eq 0)
        {
            throw "Failed to retrieve certificate for VM $Using:VMName"
        }
        
        # Add the VM certificate into the LocalMachine
        Write-Verbose "Adding VM certificate to root store" 
        $certByteArray = [System.Convert]::fromBase64String($certContent) 
        $CertToImport = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList (,$certByteArray) 
        $store = New-Object System.Security.Cryptography.X509Certificates.X509Store "Root", "LocalMachine" 
        $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite) 
        $store.Add($CertToImport) 
        $store.Close() 
    }

    # Get endpoint for PowerShell remoting and set credentials
    Write-Verbose "Getting remoting endpoint for VM"
    $uri = Get-AzureWinRMUri -ServiceName $cloudServiceName -Name $VMName
    $domainCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $VMAdminUsername,(ConvertTo-SecureString $VMAdminPassword -AsPlainText -force)

    # Connect to new VM and install Active Directory, then promote to domain controller and reboot
    Write-Verbose "Connecting to VM and deploying new AD forest"
    $ADResult = InlineScript 
    { 
        $commandResult = Invoke-command -ScriptBlock {
            Param(
               $DomainName,
               $VMAdminPassword
            )
            
            # Run the following commands in remote session on VM
            try {
                # Record deployment details in log
                $logPath = "C:\DeploymentResults"
                mkdir $logPath
                Start-Transcript -Path "$logPath\AD-Deploy.log" -Append

                # Disable Network Level Authentication to avoid logon problems after domain deployment
                (Get-WmiObject -class "Win32_TSGeneralSetting" -Namespace root\cimv2\terminalservices -Filter "TerminalName='RDP-tcp'").SetUserAuthenticationRequired(0)
                
                # Install AD role
                Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools
                
                # Configure forest deployment parameters
                $adRestorePassword = ConvertTo-SecureString -String $VMAdminPassword -AsPlainText -Force
                $ADParameters = @{
                    CreateDnsDelegation = $false
                    DomainName = $DomainName
                    NoRebootOnCompletion = $true
                    SafeModeAdministratorPassword = $adRestorePassword
                    Force = $true
                    Verbose = $true
                }
        
                # Install domain controller and DNS with new forest
                Install-ADDSForest @ADParameters
        
                Stop-Transcript
                
                # Schedule restart after script finishes
                Invoke-Expression "shutdown /r /t 10"
            }
            catch {
                $errorMessage = $error[0].Exception.Message
            }
            
            if($errorMessage -eq $null)
            {
                return "Success: Active Directory domain controller with new forest deployed on VM. See transcript in C:\DeploymentResults on VM for details."
            }
            else
            {
                return "Failed: Encountered error(s) while deploying Active Directory domain controller on VM. See transcript in C:\DeploymentResults on VM for details. Error message=[$errorMessage]"
            }
            
            # End invoke-command
        } -ConnectionUri $Using:uri -Credential $Using:domainCredential -ArgumentList $Using:DomainName,$Using:VMAdminPassword
        
        return $commandResult
    } # End InlineScript
    
    Write-Verbose "Active Directory deployment commands returned with result: $ADResult"
    
    # Return new VM object
    Get-AzureVM -Name $VMName -ServiceName $cloudServiceName
    
    Write-Verbose "Runbook finished like a boss."
    
    # End of runbook
    
    
    #############   Supporting Functions   #############
    
    Function Create-AzurevNetCfgFile 
    {
        Param(
              # Name for new virtual network
              [parameter(Mandatory,Position=1)]
              [ValidateNotNullOrEmpty()]
              [String] $NetworkName,

              # Region of the network
              [parameter(Mandatory,Position=2)]
              [ValidateNotNullOrEmpty()]
              [String] $Location,

              # Name of new DNS Server to add
              [parameter(Mandatory,Position=2)]
              [ValidateNotNullOrEmpty()]
              [String] $DNSServerName
              )

        #Define a here-string for our NetCfg xml structure
        $NetCfg = @"
<?xml version="1.0" encoding="utf-8"?>
<NetworkConfiguration xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns="http://schemas.microsoft.com/ServiceHosting/2011/07/NetworkConfiguration">
    <VirtualNetworkConfiguration>
        <Dns>
            <DnsServers>
                <DnsServer name="$DNSServerName" IPAddress="10.0.0.4" />
            </DnsServers>
        </Dns>
        <VirtualNetworkSites>
            <VirtualNetworkSite name="$NetworkName" Location="$($Location)">
            <AddressSpace>
                <AddressPrefix>10.0.0.0/24</AddressPrefix>
            </AddressSpace>
            <Subnets>
                <Subnet name="DC-Subnet">
                    <AddressPrefix>10.0.0.0/28</AddressPrefix>
                </Subnet>
                <Subnet name="Member-Subnet">
                    <AddressPrefix>10.0.0.128/25</AddressPrefix>
                </Subnet>
            </Subnets>
            <DnsServersRef>
                <DnsServerRef name="$DNSServerName" />
            </DnsServersRef>
            </VirtualNetworkSite>
        </VirtualNetworkSites>
    </VirtualNetworkConfiguration>
</NetworkConfiguration>
"@

        #Update the NetCfg file with parameter values
        $path = "$env:Temp\$NetworkName.xml"
        Set-Content -Value $NetCfg -Path $path

        return $path

    } #End of Function Create-AzurevNetCfgFile

    Function Update-AzurevNetConfig 
    {
        Param(
              # Name of new virtual network
              [parameter(Mandatory,Position=1)]
              [ValidateNotNullOrEmpty()]
              [String] $vNetName,

              # Name of new DNS Server to validate
              [parameter(Mandatory,Position=2)]
              [ValidateNotNullOrEmpty()]
              [String] $DNSServerName,

              # New Virtual Network configuration XML file path
              [parameter(Mandatory,Position=3)]
              [ValidateNotNullOrEmpty()]
              [String] $NetCfgFile
              )

        # Attempt to retrieve subscription virtual nework config
        $vNetConfig = Get-AzureVNetConfig

        # If we don't have an existing virtual network use the netcfg file to create a new one
        if (!$vNetConfig) 
        {
            Write-Verbose "$(Get-Date -f T) - Existing Azure vNet configuration not found"
            Write-Verbose "$(Get-Date -f T) - Creating $vNetName virtual network from $NetCfgFile"
    
            #Create a new virtual network from the config file and return
            Set-AzureVNetConfig -ConfigurationPath $NetCfgFile | Out-Null
            return
        } 
    
        # Otherwise, we found an existing virtual network configuration, so update the existing one
        Write-Verbose "$(Get-Date -f T) - Existing Azure vNet configuration found"
    
        #Set the vNetConfig update flag to false (this determines if changes are committed later)
        $UpdatevNetConfig = $False
    
        #Convert previously created NetCfgFile to XML
        Write-Verbose "$(Get-Date -f T) - Reading contents of $NetCfgFile"
        [XML]$NetCfg = Get-Content -Path $NetCfgFile -ErrorAction Stop
    
        #Convert vNetConfig (VirtualNetworkConfigContext object) to XML
        Write-Verbose "$(Get-Date -f T) - Converting existing vNetConfig object to XML"
        $vNetConfig = [XML]$vNetConfig.XMLConfiguration
            
        if($vNetConfig.length -eq 0)
        {
            throw "Failed to parse virtual network configuration"
        }
        
        # Check for existence of DNS entry
        Write-Verbose "$(Get-Date -f T) - Checking for Dns node"
    
        #Get the Dns child of the VirtualNetworkConfiguration Node
        $DnsNode = $vNetConfig.NetworkConfiguration.VirtualNetworkConfiguration.ChildNodes | Where-Object {$_.Name -eq "Dns"}
    
        # Check DNS configuration and handle each case
        if ($DnsNode -and $DnsNode.HasChildNodes -eq $False) 
        {
            # DNS node defined, but empty
            Write-Verbose "$(Get-Date -f T) - Dns node found, but no DNS servers defined"
            Write-Verbose "$(Get-Date -f T) - Adding DNS Server to network configuration"
    
            #Create a template for the DNS node
            $DnsEntry = $vNetConfig.ImportNode($NetCfg.NetworkConfiguration.VirtualNetworkConfiguration.Dns, $True)
                
            #Import the newly created template
            $vNetConfig.NetworkConfiguration.VirtualNetworkConfiguration.ReplaceChild($DnsEntry, $DnsNode) | Out-Null
            Write-Verbose "$(Get-Date -f T) - DNS Server added to in-memory network configuration"
    
        }
        elseif ($DnsNode -and $DnsNode.HasChildNodes -eq $True) 
        {
            # DNS node defined and not empty
            Write-Verbose "$(Get-Date -f T) - DNS node has child nodes"

            # Check whether DnsServers exists
            if (($DnsNode.FirstChild).Name -eq "DnsServers" -and $DnsNode.DnsServers.HasChildNodes) 
            {
                Write-Verbose "$(Get-Date -f T) - Existing DNS servers found"

                #Get a list of currently configured DNS servers
                $DnsServers = $vNetConfig.NetworkConfiguration.VirtualNetworkConfiguration.Dns.DnsServers.DnsServer

                Write-Verbose "$(Get-Date -f T) - Checking for DNS server conflicts"

                #Set $DnsAction as "Update"
                $DnsAction = "Update"

                #Loop through the DNS server entries
                $DnsServers | ForEach-Object {

                    #See if we have the DNS server or IP address already in use
                    If ($_.Name -eq $DNSServerName -and $_.IPAddress -eq "10.0.0.4") 
                    {
                        #Set a flag for a later action
                        $DnsAction = "NoFurther"
                    }  
                    ElseIf ($_.Name -eq $DNSServerName -and $_.IPAddress -ne "10.0.0.4") 
                    {
                        #Set a flag for a later action
                        $DnsAction = "PotentialConflict"
                    }
                }  

                #Perform appropriate action after looping through all DNS entries
                Switch ($DnsAction) 
                {
                    "NoFurther" {
                        Write-Verbose "$(Get-Date -f T) - $DNSServerName (10.0.0.4) already exists - no further action required"
                    }   

                    "PotentialConflict" {
                        Write-Error "There is a name or IP conflict with an existing DNS server - please investigate" -ErrorAction Stop
                    }  

                    Default {
                        # Since the first two conditions aren't met, it should be safe to update the node
                        Write-Verbose "$(Get-Date -f T) - No conflicts found"
                        Write-Verbose "$(Get-Date -f T) - Adding DNS Server - $DNSServerName (10.0.0.4) to network configuration"

                        #Create a template for an entry to the DNSservers node
                        $DnsServerEntry = $vNetConfig.ImportNode($NetCfg.NetworkConfiguration.VirtualNetworkConfiguration.Dns.DnsServers.DnsServer, $True)

                        #Add the template to out copy of the vNetConfig in memory
                        $vNetConfig.NetworkConfiguration.VirtualNetworkConfiguration.Dns.DnsServers.AppendChild($DnsServerEntry) | Out-Null
                        Write-Verbose "$(Get-Date -f T) - DNS Server - $DNSServerName (10.0.0.4) - added to in-memory network configuration"
                    }
                } # End switch   
            }   
            else 
            {
                # DnsServershas no entries. We can replace with our generated configuration.
                Write-Verbose "$(Get-Date -f T) - No existing DNS server entries found in child nodes"
                Write-Verbose "$(Get-Date -f T) - Adding DNS Server - $DNSServerName (10.0.0.4) to network configuration"
    
                #Create a template for the DNS node
                $DnsEntry = $vNetConfig.ImportNode($NetCfg.NetworkConfiguration.VirtualNetworkConfiguration.Dns, $True)
                
                #Import the newly created template
                $vNetConfig.NetworkConfiguration.VirtualNetworkConfiguration.ReplaceChild($DnsEntry, $DnsNode) | Out-Null
                Write-Verbose "$(Get-Date -f T) - DNS Server - $DNSServerName (10.0.0.4) - added to in-memory network configuration"
            }   
        }
        else 
        {
            # DNS configuration node not defined. Need to create it with our entry.
            Write-Verbose "$(Get-Date -f T) - Dns node not found"
            Write-Verbose "$(Get-Date -f T) - Adding DNS Server - $DNSServerName (10.0.0.4) to network configuration"
    
            #Create a template for the DNS node
            $DnsEntry = $vNetConfig.ImportNode($NetCfg.NetworkConfiguration.VirtualNetworkConfiguration.Dns, $True)
            
            #Import the newly created template
            $vNetConfig.NetworkConfiguration.VirtualNetworkConfiguration.AppendChild($DnsEntry) | Out-Null
            Write-Verbose "$(Get-Date -f T) - DNS Server - $DNSServerName (10.0.0.4) - added to in-memory network configuration"
        }  
    
        # Check for existence of our virtual network 
        Write-Verbose "$(Get-Date -f T) - Checking for VirtualNetworkSites node"
    
        #Get the VirtualNetworkSites child of the VirtualNetworkConfiguration Node
        $SitesNode = $vNetConfig.NetworkConfiguration.VirtualNetworkConfiguration.ChildNodes | Where-Object {$_.Name -eq "VirtualNetworkSites"}
    
        # Check current VirtualNetworkSites configuration
        if ($SitesNode -and $SitesNode.HasChildNodes -eq $false) 
        {
            # Node defined, but empty
            Write-Verbose "$(Get-Date -f T) - VirtualNetworkSites node found, but empty"
            Write-Verbose "$(Get-Date -f T) - Adding virtual network site - $vNetName"
    
            #Create a template for the VirtualNetworkSites node
            $SitesEntry = $vNetConfig.ImportNode($NetCfg.NetworkConfiguration.VirtualNetworkConfiguration.VirtualNetworkSites, $True)
                
            #Import the newly created template
            $vNetConfig.NetworkConfiguration.VirtualNetworkConfiguration.ReplaceChild($SitesEntry, $SitesNode) | Out-Null
            Write-Verbose "$(Get-Date -f T) - VirtualNetworkSite - $vNetName - added to in-memory network configuration"

            #Set the vNetConfig update flag to true so we know we have changes to commit later
            $UpdatevNetConfig = $True
        }
        elseif($SitesNode -and $SitesNode.HasChildNodes -eq $true) 
        {
            # Node defined, and has existing networks
            Write-Verbose "$(Get-Date -f T) - VirtualNetworkSites node has child nodes"

            #Get a list of currently configured virtual network sites
            $vNetSites = $vNetConfig.NetworkConfiguration.VirtualNetworkConfiguration.VirtualNetworkSites.VirtualNetworkSite
            Write-Verbose "$(Get-Date -f T) - Checking for virtual network site conflict"

            #Loop through the DNS server entries
            $vNetSites | ForEach-Object {

                #See if we have the vNetSite name already in use
                If ($_.Name -eq $vNetName) 
                {
                    Write-Error "$vNetName already exists - please investigate" -ErrorAction Stop
                }   
            }
            
            # At this point, validated no conflicts
            Write-Verbose "$(Get-Date -f T) - No conflicts found"
            Write-Verbose "$(Get-Date -f T) - Adding virtual network site - $vNetName"

            #Create a template for an entry to the DNSservers node
            $vNetSiteEntry = $vNetConfig.ImportNode($NetCfg.NetworkConfiguration.VirtualNetworkConfiguration.VirtualNetworkSites.VirtualNetworkSite, $True)

            #Add the template to out copy of the vNetConfig in memory
            $vNetConfig.NetworkConfiguration.VirtualNetworkConfiguration.VirtualNetworkSites.AppendChild($vNetSiteEntry) | Out-Null
            Write-Verbose "Virtual network site - $vNetName - added to in-memory network configuration"
            
            #Set the vNetConfig update flag to true so we know we have changes to commit later
            $UpdatevNetConfig = $True       
        }
        else 
        {
            # Node not yet defined for virtual networks
            Write-Verbose "$(Get-Date -f T) - VirtualNetworkSites node not found"
            Write-Verbose "$(Get-Date -f T) - Adding virtual network site - $vNetName"
    
            #Create a template for the VirtualNetworkSites node
            $SitesEntry = $vNetConfig.ImportNode($NetCfg.NetworkConfiguration.VirtualNetworkConfiguration.VirtualNetworkSites, $True)
            
            #Import the newly created template
            $vNetConfig.NetworkConfiguration.VirtualNetworkConfiguration.AppendChild($SitesEntry) | Out-Null
            Write-Verbose "$(Get-Date -f T) - VirtualNetworkSite - $vNetName - added to in-memory network configuration"

            #Set the vNetConfig update flag to true so we know we have changes to commit later
            $UpdatevNetConfig = $True
        }
    
        #Check whether we have any configuration to update
        if ($UpdatevNetConfig) 
        {
            #Troubleshooting messages
            Write-Verbose "$(Get-Date -f T) - Exporting updated in-memory configuration to $NetCfgFile"

            #Copy the in-memory config back to a file
            Set-Content -Value $vNetConfig.InnerXml -Path $NetCfgFile -ErrorAction Stop
            Write-Verbose "$(Get-Date -f T) - Exported updated vNet configuration to $NetCfgFile"

            #Troubleshooting messages
            Write-Verbose "$(Get-Date -f T) - Creating $vNetName virtual network from updated config file"
    
            #Create a new virtual network from the config file
            Set-AzureVNetConfig -ConfigurationPath $NetCfgFile -ErrorAction Stop | Out-Null
        }   
        else 
        {
            Write-Verbose "$(Get-Date -f T) - vNet config does not need updating"
        }
    
    } # End Function Update-AzurevNetConfig
}