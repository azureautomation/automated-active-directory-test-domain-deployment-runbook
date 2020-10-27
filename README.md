Automated Active Directory Test Domain Deployment Runbook
=========================================================

            
What it Does

This runbook automates the provisioning of a new AD domain/forest in Microsoft Azure for testing purposes. Given an Azure subscription and an account that has access, the runbook creates a new cloud service and virtual machine along with a new storage account
 and virtual network. The resource names are generated automatically based upon the specified domain name e.g. 'mydomain.local'. Once the Azure resources are created and the VM is provisioned, the runbook connects to the VM remotely via WinRM to the PowerShell
 endpoint, installs Active Directory and promotes to a new domain controller.


 


Note: Videos and additional details about this runbook available here: Automated
 Active Directory Test Domain Deployment in Microsoft Azure






![Image](https://github.com/azureautomation/automated-active-directory-test-domain-deployment-runbook/raw/master/Diagram2.jpg)

When to Use

Using this runbook, you can quickly provision a test lab domain in Azure with a few clicks, avoiding the time and tedium of setting up all of the components necessary to create a new working environment. Because a new virtual network is created, you can
 then add additional servers to the domain by simply creating them into the associated member subnet. And because the resources are isolated, you can later remove the environment without affecting the other resources in your subscription.


**Warning**: Do not use this runbook if manually installing Active Directory domains if one of your favorite things in life.

How it Works

Once imported and published into an Azure Automation account in your subscription, you can click “Run”, enter a few parameter values, and come back in 20 minutes to a fully-provisioned new domain.


The runbook performs the following:


  *  Authenticates to subscription 
  *  Creates dedicated cloud service 
  *  Creates dedicated storage account 
  *  Saves a backup of the subscription virtual network configuration to the storage account

  *  Creates a dedicated virtual network 
  *  Creates a new virtual machine for the domain controller 
  *  Installs Active Directory on the VM 
  *  Restarts the VM 
  *  Gives you warm fuzzies 

By default, the runbook looks for an Azure Automation credential asset that defines the username and password for the account used to connect to the Azure subscription in which the resources will be created. The subscription name is by default provided by
 a Variable asset/setting. You can also specify these per-execution in lieu of creating the default settings.


When the runbook completes, a new VM is created with the specified name with AD and DNS installed. You can then connect using RDP as normal. Adding additional members to the domain can be done by creating them as VMs in the same virtual network within the
 'Member-Subnet' subnet.

Acknowledgements

Thanks to Ian Farr and his [example script](https://gallery.technet.microsoft.com/Build-AD-Forest-in-Windows-3118c100) from which the network creation portion in particular is drawn upon in this runbook.

Runbook Content

 

 

        
    
TechNet gallery is retiring! This script was migrated from TechNet script center to GitHub by Microsoft Azure Automation product group. All the Script Center fields like Rating, RatingCount and DownloadCount have been carried over to Github as-is for the migrated scripts only. Note : The Script Center fields will not be applicable for the new repositories created in Github & hence those fields will not show up for new Github repositories.
