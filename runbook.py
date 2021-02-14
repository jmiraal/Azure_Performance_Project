import sys
import threading

import automationassets
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.resource import ResourceManagementClient

# replace with your own resource group
resource_group = "acdnd-c4-project"
vmss = "udacity-vmss"

if resource_group == "":
    raise Exception("Please provide a resource group")

def get_automation_runas_credential(runas_connection):
    """ Returns credentials to authenticate against Azure resoruce manager """
    from OpenSSL import crypto
    from msrestazure import azure_active_directory
    import adal

    # Get the Azure Automation RunAs service principal certificate
    cert = automationassets.get_automation_certificate("AzureRunAsCertificate")
    pks12_cert = crypto.load_pkcs12(cert)
    pem_pkey = crypto.dump_privatekey(crypto.FILETYPE_PEM, pks12_cert.get_privatekey())

    # Get run as connection information for the Azure Automation service principal
    application_id = runas_connection["ApplicationId"]
    thumbprint = runas_connection["CertificateThumbprint"]
    tenant_id = runas_connection["TenantId"]

    # Authenticate with service principal certificate
    resource = "https://management.core.windows.net/"
    authority_url = ("https://login.microsoftonline.com/" + tenant_id)
    context = adal.AuthenticationContext(authority_url)
    return azure_active_directory.AdalAuthentication(
        lambda: context.acquire_token_with_client_certificate(
            resource,
            application_id,
            pem_pkey,
            thumbprint)
    )

# Authenticate to Azure using the Azure Automation RunAs service principal
runas_connection = automationassets.get_automation_connection("AzureRunAsConnection")
azure_credential = get_automation_runas_credential(runas_connection)

compute_client = ComputeManagementClient(
    azure_credential,
    str(runas_connection["SubscriptionId"])
)

vmss = compute_client.virtual_machine_scale_set_vms.list(resource_group_name=resource_group, virtual_machine_scale_set_name=vmss)
for item in vmss:
    print("name: ", item.name)
    ni_reference = item.network_profile.network_interfaces[0].id
    resource_client = ResourceManagementClient(azure_credential, str(runas_connection["SubscriptionId"]))
    nic = resource_client.resources.get_by_id(ni_reference, api_version='2017-12-01')
    ip_reference = nic.properties['ipConfigurations'][0]['properties']
    print("ip info: ", ip_reference)

    instance_view = compute_client.virtual_machine_scale_set_vms.get_instance_view(resource_group_name=resource_group, vm_scale_set_name=vmss, instance_id=item.instance_id)
    print(instance_view.statuses[1].code)