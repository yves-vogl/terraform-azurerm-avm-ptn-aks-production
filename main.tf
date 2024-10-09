module "naming" {
  source  = "Azure/naming/azurerm"
  version = ">= 0.4"

  suffix = distinct(concat(var.naming_suffix, ["aks"]))
}

resource "azurerm_container_registry" "this" {
  count = var.create_container_registry ? 1 : 0

  location            = var.location
  name                = module.naming.container_registry.name_unique
  resource_group_name = var.resource_group_name
  sku                 = var.acr_sku
  tags                = var.tags
}

resource "azurerm_role_assignment" "acr" {
  count = var.create_container_registry ? 1 : 0

  principal_id                     = azurerm_kubernetes_cluster.this.kubelet_identity[0].object_id
  scope                            = azurerm_container_registry.this[0].id
  role_definition_name             = "AcrPull"
  skip_service_principal_aad_check = true
}

resource "azurerm_user_assigned_identity" "aks" {
  count = length(var.managed_identities.user_assigned_resource_ids) > 0 ? 0 : 1

  location            = var.location
  name                = module.naming.user_assigned_identity.name_unique
  resource_group_name = var.resource_group_name
  tags                = var.tags
}

resource "azurerm_kubernetes_cluster" "this" {
  location                          = var.location
  name                              = module.naming.kubernetes_cluster.name_unique
  resource_group_name               = var.resource_group_name
  automatic_channel_upgrade         = "patch"
  azure_policy_enabled              = true
  dns_prefix                        = module.naming.kubernetes_cluster.name_unique
  kubernetes_version                = var.kubernetes_version
  node_resource_group               = module.naming.resource_group.name_unique
  local_account_disabled            = false
  node_os_channel_upgrade           = "NodeImage"
  oidc_issuer_enabled               = true
  private_cluster_enabled           = true
  role_based_access_control_enabled = true
  sku_tier                          = "Standard"
  tags                              = var.tags
  workload_identity_enabled         = true

  default_node_pool {

    name    = local.default_node_pool.name
    vm_size = local.default_node_pool.vm_size

    temporary_name_for_rotation = format("%s0", local.default_node_pool.name)

    enable_auto_scaling    = true
    enable_host_encryption = var.enable_host_encryption

    min_count = local.default_node_pool.min_count
    max_count = local.default_node_pool.max_count

    # https://learn.microsoft.com/en-us/azure/aks/use-system-pools?tabs=azure-cli#system-and-user-node-pools

    max_pods = local.max_pods >= 30 ? local.max_pods : 30

    orchestrator_version = local.default_node_pool.orchestrator_version
    os_sku               = local.default_node_pool.os_sku
    tags                 = merge(var.tags, var.agents_tags)
    vnet_subnet_id       = local.vnet_subnet.resource_id
    pod_subnet_id        = var.pod_subnet.resource_id
    zones                = local.default_node_pool.zones

    upgrade_settings {
      max_surge = "10%"
    }
  }

  auto_scaler_profile {
    balance_similar_node_groups = true
  }

  azure_active_directory_role_based_access_control {
    admin_group_object_ids = var.rbac_aad_admin_group_object_ids
    azure_rbac_enabled     = var.rbac_aad_azure_rbac_enabled
    managed                = true
    tenant_id              = var.rbac_aad_tenant_id
  }

  ## Resources that only support UserAssigned
  dynamic "identity" {
    for_each = local.managed_identities.user_assigned
    content {
      type         = identity.value.type
      identity_ids = identity.value.user_assigned_resource_ids
    }
  }

  key_vault_secrets_provider {
    secret_rotation_enabled = true
  }

  monitor_metrics {
    annotations_allowed = try(var.monitor_metrics.annotations_allowed, null)
    labels_allowed      = try(var.monitor_metrics.labels_allowed, null)
  }

  network_profile {
    network_plugin      = "azure"
    load_balancer_sku   = "standard"
    network_plugin_mode = var.network_plugin_mode
    network_policy      = var.network_policy
    pod_cidr            = var.pod_cidr
    service_cidr        = var.service_cidr

    # dns_service_ip must be set when service_cidr is specified. 
    # So either we take the last host address of this CIDR or the configured dns_service_ip
    dns_service_ip = (
      var.service_cidr != null
      ? (
        var.dns_service_ip != null
        ? var.dns_service_ip
        : cidrhost(var.service_cidr, -2)
      )
      : null
    )
  }

  oms_agent {
    log_analytics_workspace_id      = azurerm_log_analytics_workspace.this.id
    msi_auth_for_monitoring_enabled = true
  }

  lifecycle {
    ignore_changes = [
      kubernetes_version
    ]

    precondition {
      condition     = var.kubernetes_version == null || try(can(regex("^[0-9]+\\.[0-9]+$", var.kubernetes_version)), false)
      error_message = "Ensure that kubernetes_version does not specify a patch version"
    }
    precondition {
      condition     = var.orchestrator_version == null || try(can(regex("^[0-9]+\\.[0-9]+$", var.orchestrator_version)), false)
      error_message = "Ensure that orchestrator_version does not specify a patch version"
    }
  }
}

# The following null_resource is used to trigger the update of the AKS cluster when the kubernetes_version changes
# This is necessary because the azurerm_kubernetes_cluster resource ignores changes to the kubernetes_version attribute
# because AKS patch versions are upgraded automatically by Azure
# The kubernetes_version_keeper and aks_cluster_post_create resources implement a mechanism to force the update
# when the minor kubernetes version changes in var.kubernetes_version

resource "null_resource" "kubernetes_version_keeper" {
  triggers = {
    version = var.kubernetes_version
  }
}

resource "azapi_update_resource" "aks_cluster_post_create" {
  type = "Microsoft.ContainerService/managedClusters@2024-02-01"
  body = jsonencode({
    properties = {
      kubernetesVersion = var.kubernetes_version
    }
  })

  resource_id = azurerm_kubernetes_cluster.this.id

  lifecycle {
    ignore_changes       = all
    replace_triggered_by = [null_resource.kubernetes_version_keeper.id]
  }
}

resource "azurerm_log_analytics_workspace" "this" {
  location            = var.location
  name                = module.naming.log_analytics_workspace.name_unique
  resource_group_name = var.resource_group_name
  sku                 = "PerGB2018"
  tags                = var.tags
}

resource "azurerm_log_analytics_workspace_table" "this" {
  for_each = toset(local.log_analytics_tables)

  name         = each.value
  workspace_id = azurerm_log_analytics_workspace.this.id
  plan         = "Basic"
}

resource "azurerm_monitor_diagnostic_setting" "aks" {
  name                           = module.naming.monitor_diagnostic_setting.name_unique
  target_resource_id             = azurerm_kubernetes_cluster.this.id
  log_analytics_destination_type = "Dedicated"
  log_analytics_workspace_id     = azurerm_log_analytics_workspace.this.id

  # Kubernetes API Server
  enabled_log {
    category = "kube-apiserver"
  }
  # Kubernetes Audit
  enabled_log {
    category = "kube-audit"
  }
  # Kubernetes Audit Admin Logs
  enabled_log {
    category = "kube-audit-admin"
  }
  # Kubernetes Controller Manager
  enabled_log {
    category = "kube-controller-manager"
  }
  # Kubernetes Scheduler
  enabled_log {
    category = "kube-scheduler"
  }
  #Kubernetes Cluster Autoscaler
  enabled_log {
    category = "cluster-autoscaler"
  }
  #Kubernetes Cloud Controller Manager
  enabled_log {
    category = "cloud-controller-manager"
  }
  #guard
  enabled_log {
    category = "guard"
  }
  #csi-azuredisk-controller
  enabled_log {
    category = "csi-azuredisk-controller"
  }
  #csi-azurefile-controller
  enabled_log {
    category = "csi-azurefile-controller"
  }
  #csi-snapshot-controller
  enabled_log {
    category = "csi-snapshot-controller"
  }
  metric {
    category = "AllMetrics"
  }
}

# required AVM resources interfaces
resource "azurerm_management_lock" "this" {
  count = var.lock != null ? 1 : 0

  lock_level = var.lock.kind
  name       = coalesce(var.lock.name, "lock-${var.lock.kind}")
  scope      = azurerm_kubernetes_cluster.this.id
  notes      = var.lock.kind == "CanNotDelete" ? "Cannot delete the resource or its child resources." : "Cannot delete or modify the resource or its child resources."
}


resource "azurerm_kubernetes_cluster_node_pool" "this" {
  for_each = tomap({
    for pool in local.node_pools : pool.name => pool if pool != "default"
  })

  kubernetes_cluster_id = azurerm_kubernetes_cluster.this.id
  name                  = each.value.name
  vm_size               = each.value.vm_size
  enable_auto_scaling   = true
  max_count             = each.value.max_count
  min_count             = each.value.min_count
  orchestrator_version  = each.value.orchestrator_version
  os_sku                = each.value.os_sku
  tags                  = var.tags
  vnet_subnet_id        = local.vnet_subnet.resource_id
  pod_subnet_id         = var.pod_subnet.resource_id
  zones                 = each.value.zone == "" ? null : [each.value.zone]

  depends_on = [azapi_update_resource.aks_cluster_post_create]

  lifecycle {
    precondition {
      condition     = can(regex("^[a-z][a-z0-9]{0,11}$", each.value.name))
      error_message = "The name must begin with a lowercase letter, contain only lowercase letters and numbers, and be between 1 and 12 characters in length."
    }
  }
}


# These resources allow the use of consistent local data files, and semver versioning
data "local_file" "compute_provider" {
  filename = format("%s/data/microsoft.compute_resourceTypes.json", path.module)
}

data "local_file" "locations" {
  filename = format("%s/data/locations.json", path.module)
}

moved {
  from = module.vnet
  to   = module.avm_res_network_virtualnetwork
}

module "avm_res_network_virtualnetwork" {
  source  = "Azure/avm-res-network-virtualnetwork/azurerm"
  version = "0.2.3"

  count = var.node_subnet == null ? 1 : 0

  address_space       = var.node_cidr != null ? [var.node_cidr] : ["10.31.0.0/16"]
  location            = var.location
  name                = module.naming.virtual_network.name_unique
  resource_group_name = var.resource_group_name
  subnets = {
    "subnet" = {
      name             = "nodecidr"
      address_prefixes = var.node_cidr != null ? [var.node_cidr] : ["10.31.0.0/16"]
    }
  }
}
