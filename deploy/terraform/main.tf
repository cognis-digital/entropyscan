terraform {
  required_providers {
    docker = { source = "kreuzwerker/docker", version = "~> 3.0" }
  }
}
# Minimal container deploy. Swap the provider block for aws_ecs_service,
# azurerm_container_app, or google_cloud_run_v2_service as needed.
provider "docker" {}
resource "docker_image" "entropyscan" { name = "ghcr.io/cognis-digital/entropyscan:latest" }
resource "docker_container" "entropyscan" {
  name  = "entropyscan"
  image = docker_image.entropyscan.image_id
  ports { internal = 8000 external = 8000 }
}
