variable "TAG" {
  default = "dev"
}
target "ce" {
  context    = "./source"
  dockerfile = "Dockerfile"
  args = {
    VERSION = "${TAG}"
  }
  cache-from = ["type=gha,scope=core-ce"]
  cache-to   = ["type=gha,mode=max,scope=core-ce"]
}

target "xpack-placeholder" {
  context    = ".github"
  dockerfile = "Dockerfile.xpack-placeholder"
}

target "ee" {
  context    = "./source"
  dockerfile = "Dockerfile-ee"
  args = {
    VERSION = "${TAG}"
  }
  contexts = {
    "jumpserver/core:${TAG}-ce"                      = "target:ce"
    "registry.fit2cloud.com/jumpserver/xpack:${TAG}" = "target:xpack-placeholder"
  }
  tags = ["ghcr.io/jumpserver-east/jumpserver:${TAG}"]
  labels = {
    "org.opencontainers.image.version" = "${TAG}"
    "org.jumpserver.edition"           = "ee"
    "org.jumpserver.xpack"             = "placeholder"
  }
  cache-from = ["type=gha,scope=core-ee"]
  cache-to   = ["type=gha,mode=max,scope=core-ee"]
}
