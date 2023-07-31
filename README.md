# Traefik Keycloak Plugin

This plugin integrates Keycloak authentication with openid into the Traefik HTTP reverse proxy.

## Description

This plugin for Traefik allows it to authenticate requests against Keycloak. It utilizes the Keycloak's client credentials flow to retrieve an access token, which is then set as a bearer token in the Authorization header of the incoming requests. The plugin communicates with Keycloak using the OpenID Connect protocol.

## Installation

First, enable the plugins support in your Traefik configuration file (traefik.yml or traefik.toml):

```yaml
# traefik.yaml
experimental:
  plugins:
    traefikkeycloak:
      moduleName: "github.com/gwojda/keycloak-openid"
      version: "v0.1.0"
```

## Usage

Add the plugin's specific configuration to your Traefik routers:

```yaml
# traefik.yaml
http:
  routers:
    my-router:
      rule: "Host(`mywebsite.com`)"
      service: "my-service"
      middlewares:
        - name: traefikkeycloak
          plugin:
            KeycloakURL: "https://my-keycloak-url.com"
            ClientID: "my-client-id"
            ClientSecret: "my-client-secret"
      tls: {}
```

The above configuration will authenticate all incoming requests for mywebsite.com with Keycloak.
