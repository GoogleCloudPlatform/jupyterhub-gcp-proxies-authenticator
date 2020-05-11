# JupyterHub authenticator for Google Cloud proxies.

User authenticator that enable Google Cloud user to login to JupyterHub using an identity transfered by one of the following:

- [Cloud IAP](https://cloud.google.com/iap)
- [Inverting Proxy](https://github.com/google/inverting-proxy)

### Install

```sh
pip install git+https://GoogleCloudPlatform/jupyterhub-gcp-proxies-authenticator
```

### Usage
<!-- For a working example, refer to this [repository](https://GoogleCloudPlatform/ai-notebook-extended) -->

#### Inverting Proxy

```sh
# Imports authenticator.
from gcpproxiesauthenticator.gcpproxiesauthenticator import GCPProxiesAuthenticator

# Sets JupyterHub authenticator.
c.JupyterHub.authenticator_class = GCPProxiesAuthenticator

# Specifies header that contains user identity.
c.GCPProxiesAuthenticator.check_header = "X-Inverting-Proxy-User-Id"

# Shows this JupyterHub page template after login.
c.GCPProxiesAuthenticator.template_to_render = "welcome.html"
```

#### Cloud IAP

```sh
# Imports authenticator.
from gcpproxiesauthenticator.gcpproxiesauthenticator import GCPProxiesAuthenticator

# Sets JupyterHub authenticator.
c.JupyterHub.authenticator_class = GCPProxiesAuthenticator

# Specifies header that contains user identity.
c.GCPProxiesAuthenticator.check_header = "X-Goog-IAP-JWT-Assertion"

# Contains alphanumerical and hyphens.
c.GCPProxiesAuthenticator.project_id = project_id

# Contains numbers only.
c.GCPProxiesAuthenticator.project_number = project_number

# Backend service of the application protected by Cloud IAP
c.GCPProxiesAuthenticator.backend_service_name = backend_service_name

# Shows this JupyterHub page template after login.
c.GCPProxiesAuthenticator.template_to_render = "welcome.html"
```