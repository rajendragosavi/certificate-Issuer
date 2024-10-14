# Certificate Manager

This is a certificate manager that provides self-service certificate management for applications running on a Kubernetes cluster.

## Description

The Certificate Manager is a service built as a Kubernetes operator, designed to offload the burden of generating and managing TLS certificates from developers. With the Certificate Manager, developers no longer need to manually handle TLS certificates for their applications.

Instead, the Certificate Manager offers a self-service experience by automating the creation, renewal, and management of TLS certificates for applications and services within the cluster.

### How It Works

Developers create a `Certificate` custom resource (CR) with the required details, such as:

- The DNS Fully Qualified Domain Name (FQDN) for which the certificate is needed.
- The Kubernetes Secret where the TLS certificate should be stored.
- The validity period of the certificate.

An example of a `Certificate` object:

```yaml
apiVersion: certs.k8c.io/v1
kind: Certificate
metadata:
  name: certificate-sample
  namespace: default

spec:
  dnsName: example.k8c.io  # FQDN 
  secretRef:
    name: my-certificate-secret  # Secret where TLS certificate will be stored
  validity: 360d  # Validity of the certificate
```

The Certificate Manager continuously watches for Certificate resources created by users. Upon detecting a new Certificate object, it generates a self-signed TLS certificate and stores it as a Kubernetes Secret, using the name provided in the Certificate resource.

This service simplifies certificate management, enabling developers to focus on their applications while ensuring secure communication through automated TLS management.


## Getting Started

### Prerequisites
- go version v1.22.0+
- docker version 17.03+.
- kubectl version v1.11.3+.
- Access to a Kubernetes v1.11.3+ cluster.
- Kubernetes Cluster either Kind or Minikube




### To Deploy on the cluster
**Build your image to the location specified by `IMG`:**

```sh
make docker-build
```

**Push your image to the location specified by `IMG`:**

```sh
make docker-push
```

**Install the CRDs into the cluster:**

```sh
make install
```

**Deploy the Manager to the cluster with the image specified by `IMG`:**

```sh
make deploy
```

**Delete the APIs(CRDs) from the cluster:**

```sh
make uninstall
```

**remove certfificate manager from the cluster:**

```sh
make undeploy
```


Demo : [![asciicast](https://asciinema.org/a/5EZdG6sfRsPM6NCbm6QycyRRY)](https://asciinema.org/a/5EZdG6sfRsPM6NCbm6QycyRRY)
