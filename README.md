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



**NOTE:** This image ought to be published in the personal registry you specified.
And it is required to have access to pull the image from the working environment.
Make sure you have the proper permission to the registry if the above commands don’t work.

**Install the CRDs into the cluster:**

```sh
make install
```

**Deploy the Manager to the cluster with the image specified by `IMG`:**

```sh
make deploy
```

> **NOTE**: If you encounter RBAC errors, you may need to grant yourself cluster-admin
privileges or be logged in as admin.

**Create instances of your solution**
You can apply the samples (examples) from the config/sample:

```sh
kubectl apply -k config/samples/
```

>**NOTE**: Ensure that the samples has default values to test it out.

### To Uninstall
**Delete the instances (CRs) from the cluster:**

```sh
kubectl delete -k config/samples/
```

**Delete the APIs(CRDs) from the cluster:**

```sh
make uninstall
```

**UnDeploy the controller from the cluster:**

```sh
make undeploy
```

## Project Distribution

Following are the steps to build the installer and distribute this project to users.

1. Build the installer for the image built and published in the registry:

```sh
make build-installer IMG=<some-registry>/certificate-issuer:tag
```

NOTE: The makefile target mentioned above generates an 'install.yaml'
file in the dist directory. This file contains all the resources built
with Kustomize, which are necessary to install this project without
its dependencies.

2. Using the installer

Users can just run kubectl apply -f <URL for YAML BUNDLE> to install the project, i.e.:

```sh
kubectl apply -f https://raw.githubusercontent.com/<org>/certificate-issuer/<tag or branch>/dist/install.yaml
```

## Contributing
// TODO(user): Add detailed information on how you would like others to contribute to this project

**NOTE:** Run `make help` for more information on all potential `make` targets

More information can be found via the [Kubebuilder Documentation](https://book.kubebuilder.io/introduction.html)

## License

Copyright 2024.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

Demo : [![asciicast](https://asciinema.org/a/5EZdG6sfRsPM6NCbm6QycyRRY)](https://asciinema.org/a/5EZdG6sfRsPM6NCbm6QycyRRY)
