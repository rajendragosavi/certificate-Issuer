/*
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
*/

package controller

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	certsv1 "github.com/rajendragosavi/cert-issuer/api/v1"
	"github.com/rajendragosavi/cert-issuer/internal/pkg"
)

// CertificateReconciler reconciles a Certificate object
type CertificateReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	Logger logr.Logger
}

// +kubebuilder:rbac:groups=certs.k8c.io,resources=certificates,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=certs.k8c.io,resources=certificates/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=certs.k8c.io,resources=certificates/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the Certificate object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.18.2/pkg/reconcile
func (r *CertificateReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.Logger
	log.WithValues("certificate_name ", req.Name, " certificate_namespace", req.Namespace).V(1).Info("Reconcile started")

	// Fetch the Certificate instance
	var cert certsv1.Certificate
	if err := r.Get(ctx, req.NamespacedName, &cert); err != nil {
		if apierrors.IsNotFound(err) {
			// The resource no longer exists, so it must have been deleted
			log.V(2).Info("Certificate resource not found. It must have been deleted.")
			return ctrl.Result{}, nil
		}
		log.Error(err, "unable to fetch certificate object")
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Ensure the Certificate has a finalizer
	if !controllerutil.ContainsFinalizer(&cert, "certs.k8c.io/finalizer") {
		controllerutil.AddFinalizer(&cert, "certs.k8c.io/finalizer")
		if err := r.Update(ctx, &cert); err != nil {
			return ctrl.Result{}, err
		}
	}
	// Handle Deletion of Certificate resource
	if !cert.ObjectMeta.DeletionTimestamp.IsZero() {
		log.V(1).Info("Deleting associated Secret", "SecretName", cert.Spec.SecretRef.Name)
		err := r.Client.Delete(ctx, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      cert.Spec.SecretRef.Name,
				Namespace: cert.Namespace,
			},
		})
		if err != nil && !apierrors.IsNotFound(err) {
			log.Error(err, "Failed to delete Secret for Certificate", "SecretName", cert.Spec.SecretRef.Name)
			return ctrl.Result{}, err
		}
		// Remove finalizer after secret deletion
		controllerutil.RemoveFinalizer(&cert, "certs.k8c.io/finalizer")
		if err := r.Update(ctx, &cert); err != nil {
			return ctrl.Result{}, err
		}
		log.V(1).Info("Secret successfully deleted", "SecretName", cert.Spec.SecretRef.Name)
		return ctrl.Result{}, nil
	}

	// Check if the certificate is already issued
	if cert.Status.Issued {
		log.V(2).Info("Certificate is already issued hence skipping reconciliation")
		return ctrl.Result{}, nil
	}

	// Check if the secret already exists
	secret := &corev1.Secret{}
	err := r.Client.Get(ctx, client.ObjectKey{Name: cert.Spec.SecretRef.Name, Namespace: cert.Namespace}, secret)
	if err == nil {
		log.Info("Secret already exists, skipping creation")
		return ctrl.Result{}, nil
	} else if !apierrors.IsNotFound(err) {
		log.Error(err, "Failed to get Secret for Certificate")
		return ctrl.Result{}, err
	}

	validityDuration, err := pkg.ParseDuration(cert.Spec.Validity)
	if err != nil {
		log.Error(err, "Failed to parse certificate validity")
		return ctrl.Result{}, err
	}

	// Generate a new TLS certificate
	tlsCert, err := r.generateSelfSignedCert(cert.Spec.DNSName, validityDuration)
	if err != nil {
		log.Error(err, "Failed to generate TLS certificate")
		return ctrl.Result{}, err
	}

	// Create the Secret to store the TLS certificate
	err = r.CreateSecret(tlsCert, &cert)
	if err != nil {
		log.Error(err, "Failed to create Secret for Certificate")
		return ctrl.Result{}, err
	}
	log.V(1).Info("Successfully created Secret for TLS certificate", "SecretName", cert.Spec.SecretRef.Name)
	cert.Status.Issued = true
	cert.Status.ExpiringOn = tlsCert.ExpiringON.Format(time.RFC3339)
	if err := r.Status().Update(ctx, &cert); err != nil {
		log.Error(err, "Failed to update certificate status")
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *CertificateReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&certsv1.Certificate{}).
		Complete(r)
}

func (r *CertificateReconciler) CreateSecret(cert *pkg.TLSCertificate, certObj *certsv1.Certificate) error {
	if cert == nil {
		return errors.New("tlsCert cannot be nil")
	}
	if certObj != nil {
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      certObj.Spec.SecretRef.Name,
				Namespace: certObj.Namespace,
			},
			Data: map[string][]byte{
				"tls.crt": cert.Certificate, // Certificate in PEM format
				"tls.key": cert.PrivateKey,  // Private key is already in PEM format
			},
			Type: corev1.SecretTypeTLS,
		}

		return r.Client.Create(context.TODO(), secret)
	} else {
		return errors.New("certObj cannot be nil")
	}
}

func (r *CertificateReconciler) generateSelfSignedCert(dnsName string, validity time.Duration) (*pkg.TLSCertificate, error) {
	// Set the expiration date based on the provided validity duration
	notAfter := time.Now().Add(validity)

	// Generate ECDSA private key
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, err
	}

	// Generate a random serial number
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}

	// Create a certificate template
	template := x509.Certificate{
		DNSNames:              []string{dnsName},
		NotBefore:             time.Now(),
		NotAfter:              notAfter,
		SerialNumber:          serialNumber,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Create the certificate (self-signed)
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}

	// PEM encode the certificate and private key
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(pkg.PemBlockForKey(priv))

	return &pkg.TLSCertificate{
		Certificate: certPEM,
		PrivateKey:  keyPEM,
		ExpiringON:  notAfter,
	}, nil
}
