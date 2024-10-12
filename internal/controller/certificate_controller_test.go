package controller_test

import (
	"context"
	"errors"
	"testing"
	"time"

	certsv1 "github.com/rajendragosavi/cert-issuer/api/v1"
	ctrl "github.com/rajendragosavi/cert-issuer/internal/controller"
	"github.com/rajendragosavi/cert-issuer/internal/pkg"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// Helper function to set up the test environment
func setupTest(t *testing.T) (client.Client, *ctrl.CertificateReconciler) {
	scheme := runtime.NewScheme()

	// Add corev1 and certsv1 schemes
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("unable to add corev1 to scheme: %v", err)
	}
	if err := certsv1.AddToScheme(scheme); err != nil {
		t.Fatalf("unable to add certsv1 to scheme: %v", err)
	}

	// Create a fake client with the scheme
	k8sClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	// Initialize the reconciler with the fake client
	r := &ctrl.CertificateReconciler{
		Client: k8sClient,
	}
	return k8sClient, r
}

func TestCreateSecret_Success(t *testing.T) {
	k8sClient, r := setupTest(t)

	// Create a mock Certificate object
	cert := &certsv1.Certificate{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cert",
			Namespace: "default",
		},
		Spec: certsv1.CertificateSpec{
			SecretRef: certsv1.SecretReference{
				Name: "test-secret",
			},
		},
	}

	// Create a mock TLSCertificate object
	tlsCert := &pkg.TLSCertificate{
		Certificate: []byte("fake-cert-data"),
		PrivateKey:  []byte("fake-key-data"),
		ExpiringON:  time.Now().Add(365 * 24 * time.Hour),
	}

	// Call the function being tested
	err := r.CreateSecret(tlsCert, cert)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify that the secret was created
	secret := &corev1.Secret{}
	err = k8sClient.Get(context.TODO(), types.NamespacedName{
		Namespace: "default",
		Name:      "test-secret",
	}, secret)
	if err != nil {
		t.Fatalf("unexpected error getting secret: %v", err)
	}

	// Verify secret data
	if string(secret.Data["tls.crt"]) != "fake-cert-data" {
		t.Errorf("expected 'tls.crt' to be 'fake-cert-data', got %s", secret.Data["tls.crt"])
	}
	if string(secret.Data["tls.key"]) != "fake-key-data" {
		t.Errorf("expected 'tls.key' to be 'fake-key-data', got %s", secret.Data["tls.key"])
	}
}

func TestCreateSecret_NilCertificateObject(t *testing.T) {
	_, r := setupTest(t)

	// Create a mock TLSCertificate object
	tlsCert := &pkg.TLSCertificate{
		Certificate: []byte("fake-cert-data"),
		PrivateKey:  []byte("fake-key-data"),
		ExpiringON:  time.Now().Add(365 * 24 * time.Hour),
	}

	// Pass a nil cert object
	err := r.CreateSecret(tlsCert, nil)
	if err == nil || err.Error() != "certObj cannot be nil" {
		t.Fatalf("expected 'certObj cannot be nil' error, got %v", err)
	}
}

func TestCreateSecret_NilTLSCertificateObject(t *testing.T) {
	_, r := setupTest(t)

	// Create a mock Certificate object
	cert := &certsv1.Certificate{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cert",
			Namespace: "default",
		},
		Spec: certsv1.CertificateSpec{
			SecretRef: certsv1.SecretReference{
				Name: "test-secret",
			},
		},
	}

	// Pass a nil TLSCertificate object
	err := r.CreateSecret(nil, cert)
	if err == nil || err.Error() != "tlsCert cannot be nil" {
		t.Fatalf("expected 'tlsCert cannot be nil' error, got %v", err)
	}
}

func TestCreateSecret_ErrorOnSecretCreation(t *testing.T) {
	k8sClient := &FakeClientWithCreateError{}
	r := &ctrl.CertificateReconciler{
		Client: k8sClient,
	}

	// Create a mock Certificate object
	cert := &certsv1.Certificate{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cert",
			Namespace: "default",
		},
		Spec: certsv1.CertificateSpec{
			SecretRef: certsv1.SecretReference{
				Name: "test-secret",
			},
		},
	}

	// Create a mock TLSCertificate object
	tlsCert := &pkg.TLSCertificate{
		Certificate: []byte("fake-cert-data"),
		PrivateKey:  []byte("fake-key-data"),
		ExpiringON:  time.Now().Add(365 * 24 * time.Hour),
	}

	// Call the function being tested
	err := r.CreateSecret(tlsCert, cert)

	// Expect an error due to secret creation failure
	if err == nil || err.Error() != "failed to create secret" {
		t.Fatalf("expected 'failed to create secret' error, got %v", err)
	}
}

// FakeClientWithCreateError mocks a client that returns an error on Create
type FakeClientWithCreateError struct {
	client.Client
}

func (f *FakeClientWithCreateError) Create(ctx context.Context, obj client.Object, opts ...client.CreateOption) error {
	return errors.New("failed to create secret")
}
