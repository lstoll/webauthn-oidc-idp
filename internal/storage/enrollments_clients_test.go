package storage_test

import (
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"lds.li/passidp/internal/storage"
)

func TestEnrollmentStore(t *testing.T) {
	store := storage.NewEnrollmentStore(storage.OpenTest(t))
	userID := uuid.New()

	enrollment, err := store.CreatePendingEnrollment(userID)
	if err != nil {
		t.Fatalf("create enrollment: %v", err)
	}

	byKey, err := store.GetPendingEnrollmentByKey(enrollment.EnrollmentKey)
	if err != nil {
		t.Fatalf("get by key: %v", err)
	}
	if byKey.ID != enrollment.ID {
		t.Fatalf("expected enrollment id %v, got %v", enrollment.ID, byKey.ID)
	}

	byID, err := store.GetPendingEnrollmentByID(enrollment.ID)
	if err != nil {
		t.Fatalf("get by id: %v", err)
	}
	if byID.EnrollmentKey != enrollment.EnrollmentKey {
		t.Fatalf("expected enrollment key %q, got %q", enrollment.EnrollmentKey, byKey.EnrollmentKey)
	}

	list, err := store.ListPendingEnrollmentsByUser(userID)
	if err != nil {
		t.Fatalf("list by user: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected 1 enrollment, got %d", len(list))
	}

	if err := store.UpdatePendingEnrollment(enrollment.ID, []byte("cred"), &webauthn.Credential{}, "key", "confirm"); err != nil {
		t.Fatalf("update enrollment: %v", err)
	}

	confirmed, err := store.ConfirmPendingEnrollment(enrollment.ID, "confirm")
	if err != nil {
		t.Fatalf("confirm enrollment: %v", err)
	}
	if confirmed.Name != "key" {
		t.Fatalf("expected confirmed name %q, got %q", "key", confirmed.Name)
	}

	_, err = store.GetPendingEnrollmentByID(enrollment.ID)
	if err == nil {
		t.Fatal("expected confirmed enrollment to be deleted")
	}
}

func TestEnrollmentStoreGC(t *testing.T) {
	sqlDB := storage.OpenTest(t)
	store := storage.NewEnrollmentStore(sqlDB)
	userID := uuid.New()

	enrollment, err := store.CreatePendingEnrollment(userID)
	if err != nil {
		t.Fatalf("create enrollment: %v", err)
	}

	_, err = sqlDB.Exec(`UPDATE pending_enrollments SET created_at = ? WHERE id = ?`, time.Now().Add(-48*time.Hour), enrollment.ID.String())
	if err != nil {
		t.Fatalf("backdate enrollment: %v", err)
	}

	deleted, err := store.GarbageCollectPendingEnrollments()
	if err != nil {
		t.Fatalf("gc: %v", err)
	}
	if deleted != 1 {
		t.Fatalf("expected 1 deleted enrollment, got %d", deleted)
	}
}
