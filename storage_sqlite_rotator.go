package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/sirupsen/logrus"
)

type rotatorStage string

const (
	rotatorStageNext     rotatorStage = "next"
	rotatorStageCurrent  rotatorStage = "current"
	rotatorStagePrevious rotatorStage = "previous"
)

type rotatable interface {
	// ID returns the globally unique ID for this item. This should always
	// return the same value
	ID() string
	// Rotate is called on each rotation, with the stage the key is being
	// rotated in to.
	Rotate(stage rotatorStage) error
}

type dbRotator[T any, PT interface {
	rotatable
	*T
}] struct {
	log logrus.FieldLogger
	db  *sql.DB

	// usage is a unique value to identify this instance of the rotator, all
	// related items are grouped under this
	usage string

	// rotateInterval indicates how long a current key should be used before it
	// is rotated out
	rotateInterval time.Duration
	// max age of any key, from it's inception time. This should be at least
	// twice the rotate period to allow for an upcoming and current
	maxAge time.Duration

	// newFn is called to instantiate a T. It should set up the item
	// appropriatly, populate the ID etc.
	newFn func() (PT, error)
}

const defaultRotateTxTimeout = 30000 // 30s, leave plenty of time for key generation

// RotateIfNeeded checks if a rotation is required, and if it is rotates keys
// using the result of keygen. rotateAt specifies at what age a generated
// upcoming key will be rotated in to current, and the rest of the keys slid
// along a slot. Expires is the overall length that a key is considered valid
// before it is no longer offered as a valid public key. This should be at least
// 3x the rotation window to have a upcoming key, a current key, and a previous
// key to validate still-issued certs.
func (d *dbRotator[T, PT]) RotateIfNeeded(ctx context.Context) error {
	l := d.log.WithFields(logrus.Fields{"fn": "dbRotate", "usage": d.usage})

	tx, err := d.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		return fmt.Errorf("starting transaction: %v", err)
	}
	// track a rollback for all exit points, unless explicitly canceled
	shouldRollback := true
	defer func() {
		if shouldRollback {
			if err := tx.Rollback(); err != nil {
				l.WithError(err).Warn("rollback failed")
			}
		}
	}()

	// Delete all expired keys from the database.
	res, err := tx.ExecContext(ctx, "delete from rotatable where expires_at < datetime('now')")
	if err != nil {
		return fmt.Errorf("deleting expired rotatables: %w", err)
	}
	ra, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("getting affected deletion rows: %w", err)
	}
	if ra > 0 {
		l.Infof("Deleted %d old items", ra)
	}

	// We should always have an upcoming key. If we do not, insert one. This is
	// likely the initialization case. This will allow the rest of the flow to
	// proceed like it's a rotation. If we have more than one key we're in an
	// inconsistent state, so purge all but the oldest.
	var upcomingItems []string
	rows, err := tx.Query("select id from rotatable where usage = $1 and stage = $2 order by created_at asc", d.usage, rotatorStageNext)
	if err != nil {
		return fmt.Errorf("selecting current key ids")
	}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return fmt.Errorf("scanning row: %w", err)
		}
		upcomingItems = append(upcomingItems, id)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("closing query: %w", err)
	}
	if len(upcomingItems) < 1 {
		// no key, add one
		newID, err := d.newItem(ctx, tx, rotatorStageNext)
		if err != nil {
			return err
		}
		upcomingItems = append(upcomingItems, newID)
	}
	if len(upcomingItems) > 1 {
		for _, del := range upcomingItems[1:] {
			// TODO - batch?
			if _, err := tx.ExecContext(ctx, "delete from rotatable where usage = $1 and id = $2", d.usage, del); err != nil {
				return fmt.Errorf("deleting %s: %w", del, err)
			}
		}
	}

	// Next, check if we have a current key that is valid (i.e marked current,
	// and before its rotation window). If we do, we can exit the rotation early.
	var currentCount int
	if err := tx.QueryRowContext(ctx, `
		select count(*) from rotatable
		where usage = $1 and stage = $2 and current_at > $3`,
		d.usage, rotatorStageCurrent, time.Now().Add(-d.rotateInterval)).Scan(&currentCount); err != nil {
		return fmt.Errorf("checking rows: %w", err)
	}
	if currentCount > 0 {
		return nil // early exit, no more to do
	}

	// If we get here, the current key needs to be rotated out. To do this, we need to
	// * move the current key to the collection of previous
	// * move the upcoming key to the current key
	// * create a new upcoming key
	// there should only be one, but process all just in case.
	currentKeys := map[string]PT{}
	rows, err = tx.Query("select id, data from rotatable where usage = $1 and stage = $2", d.usage, rotatorStageCurrent)
	if err != nil {
		return fmt.Errorf("selecting current key ids")
	}
	for rows.Next() {
		var (
			id   string
			data []byte
		)
		if err := rows.Scan(&id, &data); err != nil {
			return fmt.Errorf("scanning row: %w", err)
		}
		into := PT(new(T))
		if err := json.Unmarshal(data, into); err != nil {
			return fmt.Errorf("unmarshaling row %s: %w", id, err)
		}
		currentKeys[id] = into
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("closing query: %w", err)
	}

	for k, v := range currentKeys {
		if err := v.Rotate(rotatorStageNext); err != nil {
			return fmt.Errorf("calling rotate on %s: %w", k, err)
		}
		b, err := json.Marshal(v)
		if err != nil {
			return fmt.Errorf("marshaling %s: %w", k, err)
		}
		if _, err := tx.ExecContext(ctx,
			"update rotatable set stage=$1, data=$2, previous_at=$3 where usage=$4 and id=$5",
			rotatorStagePrevious, b, time.Now(), d.usage, k,
		); err != nil {
			return fmt.Errorf("updating key %s: %w", k, err)
		}
	}

	// Now, the next key needs to become current
	var (
		nextID   = upcomingItems[0]
		nextData []byte
	)
	if err := tx.QueryRowContext(ctx,
		"select data from rotatable where usage=$1 and id=$2",
		d.usage, nextID).Scan(&nextData); err != nil {
		return fmt.Errorf("fetching data for %s: %w", nextID, err)
	}
	into := PT(new(T))
	if err := json.Unmarshal(nextData, into); err != nil {
		return fmt.Errorf("unmarshaling row %s: %w", nextID, err)
	}
	if err := into.Rotate(rotatorStageCurrent); err != nil {
		return fmt.Errorf("calling rotate on %s: %w", nextID, err)
	}
	b, err := json.Marshal(into)
	if err != nil {
		return fmt.Errorf("marshaling %s: %w", nextID, err)
	}
	if _, err := tx.ExecContext(ctx,
		"update rotatable set stage=$1, data=$2, current_at=$3 where usage=$4 and id=$5",
		rotatorStageCurrent, b, time.Now(), d.usage, nextID,
	); err != nil {
		return fmt.Errorf("updating key %s: %w", nextID, err)
	}

	// now ensure we have a new upcoming item
	if _, err := d.newItem(ctx, tx, rotatorStageNext); err != nil {
		return err
	}

	shouldRollback = false
	return tx.Commit()
}

func (d *dbRotator[T, PT]) newItem(ctx context.Context, tx *sql.Tx, stage rotatorStage) (string, error) {
	item, err := d.newFn()
	if err != nil {
		return "", fmt.Errorf("creating new rotated item: %w", err)
	}
	if item.ID() == "" {
		return "", errors.New("item cannot return empty ID")
	}
	if err := item.Rotate(stage); err != nil {
		return "", err
	}

	ib, err := json.Marshal(item)
	if err != nil {
		return "", fmt.Errorf("marshaling item: %w", err)
	}

	d.log.Infof("Inserting new %s %s key %s", stage, d.usage, item.ID())

	_, err = tx.ExecContext(ctx,
		`insert into rotatable (id, usage, stage, data, expires_at) values ($1, $2, $3, $4, $5)`,
		item.ID(), d.usage, stage, ib, time.Now().Add(d.maxAge),
	)
	if err != nil {
		return "", fmt.Errorf("inserting current key: %v", err)
	}

	return item.ID(), nil
}

func (d *dbRotator[T, PT]) GetCurrent(ctx context.Context) (PT, error) {
	var id string
	var currentb []byte
	err := d.db.QueryRowContext(ctx, `select id, data from rotatable where usage=$1 and stage = $2 limit 1`, d.usage, rotatorStageCurrent).Scan(&id, &currentb)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("DB contains no current item %s", d.usage)
		}
		return nil, fmt.Errorf("looking up private key: %v", err)
	}

	current := PT(new(T))
	if err := json.Unmarshal(currentb, current); err != nil {
		return nil, fmt.Errorf("unmarshaling %s: %w", id, err)
	}

	return current, nil
}

type dbPubKey struct {
	KeyID    string
	PEMBytes []byte
}

func (d *dbRotator[T, PT]) GetUpcoming(ctx context.Context) ([]PT, error) {
	return d.getStage(ctx, rotatorStageNext)
}

func (d *dbRotator[T, PT]) GetPrevious(ctx context.Context) ([]PT, error) {
	return d.getStage(ctx, rotatorStagePrevious)
}

func (d *dbRotator[T, PT]) getStage(ctx context.Context, stage rotatorStage) ([]PT, error) {
	var items []PT

	rows, err := d.db.QueryContext(ctx, `select data from rotatable where usage=$1 and stage=$2 and expires_at > datetime('now')`, d.usage, stage)
	if err != nil {
		return nil, fmt.Errorf("looking up public keys: %v", err)
	}
	defer rows.Close()

	for rows.Next() {
		var (
			data []byte
		)
		if err := rows.Scan(&data); err != nil {
			return nil, fmt.Errorf("scanning data key: %v", err)
		}
		item := PT(new(T))
		if err := json.Unmarshal(data, item); err != nil {
			return nil, fmt.Errorf("unmarshaling: %w", err)
		}
		items = append(items, item)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows: %v", err)
	}

	return items, nil
}
