package corrosion

import (
	"context"
	"errors"
)

// specMutateMaxRetries bounds MutateDesiredSpec's optimistic read-modify-CAS loop
// against a concurrent spec_generation bump. Real operations are serialized by the
// active_operation_id barrier, so this only covers two out-of-band metadata writers
// (labels, health-spec repair) racing on one VM — rare, and each retry re-reads.
const specMutateMaxRetries = 6

// ErrSpecMutateContention is returned when MutateDesiredSpec exhausts its retry
// budget — a persistent generation race on one VM, which should never happen in
// practice and signals a bug or pathological contention rather than a lost update.
var ErrSpecMutateContention = errors.New("corrosion: MutateDesiredSpec exceeded retry budget under spec-generation contention")

// MutateDesiredSpec reads name's desired spec JSON, applies fn, and persists the
// result under the active_operation_id mutation barrier, bumping spec_generation
// EXACTLY ONCE. It is the sanctioned way to change a VM's desired spec OUTSIDE an
// F1 operation (labels, health-spec repair, a direct stopped-VM redefine); an
// operation sets its desired spec atomically via BeginVMOperation instead. Along
// with UpdateObservedActuals it replaces the old blind UpdateVMSpec so no writer
// can bypass the barrier or the generation discipline.
//
//   - applied=false, nil error → an operation currently holds the barrier (or the
//     VM is gone); the caller MUST defer without writing.
//   - A no-op patch (fn returns the spec byte-identical) reports applied=true with
//     the CURRENT generation and does NOT bump spec_generation.
//   - It NEVER writes cpu_actual/mem_actual (those are observed-live values written
//     only by UpdateObservedActuals).
//
// newGen is the VM's spec_generation after the call (the bumped value, or the
// unchanged value for a no-op / deferral) — thread it into a later
// UpdateObservedActuals so the observation records against the spec it applied to.
func MutateDesiredSpec(ctx context.Context, c *Client, name string, fn func(oldSpec string) (string, error)) (applied bool, newGen int64, err error) {
	for attempt := 0; attempt < specMutateMaxRetries; attempt++ {
		rows, qerr := c.Query(ctx,
			`SELECT spec, spec_generation, active_operation_id FROM vms WHERE name = ? AND deleted_at IS NULL`, name)
		if qerr != nil {
			return false, 0, qerr
		}
		if len(rows) == 0 {
			return false, 0, nil // no such VM — caller treats as not-applied
		}
		oldSpec := rows[0].String("spec")
		specGen := rows[0].Int64("spec_generation")
		if rows[0].String("active_operation_id") != "" {
			return false, specGen, nil // barrier held by an in-flight operation → defer
		}
		newSpec, ferr := fn(oldSpec)
		if ferr != nil {
			return false, specGen, ferr
		}
		if newSpec == oldSpec {
			return true, specGen, nil // no-op: MUST NOT bump the generation
		}
		// CAS: apply only if the generation is still specGen AND no operation has
		// since claimed the barrier. A miss means a concurrent writer moved the row;
		// re-read and retry (bounded).
		n, uerr := c.ExecuteRows(ctx,
			`UPDATE vms SET spec = ?, spec_generation = spec_generation + 1, updated_at = ?
			 WHERE name = ? AND spec_generation = ? AND active_operation_id = '' AND deleted_at IS NULL`,
			newSpec, c.NowTS(), name, specGen)
		if uerr != nil {
			return false, specGen, uerr
		}
		if n > 0 {
			return true, specGen + 1, nil
		}
	}
	return false, 0, ErrSpecMutateContention
}

// UpdateObservedActuals writes ONLY cpu_actual/mem_actual, under a CAS on the owner
// epoch and (optionally) the spec generation, so a stale observation can't record
// actuals against a spec that has since changed or a VM that has since transferred
// owners. It NEVER bumps spec_generation — otherwise reading actuals back would
// fail an operation's completion CAS against the desired generation.
//
// Pass expectedOwnerEpoch < 0 to skip the owner check and/or expectedSpecGen < 0 to
// skip the generation check (a direct sequential write outside an F1 operation,
// e.g. a stopped-VM redefine that just persisted its spec). Returns applied (a row
// was updated), error.
func UpdateObservedActuals(ctx context.Context, c *Client, name string, cpu, mem int, expectedOwnerEpoch, expectedSpecGen int64) (bool, error) {
	sql := `UPDATE vms SET cpu_actual = ?, mem_actual = ?, updated_at = ? WHERE name = ? AND deleted_at IS NULL`
	params := []interface{}{cpu, mem, c.NowTS(), name}
	if expectedOwnerEpoch >= 0 {
		sql += ` AND vm_owner_epoch = ?`
		params = append(params, expectedOwnerEpoch)
	}
	if expectedSpecGen >= 0 {
		sql += ` AND spec_generation = ?`
		params = append(params, expectedSpecGen)
	}
	n, err := c.ExecuteRows(ctx, sql, params...)
	return n > 0, err
}
