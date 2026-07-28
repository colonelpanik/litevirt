package corrosion

// SQLite error classification by stable result code (NOT by matching error text). The
// apply path needs to tell a deterministic row-level constraint violation (which AE keeps
// local + counts, and WAL back-pressures) apart from an operational/infrastructure failure
// (disk full, I/O, busy/locked, corruption, interrupt) which must always roll back and
// propagate — never be presented as a row-level rejection.

import (
	"errors"

	sqlite3 "modernc.org/sqlite/lib"

	sqlitedrv "modernc.org/sqlite"
)

// sqliteClass is the coarse classification the apply path branches on.
type sqliteClass int

const (
	classOther       sqliteClass = iota // unrecognized / non-SQLite → treat as operational (fail closed)
	classConstraint                     // a deterministic row constraint violation
	classOperational                    // infrastructure failure (busy/locked/io/full/interrupt/corrupt)
)

// constraintKind names the specific constraint that failed, for a bounded metric label.
type constraintKind string

const (
	constraintUnique     constraintKind = "unique"
	constraintPrimaryKey constraintKind = "primary_key"
	constraintNotNull    constraintKind = "not_null"
	constraintCheck      constraintKind = "check"
	constraintForeignKey constraintKind = "foreign_key"
	constraintGeneric    constraintKind = "constraint"
	constraintNone       constraintKind = ""
)

// classifySQLiteError extracts the driver's extended result code and classifies it. A nil
// error is classOther/none. An error that is not a *sqlite.Error (wrapped or not) is
// classOther — which the AE policy treats as fail-closed (rollback + propagate), never a
// keep-local skip.
func classifySQLiteError(err error) (sqliteClass, constraintKind) {
	if err == nil {
		return classOther, constraintNone
	}
	var serr *sqlitedrv.Error
	if !errors.As(err, &serr) {
		return classOther, constraintNone
	}
	code := serr.Code()
	primary := code & 0xff
	switch primary {
	case sqlite3.SQLITE_CONSTRAINT:
		switch code {
		case sqlite3.SQLITE_CONSTRAINT_UNIQUE:
			return classConstraint, constraintUnique
		case sqlite3.SQLITE_CONSTRAINT_PRIMARYKEY:
			return classConstraint, constraintPrimaryKey
		case sqlite3.SQLITE_CONSTRAINT_NOTNULL:
			return classConstraint, constraintNotNull
		case sqlite3.SQLITE_CONSTRAINT_CHECK:
			return classConstraint, constraintCheck
		case sqlite3.SQLITE_CONSTRAINT_FOREIGNKEY:
			return classConstraint, constraintForeignKey
		default:
			return classConstraint, constraintGeneric
		}
	case sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED, sqlite3.SQLITE_IOERR,
		sqlite3.SQLITE_FULL, sqlite3.SQLITE_INTERRUPT, sqlite3.SQLITE_CORRUPT:
		return classOperational, constraintNone
	default:
		// Any other SQLite error (SQLITE_ERROR, SQLITE_MISMATCH, …) is classOther — an
		// unrecognized fault. Like classOperational it is never a row-level skip: the apply path
		// treats classOther as fail-closed (WAL back-pressures; AE rolls back the chunk and
		// propagates), so an unclassified error never silently drops a write.
		return classOther, constraintNone
	}
}
