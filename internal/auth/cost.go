package auth

import "golang.org/x/crypto/bcrypt"

// BcryptCost is the work factor used for password and recovery-code
// hashing across the auth + grpcapi packages. It defaults to
// bcrypt.DefaultCost (10) for production. Test binaries flip this to
// bcrypt.MinCost in TestMain so the suite doesn't spend most of its
// runtime burning CPU in the KDF — bcrypt is intentionally slow, and
// 800+ tests × ~80 ms/hash adds up fast (especially under -race).
//
// Callers must reference this variable directly; do not capture it.
var BcryptCost = bcrypt.DefaultCost
