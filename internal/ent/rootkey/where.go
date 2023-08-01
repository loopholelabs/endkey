// Code generated by ent, DO NOT EDIT.

package rootkey

import (
	"time"

	"entgo.io/ent/dialect/sql"
	"github.com/loopholelabs/endkey/internal/ent/predicate"
)

// ID filters vertices based on their ID field.
func ID(id int) predicate.RootKey {
	return predicate.RootKey(sql.FieldEQ(FieldID, id))
}

// IDEQ applies the EQ predicate on the ID field.
func IDEQ(id int) predicate.RootKey {
	return predicate.RootKey(sql.FieldEQ(FieldID, id))
}

// IDNEQ applies the NEQ predicate on the ID field.
func IDNEQ(id int) predicate.RootKey {
	return predicate.RootKey(sql.FieldNEQ(FieldID, id))
}

// IDIn applies the In predicate on the ID field.
func IDIn(ids ...int) predicate.RootKey {
	return predicate.RootKey(sql.FieldIn(FieldID, ids...))
}

// IDNotIn applies the NotIn predicate on the ID field.
func IDNotIn(ids ...int) predicate.RootKey {
	return predicate.RootKey(sql.FieldNotIn(FieldID, ids...))
}

// IDGT applies the GT predicate on the ID field.
func IDGT(id int) predicate.RootKey {
	return predicate.RootKey(sql.FieldGT(FieldID, id))
}

// IDGTE applies the GTE predicate on the ID field.
func IDGTE(id int) predicate.RootKey {
	return predicate.RootKey(sql.FieldGTE(FieldID, id))
}

// IDLT applies the LT predicate on the ID field.
func IDLT(id int) predicate.RootKey {
	return predicate.RootKey(sql.FieldLT(FieldID, id))
}

// IDLTE applies the LTE predicate on the ID field.
func IDLTE(id int) predicate.RootKey {
	return predicate.RootKey(sql.FieldLTE(FieldID, id))
}

// CreatedAt applies equality check predicate on the "created_at" field. It's identical to CreatedAtEQ.
func CreatedAt(v time.Time) predicate.RootKey {
	return predicate.RootKey(sql.FieldEQ(FieldCreatedAt, v))
}

// Identifier applies equality check predicate on the "identifier" field. It's identical to IdentifierEQ.
func Identifier(v string) predicate.RootKey {
	return predicate.RootKey(sql.FieldEQ(FieldIdentifier, v))
}

// Salt applies equality check predicate on the "salt" field. It's identical to SaltEQ.
func Salt(v []byte) predicate.RootKey {
	return predicate.RootKey(sql.FieldEQ(FieldSalt, v))
}

// Hash applies equality check predicate on the "hash" field. It's identical to HashEQ.
func Hash(v []byte) predicate.RootKey {
	return predicate.RootKey(sql.FieldEQ(FieldHash, v))
}

// Bootstrap applies equality check predicate on the "bootstrap" field. It's identical to BootstrapEQ.
func Bootstrap(v string) predicate.RootKey {
	return predicate.RootKey(sql.FieldEQ(FieldBootstrap, v))
}

// CreatedAtEQ applies the EQ predicate on the "created_at" field.
func CreatedAtEQ(v time.Time) predicate.RootKey {
	return predicate.RootKey(sql.FieldEQ(FieldCreatedAt, v))
}

// CreatedAtNEQ applies the NEQ predicate on the "created_at" field.
func CreatedAtNEQ(v time.Time) predicate.RootKey {
	return predicate.RootKey(sql.FieldNEQ(FieldCreatedAt, v))
}

// CreatedAtIn applies the In predicate on the "created_at" field.
func CreatedAtIn(vs ...time.Time) predicate.RootKey {
	return predicate.RootKey(sql.FieldIn(FieldCreatedAt, vs...))
}

// CreatedAtNotIn applies the NotIn predicate on the "created_at" field.
func CreatedAtNotIn(vs ...time.Time) predicate.RootKey {
	return predicate.RootKey(sql.FieldNotIn(FieldCreatedAt, vs...))
}

// CreatedAtGT applies the GT predicate on the "created_at" field.
func CreatedAtGT(v time.Time) predicate.RootKey {
	return predicate.RootKey(sql.FieldGT(FieldCreatedAt, v))
}

// CreatedAtGTE applies the GTE predicate on the "created_at" field.
func CreatedAtGTE(v time.Time) predicate.RootKey {
	return predicate.RootKey(sql.FieldGTE(FieldCreatedAt, v))
}

// CreatedAtLT applies the LT predicate on the "created_at" field.
func CreatedAtLT(v time.Time) predicate.RootKey {
	return predicate.RootKey(sql.FieldLT(FieldCreatedAt, v))
}

// CreatedAtLTE applies the LTE predicate on the "created_at" field.
func CreatedAtLTE(v time.Time) predicate.RootKey {
	return predicate.RootKey(sql.FieldLTE(FieldCreatedAt, v))
}

// IdentifierEQ applies the EQ predicate on the "identifier" field.
func IdentifierEQ(v string) predicate.RootKey {
	return predicate.RootKey(sql.FieldEQ(FieldIdentifier, v))
}

// IdentifierNEQ applies the NEQ predicate on the "identifier" field.
func IdentifierNEQ(v string) predicate.RootKey {
	return predicate.RootKey(sql.FieldNEQ(FieldIdentifier, v))
}

// IdentifierIn applies the In predicate on the "identifier" field.
func IdentifierIn(vs ...string) predicate.RootKey {
	return predicate.RootKey(sql.FieldIn(FieldIdentifier, vs...))
}

// IdentifierNotIn applies the NotIn predicate on the "identifier" field.
func IdentifierNotIn(vs ...string) predicate.RootKey {
	return predicate.RootKey(sql.FieldNotIn(FieldIdentifier, vs...))
}

// IdentifierGT applies the GT predicate on the "identifier" field.
func IdentifierGT(v string) predicate.RootKey {
	return predicate.RootKey(sql.FieldGT(FieldIdentifier, v))
}

// IdentifierGTE applies the GTE predicate on the "identifier" field.
func IdentifierGTE(v string) predicate.RootKey {
	return predicate.RootKey(sql.FieldGTE(FieldIdentifier, v))
}

// IdentifierLT applies the LT predicate on the "identifier" field.
func IdentifierLT(v string) predicate.RootKey {
	return predicate.RootKey(sql.FieldLT(FieldIdentifier, v))
}

// IdentifierLTE applies the LTE predicate on the "identifier" field.
func IdentifierLTE(v string) predicate.RootKey {
	return predicate.RootKey(sql.FieldLTE(FieldIdentifier, v))
}

// IdentifierContains applies the Contains predicate on the "identifier" field.
func IdentifierContains(v string) predicate.RootKey {
	return predicate.RootKey(sql.FieldContains(FieldIdentifier, v))
}

// IdentifierHasPrefix applies the HasPrefix predicate on the "identifier" field.
func IdentifierHasPrefix(v string) predicate.RootKey {
	return predicate.RootKey(sql.FieldHasPrefix(FieldIdentifier, v))
}

// IdentifierHasSuffix applies the HasSuffix predicate on the "identifier" field.
func IdentifierHasSuffix(v string) predicate.RootKey {
	return predicate.RootKey(sql.FieldHasSuffix(FieldIdentifier, v))
}

// IdentifierEqualFold applies the EqualFold predicate on the "identifier" field.
func IdentifierEqualFold(v string) predicate.RootKey {
	return predicate.RootKey(sql.FieldEqualFold(FieldIdentifier, v))
}

// IdentifierContainsFold applies the ContainsFold predicate on the "identifier" field.
func IdentifierContainsFold(v string) predicate.RootKey {
	return predicate.RootKey(sql.FieldContainsFold(FieldIdentifier, v))
}

// SaltEQ applies the EQ predicate on the "salt" field.
func SaltEQ(v []byte) predicate.RootKey {
	return predicate.RootKey(sql.FieldEQ(FieldSalt, v))
}

// SaltNEQ applies the NEQ predicate on the "salt" field.
func SaltNEQ(v []byte) predicate.RootKey {
	return predicate.RootKey(sql.FieldNEQ(FieldSalt, v))
}

// SaltIn applies the In predicate on the "salt" field.
func SaltIn(vs ...[]byte) predicate.RootKey {
	return predicate.RootKey(sql.FieldIn(FieldSalt, vs...))
}

// SaltNotIn applies the NotIn predicate on the "salt" field.
func SaltNotIn(vs ...[]byte) predicate.RootKey {
	return predicate.RootKey(sql.FieldNotIn(FieldSalt, vs...))
}

// SaltGT applies the GT predicate on the "salt" field.
func SaltGT(v []byte) predicate.RootKey {
	return predicate.RootKey(sql.FieldGT(FieldSalt, v))
}

// SaltGTE applies the GTE predicate on the "salt" field.
func SaltGTE(v []byte) predicate.RootKey {
	return predicate.RootKey(sql.FieldGTE(FieldSalt, v))
}

// SaltLT applies the LT predicate on the "salt" field.
func SaltLT(v []byte) predicate.RootKey {
	return predicate.RootKey(sql.FieldLT(FieldSalt, v))
}

// SaltLTE applies the LTE predicate on the "salt" field.
func SaltLTE(v []byte) predicate.RootKey {
	return predicate.RootKey(sql.FieldLTE(FieldSalt, v))
}

// HashEQ applies the EQ predicate on the "hash" field.
func HashEQ(v []byte) predicate.RootKey {
	return predicate.RootKey(sql.FieldEQ(FieldHash, v))
}

// HashNEQ applies the NEQ predicate on the "hash" field.
func HashNEQ(v []byte) predicate.RootKey {
	return predicate.RootKey(sql.FieldNEQ(FieldHash, v))
}

// HashIn applies the In predicate on the "hash" field.
func HashIn(vs ...[]byte) predicate.RootKey {
	return predicate.RootKey(sql.FieldIn(FieldHash, vs...))
}

// HashNotIn applies the NotIn predicate on the "hash" field.
func HashNotIn(vs ...[]byte) predicate.RootKey {
	return predicate.RootKey(sql.FieldNotIn(FieldHash, vs...))
}

// HashGT applies the GT predicate on the "hash" field.
func HashGT(v []byte) predicate.RootKey {
	return predicate.RootKey(sql.FieldGT(FieldHash, v))
}

// HashGTE applies the GTE predicate on the "hash" field.
func HashGTE(v []byte) predicate.RootKey {
	return predicate.RootKey(sql.FieldGTE(FieldHash, v))
}

// HashLT applies the LT predicate on the "hash" field.
func HashLT(v []byte) predicate.RootKey {
	return predicate.RootKey(sql.FieldLT(FieldHash, v))
}

// HashLTE applies the LTE predicate on the "hash" field.
func HashLTE(v []byte) predicate.RootKey {
	return predicate.RootKey(sql.FieldLTE(FieldHash, v))
}

// BootstrapEQ applies the EQ predicate on the "bootstrap" field.
func BootstrapEQ(v string) predicate.RootKey {
	return predicate.RootKey(sql.FieldEQ(FieldBootstrap, v))
}

// BootstrapNEQ applies the NEQ predicate on the "bootstrap" field.
func BootstrapNEQ(v string) predicate.RootKey {
	return predicate.RootKey(sql.FieldNEQ(FieldBootstrap, v))
}

// BootstrapIn applies the In predicate on the "bootstrap" field.
func BootstrapIn(vs ...string) predicate.RootKey {
	return predicate.RootKey(sql.FieldIn(FieldBootstrap, vs...))
}

// BootstrapNotIn applies the NotIn predicate on the "bootstrap" field.
func BootstrapNotIn(vs ...string) predicate.RootKey {
	return predicate.RootKey(sql.FieldNotIn(FieldBootstrap, vs...))
}

// BootstrapGT applies the GT predicate on the "bootstrap" field.
func BootstrapGT(v string) predicate.RootKey {
	return predicate.RootKey(sql.FieldGT(FieldBootstrap, v))
}

// BootstrapGTE applies the GTE predicate on the "bootstrap" field.
func BootstrapGTE(v string) predicate.RootKey {
	return predicate.RootKey(sql.FieldGTE(FieldBootstrap, v))
}

// BootstrapLT applies the LT predicate on the "bootstrap" field.
func BootstrapLT(v string) predicate.RootKey {
	return predicate.RootKey(sql.FieldLT(FieldBootstrap, v))
}

// BootstrapLTE applies the LTE predicate on the "bootstrap" field.
func BootstrapLTE(v string) predicate.RootKey {
	return predicate.RootKey(sql.FieldLTE(FieldBootstrap, v))
}

// BootstrapContains applies the Contains predicate on the "bootstrap" field.
func BootstrapContains(v string) predicate.RootKey {
	return predicate.RootKey(sql.FieldContains(FieldBootstrap, v))
}

// BootstrapHasPrefix applies the HasPrefix predicate on the "bootstrap" field.
func BootstrapHasPrefix(v string) predicate.RootKey {
	return predicate.RootKey(sql.FieldHasPrefix(FieldBootstrap, v))
}

// BootstrapHasSuffix applies the HasSuffix predicate on the "bootstrap" field.
func BootstrapHasSuffix(v string) predicate.RootKey {
	return predicate.RootKey(sql.FieldHasSuffix(FieldBootstrap, v))
}

// BootstrapIsNil applies the IsNil predicate on the "bootstrap" field.
func BootstrapIsNil() predicate.RootKey {
	return predicate.RootKey(sql.FieldIsNull(FieldBootstrap))
}

// BootstrapNotNil applies the NotNil predicate on the "bootstrap" field.
func BootstrapNotNil() predicate.RootKey {
	return predicate.RootKey(sql.FieldNotNull(FieldBootstrap))
}

// BootstrapEqualFold applies the EqualFold predicate on the "bootstrap" field.
func BootstrapEqualFold(v string) predicate.RootKey {
	return predicate.RootKey(sql.FieldEqualFold(FieldBootstrap, v))
}

// BootstrapContainsFold applies the ContainsFold predicate on the "bootstrap" field.
func BootstrapContainsFold(v string) predicate.RootKey {
	return predicate.RootKey(sql.FieldContainsFold(FieldBootstrap, v))
}

// And groups predicates with the AND operator between them.
func And(predicates ...predicate.RootKey) predicate.RootKey {
	return predicate.RootKey(func(s *sql.Selector) {
		s1 := s.Clone().SetP(nil)
		for _, p := range predicates {
			p(s1)
		}
		s.Where(s1.P())
	})
}

// Or groups predicates with the OR operator between them.
func Or(predicates ...predicate.RootKey) predicate.RootKey {
	return predicate.RootKey(func(s *sql.Selector) {
		s1 := s.Clone().SetP(nil)
		for i, p := range predicates {
			if i > 0 {
				s1.Or()
			}
			p(s1)
		}
		s.Where(s1.P())
	})
}

// Not applies the not operator on the given predicate.
func Not(p predicate.RootKey) predicate.RootKey {
	return predicate.RootKey(func(s *sql.Selector) {
		p(s.Not())
	})
}
