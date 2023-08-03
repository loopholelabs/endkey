// Code generated by ent, DO NOT EDIT.

package servertemplate

import (
	"time"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"github.com/loopholelabs/endkey/internal/ent/predicate"
)

// ID filters vertices based on their ID field.
func ID(id string) predicate.ServerTemplate {
	return predicate.ServerTemplate(sql.FieldEQ(FieldID, id))
}

// IDEQ applies the EQ predicate on the ID field.
func IDEQ(id string) predicate.ServerTemplate {
	return predicate.ServerTemplate(sql.FieldEQ(FieldID, id))
}

// IDNEQ applies the NEQ predicate on the ID field.
func IDNEQ(id string) predicate.ServerTemplate {
	return predicate.ServerTemplate(sql.FieldNEQ(FieldID, id))
}

// IDIn applies the In predicate on the ID field.
func IDIn(ids ...string) predicate.ServerTemplate {
	return predicate.ServerTemplate(sql.FieldIn(FieldID, ids...))
}

// IDNotIn applies the NotIn predicate on the ID field.
func IDNotIn(ids ...string) predicate.ServerTemplate {
	return predicate.ServerTemplate(sql.FieldNotIn(FieldID, ids...))
}

// IDGT applies the GT predicate on the ID field.
func IDGT(id string) predicate.ServerTemplate {
	return predicate.ServerTemplate(sql.FieldGT(FieldID, id))
}

// IDGTE applies the GTE predicate on the ID field.
func IDGTE(id string) predicate.ServerTemplate {
	return predicate.ServerTemplate(sql.FieldGTE(FieldID, id))
}

// IDLT applies the LT predicate on the ID field.
func IDLT(id string) predicate.ServerTemplate {
	return predicate.ServerTemplate(sql.FieldLT(FieldID, id))
}

// IDLTE applies the LTE predicate on the ID field.
func IDLTE(id string) predicate.ServerTemplate {
	return predicate.ServerTemplate(sql.FieldLTE(FieldID, id))
}

// IDEqualFold applies the EqualFold predicate on the ID field.
func IDEqualFold(id string) predicate.ServerTemplate {
	return predicate.ServerTemplate(sql.FieldEqualFold(FieldID, id))
}

// IDContainsFold applies the ContainsFold predicate on the ID field.
func IDContainsFold(id string) predicate.ServerTemplate {
	return predicate.ServerTemplate(sql.FieldContainsFold(FieldID, id))
}

// CreatedAt applies equality check predicate on the "created_at" field. It's identical to CreatedAtEQ.
func CreatedAt(v time.Time) predicate.ServerTemplate {
	return predicate.ServerTemplate(sql.FieldEQ(FieldCreatedAt, v))
}

// Name applies equality check predicate on the "name" field. It's identical to NameEQ.
func Name(v string) predicate.ServerTemplate {
	return predicate.ServerTemplate(sql.FieldEQ(FieldName, v))
}

// CommonName applies equality check predicate on the "common_name" field. It's identical to CommonNameEQ.
func CommonName(v string) predicate.ServerTemplate {
	return predicate.ServerTemplate(sql.FieldEQ(FieldCommonName, v))
}

// Tag applies equality check predicate on the "tag" field. It's identical to TagEQ.
func Tag(v string) predicate.ServerTemplate {
	return predicate.ServerTemplate(sql.FieldEQ(FieldTag, v))
}

// Validity applies equality check predicate on the "validity" field. It's identical to ValidityEQ.
func Validity(v string) predicate.ServerTemplate {
	return predicate.ServerTemplate(sql.FieldEQ(FieldValidity, v))
}

// AllowAdditionalDNSNames applies equality check predicate on the "allow_additional_dns_names" field. It's identical to AllowAdditionalDNSNamesEQ.
func AllowAdditionalDNSNames(v bool) predicate.ServerTemplate {
	return predicate.ServerTemplate(sql.FieldEQ(FieldAllowAdditionalDNSNames, v))
}

// AllowAdditionalIps applies equality check predicate on the "allow_additional_ips" field. It's identical to AllowAdditionalIpsEQ.
func AllowAdditionalIps(v bool) predicate.ServerTemplate {
	return predicate.ServerTemplate(sql.FieldEQ(FieldAllowAdditionalIps, v))
}

// CreatedAtEQ applies the EQ predicate on the "created_at" field.
func CreatedAtEQ(v time.Time) predicate.ServerTemplate {
	return predicate.ServerTemplate(sql.FieldEQ(FieldCreatedAt, v))
}

// CreatedAtNEQ applies the NEQ predicate on the "created_at" field.
func CreatedAtNEQ(v time.Time) predicate.ServerTemplate {
	return predicate.ServerTemplate(sql.FieldNEQ(FieldCreatedAt, v))
}

// CreatedAtIn applies the In predicate on the "created_at" field.
func CreatedAtIn(vs ...time.Time) predicate.ServerTemplate {
	return predicate.ServerTemplate(sql.FieldIn(FieldCreatedAt, vs...))
}

// CreatedAtNotIn applies the NotIn predicate on the "created_at" field.
func CreatedAtNotIn(vs ...time.Time) predicate.ServerTemplate {
	return predicate.ServerTemplate(sql.FieldNotIn(FieldCreatedAt, vs...))
}

// CreatedAtGT applies the GT predicate on the "created_at" field.
func CreatedAtGT(v time.Time) predicate.ServerTemplate {
	return predicate.ServerTemplate(sql.FieldGT(FieldCreatedAt, v))
}

// CreatedAtGTE applies the GTE predicate on the "created_at" field.
func CreatedAtGTE(v time.Time) predicate.ServerTemplate {
	return predicate.ServerTemplate(sql.FieldGTE(FieldCreatedAt, v))
}

// CreatedAtLT applies the LT predicate on the "created_at" field.
func CreatedAtLT(v time.Time) predicate.ServerTemplate {
	return predicate.ServerTemplate(sql.FieldLT(FieldCreatedAt, v))
}

// CreatedAtLTE applies the LTE predicate on the "created_at" field.
func CreatedAtLTE(v time.Time) predicate.ServerTemplate {
	return predicate.ServerTemplate(sql.FieldLTE(FieldCreatedAt, v))
}

// NameEQ applies the EQ predicate on the "name" field.
func NameEQ(v string) predicate.ServerTemplate {
	return predicate.ServerTemplate(sql.FieldEQ(FieldName, v))
}

// NameNEQ applies the NEQ predicate on the "name" field.
func NameNEQ(v string) predicate.ServerTemplate {
	return predicate.ServerTemplate(sql.FieldNEQ(FieldName, v))
}

// NameIn applies the In predicate on the "name" field.
func NameIn(vs ...string) predicate.ServerTemplate {
	return predicate.ServerTemplate(sql.FieldIn(FieldName, vs...))
}

// NameNotIn applies the NotIn predicate on the "name" field.
func NameNotIn(vs ...string) predicate.ServerTemplate {
	return predicate.ServerTemplate(sql.FieldNotIn(FieldName, vs...))
}

// NameGT applies the GT predicate on the "name" field.
func NameGT(v string) predicate.ServerTemplate {
	return predicate.ServerTemplate(sql.FieldGT(FieldName, v))
}

// NameGTE applies the GTE predicate on the "name" field.
func NameGTE(v string) predicate.ServerTemplate {
	return predicate.ServerTemplate(sql.FieldGTE(FieldName, v))
}

// NameLT applies the LT predicate on the "name" field.
func NameLT(v string) predicate.ServerTemplate {
	return predicate.ServerTemplate(sql.FieldLT(FieldName, v))
}

// NameLTE applies the LTE predicate on the "name" field.
func NameLTE(v string) predicate.ServerTemplate {
	return predicate.ServerTemplate(sql.FieldLTE(FieldName, v))
}

// NameContains applies the Contains predicate on the "name" field.
func NameContains(v string) predicate.ServerTemplate {
	return predicate.ServerTemplate(sql.FieldContains(FieldName, v))
}

// NameHasPrefix applies the HasPrefix predicate on the "name" field.
func NameHasPrefix(v string) predicate.ServerTemplate {
	return predicate.ServerTemplate(sql.FieldHasPrefix(FieldName, v))
}

// NameHasSuffix applies the HasSuffix predicate on the "name" field.
func NameHasSuffix(v string) predicate.ServerTemplate {
	return predicate.ServerTemplate(sql.FieldHasSuffix(FieldName, v))
}

// NameEqualFold applies the EqualFold predicate on the "name" field.
func NameEqualFold(v string) predicate.ServerTemplate {
	return predicate.ServerTemplate(sql.FieldEqualFold(FieldName, v))
}

// NameContainsFold applies the ContainsFold predicate on the "name" field.
func NameContainsFold(v string) predicate.ServerTemplate {
	return predicate.ServerTemplate(sql.FieldContainsFold(FieldName, v))
}

// CommonNameEQ applies the EQ predicate on the "common_name" field.
func CommonNameEQ(v string) predicate.ServerTemplate {
	return predicate.ServerTemplate(sql.FieldEQ(FieldCommonName, v))
}

// CommonNameNEQ applies the NEQ predicate on the "common_name" field.
func CommonNameNEQ(v string) predicate.ServerTemplate {
	return predicate.ServerTemplate(sql.FieldNEQ(FieldCommonName, v))
}

// CommonNameIn applies the In predicate on the "common_name" field.
func CommonNameIn(vs ...string) predicate.ServerTemplate {
	return predicate.ServerTemplate(sql.FieldIn(FieldCommonName, vs...))
}

// CommonNameNotIn applies the NotIn predicate on the "common_name" field.
func CommonNameNotIn(vs ...string) predicate.ServerTemplate {
	return predicate.ServerTemplate(sql.FieldNotIn(FieldCommonName, vs...))
}

// CommonNameGT applies the GT predicate on the "common_name" field.
func CommonNameGT(v string) predicate.ServerTemplate {
	return predicate.ServerTemplate(sql.FieldGT(FieldCommonName, v))
}

// CommonNameGTE applies the GTE predicate on the "common_name" field.
func CommonNameGTE(v string) predicate.ServerTemplate {
	return predicate.ServerTemplate(sql.FieldGTE(FieldCommonName, v))
}

// CommonNameLT applies the LT predicate on the "common_name" field.
func CommonNameLT(v string) predicate.ServerTemplate {
	return predicate.ServerTemplate(sql.FieldLT(FieldCommonName, v))
}

// CommonNameLTE applies the LTE predicate on the "common_name" field.
func CommonNameLTE(v string) predicate.ServerTemplate {
	return predicate.ServerTemplate(sql.FieldLTE(FieldCommonName, v))
}

// CommonNameContains applies the Contains predicate on the "common_name" field.
func CommonNameContains(v string) predicate.ServerTemplate {
	return predicate.ServerTemplate(sql.FieldContains(FieldCommonName, v))
}

// CommonNameHasPrefix applies the HasPrefix predicate on the "common_name" field.
func CommonNameHasPrefix(v string) predicate.ServerTemplate {
	return predicate.ServerTemplate(sql.FieldHasPrefix(FieldCommonName, v))
}

// CommonNameHasSuffix applies the HasSuffix predicate on the "common_name" field.
func CommonNameHasSuffix(v string) predicate.ServerTemplate {
	return predicate.ServerTemplate(sql.FieldHasSuffix(FieldCommonName, v))
}

// CommonNameEqualFold applies the EqualFold predicate on the "common_name" field.
func CommonNameEqualFold(v string) predicate.ServerTemplate {
	return predicate.ServerTemplate(sql.FieldEqualFold(FieldCommonName, v))
}

// CommonNameContainsFold applies the ContainsFold predicate on the "common_name" field.
func CommonNameContainsFold(v string) predicate.ServerTemplate {
	return predicate.ServerTemplate(sql.FieldContainsFold(FieldCommonName, v))
}

// TagEQ applies the EQ predicate on the "tag" field.
func TagEQ(v string) predicate.ServerTemplate {
	return predicate.ServerTemplate(sql.FieldEQ(FieldTag, v))
}

// TagNEQ applies the NEQ predicate on the "tag" field.
func TagNEQ(v string) predicate.ServerTemplate {
	return predicate.ServerTemplate(sql.FieldNEQ(FieldTag, v))
}

// TagIn applies the In predicate on the "tag" field.
func TagIn(vs ...string) predicate.ServerTemplate {
	return predicate.ServerTemplate(sql.FieldIn(FieldTag, vs...))
}

// TagNotIn applies the NotIn predicate on the "tag" field.
func TagNotIn(vs ...string) predicate.ServerTemplate {
	return predicate.ServerTemplate(sql.FieldNotIn(FieldTag, vs...))
}

// TagGT applies the GT predicate on the "tag" field.
func TagGT(v string) predicate.ServerTemplate {
	return predicate.ServerTemplate(sql.FieldGT(FieldTag, v))
}

// TagGTE applies the GTE predicate on the "tag" field.
func TagGTE(v string) predicate.ServerTemplate {
	return predicate.ServerTemplate(sql.FieldGTE(FieldTag, v))
}

// TagLT applies the LT predicate on the "tag" field.
func TagLT(v string) predicate.ServerTemplate {
	return predicate.ServerTemplate(sql.FieldLT(FieldTag, v))
}

// TagLTE applies the LTE predicate on the "tag" field.
func TagLTE(v string) predicate.ServerTemplate {
	return predicate.ServerTemplate(sql.FieldLTE(FieldTag, v))
}

// TagContains applies the Contains predicate on the "tag" field.
func TagContains(v string) predicate.ServerTemplate {
	return predicate.ServerTemplate(sql.FieldContains(FieldTag, v))
}

// TagHasPrefix applies the HasPrefix predicate on the "tag" field.
func TagHasPrefix(v string) predicate.ServerTemplate {
	return predicate.ServerTemplate(sql.FieldHasPrefix(FieldTag, v))
}

// TagHasSuffix applies the HasSuffix predicate on the "tag" field.
func TagHasSuffix(v string) predicate.ServerTemplate {
	return predicate.ServerTemplate(sql.FieldHasSuffix(FieldTag, v))
}

// TagEqualFold applies the EqualFold predicate on the "tag" field.
func TagEqualFold(v string) predicate.ServerTemplate {
	return predicate.ServerTemplate(sql.FieldEqualFold(FieldTag, v))
}

// TagContainsFold applies the ContainsFold predicate on the "tag" field.
func TagContainsFold(v string) predicate.ServerTemplate {
	return predicate.ServerTemplate(sql.FieldContainsFold(FieldTag, v))
}

// ValidityEQ applies the EQ predicate on the "validity" field.
func ValidityEQ(v string) predicate.ServerTemplate {
	return predicate.ServerTemplate(sql.FieldEQ(FieldValidity, v))
}

// ValidityNEQ applies the NEQ predicate on the "validity" field.
func ValidityNEQ(v string) predicate.ServerTemplate {
	return predicate.ServerTemplate(sql.FieldNEQ(FieldValidity, v))
}

// ValidityIn applies the In predicate on the "validity" field.
func ValidityIn(vs ...string) predicate.ServerTemplate {
	return predicate.ServerTemplate(sql.FieldIn(FieldValidity, vs...))
}

// ValidityNotIn applies the NotIn predicate on the "validity" field.
func ValidityNotIn(vs ...string) predicate.ServerTemplate {
	return predicate.ServerTemplate(sql.FieldNotIn(FieldValidity, vs...))
}

// ValidityGT applies the GT predicate on the "validity" field.
func ValidityGT(v string) predicate.ServerTemplate {
	return predicate.ServerTemplate(sql.FieldGT(FieldValidity, v))
}

// ValidityGTE applies the GTE predicate on the "validity" field.
func ValidityGTE(v string) predicate.ServerTemplate {
	return predicate.ServerTemplate(sql.FieldGTE(FieldValidity, v))
}

// ValidityLT applies the LT predicate on the "validity" field.
func ValidityLT(v string) predicate.ServerTemplate {
	return predicate.ServerTemplate(sql.FieldLT(FieldValidity, v))
}

// ValidityLTE applies the LTE predicate on the "validity" field.
func ValidityLTE(v string) predicate.ServerTemplate {
	return predicate.ServerTemplate(sql.FieldLTE(FieldValidity, v))
}

// ValidityContains applies the Contains predicate on the "validity" field.
func ValidityContains(v string) predicate.ServerTemplate {
	return predicate.ServerTemplate(sql.FieldContains(FieldValidity, v))
}

// ValidityHasPrefix applies the HasPrefix predicate on the "validity" field.
func ValidityHasPrefix(v string) predicate.ServerTemplate {
	return predicate.ServerTemplate(sql.FieldHasPrefix(FieldValidity, v))
}

// ValidityHasSuffix applies the HasSuffix predicate on the "validity" field.
func ValidityHasSuffix(v string) predicate.ServerTemplate {
	return predicate.ServerTemplate(sql.FieldHasSuffix(FieldValidity, v))
}

// ValidityEqualFold applies the EqualFold predicate on the "validity" field.
func ValidityEqualFold(v string) predicate.ServerTemplate {
	return predicate.ServerTemplate(sql.FieldEqualFold(FieldValidity, v))
}

// ValidityContainsFold applies the ContainsFold predicate on the "validity" field.
func ValidityContainsFold(v string) predicate.ServerTemplate {
	return predicate.ServerTemplate(sql.FieldContainsFold(FieldValidity, v))
}

// DNSNamesIsNil applies the IsNil predicate on the "dns_names" field.
func DNSNamesIsNil() predicate.ServerTemplate {
	return predicate.ServerTemplate(sql.FieldIsNull(FieldDNSNames))
}

// DNSNamesNotNil applies the NotNil predicate on the "dns_names" field.
func DNSNamesNotNil() predicate.ServerTemplate {
	return predicate.ServerTemplate(sql.FieldNotNull(FieldDNSNames))
}

// AllowAdditionalDNSNamesEQ applies the EQ predicate on the "allow_additional_dns_names" field.
func AllowAdditionalDNSNamesEQ(v bool) predicate.ServerTemplate {
	return predicate.ServerTemplate(sql.FieldEQ(FieldAllowAdditionalDNSNames, v))
}

// AllowAdditionalDNSNamesNEQ applies the NEQ predicate on the "allow_additional_dns_names" field.
func AllowAdditionalDNSNamesNEQ(v bool) predicate.ServerTemplate {
	return predicate.ServerTemplate(sql.FieldNEQ(FieldAllowAdditionalDNSNames, v))
}

// IPAddressesIsNil applies the IsNil predicate on the "ip_addresses" field.
func IPAddressesIsNil() predicate.ServerTemplate {
	return predicate.ServerTemplate(sql.FieldIsNull(FieldIPAddresses))
}

// IPAddressesNotNil applies the NotNil predicate on the "ip_addresses" field.
func IPAddressesNotNil() predicate.ServerTemplate {
	return predicate.ServerTemplate(sql.FieldNotNull(FieldIPAddresses))
}

// AllowAdditionalIpsEQ applies the EQ predicate on the "allow_additional_ips" field.
func AllowAdditionalIpsEQ(v bool) predicate.ServerTemplate {
	return predicate.ServerTemplate(sql.FieldEQ(FieldAllowAdditionalIps, v))
}

// AllowAdditionalIpsNEQ applies the NEQ predicate on the "allow_additional_ips" field.
func AllowAdditionalIpsNEQ(v bool) predicate.ServerTemplate {
	return predicate.ServerTemplate(sql.FieldNEQ(FieldAllowAdditionalIps, v))
}

// HasAuthority applies the HasEdge predicate on the "authority" edge.
func HasAuthority() predicate.ServerTemplate {
	return predicate.ServerTemplate(func(s *sql.Selector) {
		step := sqlgraph.NewStep(
			sqlgraph.From(Table, FieldID),
			sqlgraph.Edge(sqlgraph.M2O, true, AuthorityTable, AuthorityColumn),
		)
		sqlgraph.HasNeighbors(s, step)
	})
}

// HasAuthorityWith applies the HasEdge predicate on the "authority" edge with a given conditions (other predicates).
func HasAuthorityWith(preds ...predicate.Authority) predicate.ServerTemplate {
	return predicate.ServerTemplate(func(s *sql.Selector) {
		step := newAuthorityStep()
		sqlgraph.HasNeighborsWith(s, step, func(s *sql.Selector) {
			for _, p := range preds {
				p(s)
			}
		})
	})
}

// HasAPIKeys applies the HasEdge predicate on the "api_keys" edge.
func HasAPIKeys() predicate.ServerTemplate {
	return predicate.ServerTemplate(func(s *sql.Selector) {
		step := sqlgraph.NewStep(
			sqlgraph.From(Table, FieldID),
			sqlgraph.Edge(sqlgraph.O2M, false, APIKeysTable, APIKeysColumn),
		)
		sqlgraph.HasNeighbors(s, step)
	})
}

// HasAPIKeysWith applies the HasEdge predicate on the "api_keys" edge with a given conditions (other predicates).
func HasAPIKeysWith(preds ...predicate.APIKey) predicate.ServerTemplate {
	return predicate.ServerTemplate(func(s *sql.Selector) {
		step := newAPIKeysStep()
		sqlgraph.HasNeighborsWith(s, step, func(s *sql.Selector) {
			for _, p := range preds {
				p(s)
			}
		})
	})
}

// And groups predicates with the AND operator between them.
func And(predicates ...predicate.ServerTemplate) predicate.ServerTemplate {
	return predicate.ServerTemplate(func(s *sql.Selector) {
		s1 := s.Clone().SetP(nil)
		for _, p := range predicates {
			p(s1)
		}
		s.Where(s1.P())
	})
}

// Or groups predicates with the OR operator between them.
func Or(predicates ...predicate.ServerTemplate) predicate.ServerTemplate {
	return predicate.ServerTemplate(func(s *sql.Selector) {
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
func Not(p predicate.ServerTemplate) predicate.ServerTemplate {
	return predicate.ServerTemplate(func(s *sql.Selector) {
		p(s.Not())
	})
}
