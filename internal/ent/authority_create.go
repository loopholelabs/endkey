// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"errors"
	"fmt"
	"time"

	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/loopholelabs/endkey/internal/ent/apikey"
	"github.com/loopholelabs/endkey/internal/ent/authority"
	"github.com/loopholelabs/endkey/internal/ent/template"
	"github.com/loopholelabs/endkey/internal/ent/userkey"
)

// AuthorityCreate is the builder for creating a Authority entity.
type AuthorityCreate struct {
	config
	mutation *AuthorityMutation
	hooks    []Hook
}

// SetCreatedAt sets the "created_at" field.
func (ac *AuthorityCreate) SetCreatedAt(t time.Time) *AuthorityCreate {
	ac.mutation.SetCreatedAt(t)
	return ac
}

// SetNillableCreatedAt sets the "created_at" field if the given value is not nil.
func (ac *AuthorityCreate) SetNillableCreatedAt(t *time.Time) *AuthorityCreate {
	if t != nil {
		ac.SetCreatedAt(*t)
	}
	return ac
}

// SetName sets the "name" field.
func (ac *AuthorityCreate) SetName(s string) *AuthorityCreate {
	ac.mutation.SetName(s)
	return ac
}

// SetCaCertificatePem sets the "ca_certificate_pem" field.
func (ac *AuthorityCreate) SetCaCertificatePem(b []byte) *AuthorityCreate {
	ac.mutation.SetCaCertificatePem(b)
	return ac
}

// SetEncryptedPrivateKey sets the "encrypted_private_key" field.
func (ac *AuthorityCreate) SetEncryptedPrivateKey(s string) *AuthorityCreate {
	ac.mutation.SetEncryptedPrivateKey(s)
	return ac
}

// SetID sets the "id" field.
func (ac *AuthorityCreate) SetID(s string) *AuthorityCreate {
	ac.mutation.SetID(s)
	return ac
}

// SetUserKeyID sets the "user_key" edge to the UserKey entity by ID.
func (ac *AuthorityCreate) SetUserKeyID(id string) *AuthorityCreate {
	ac.mutation.SetUserKeyID(id)
	return ac
}

// SetNillableUserKeyID sets the "user_key" edge to the UserKey entity by ID if the given value is not nil.
func (ac *AuthorityCreate) SetNillableUserKeyID(id *string) *AuthorityCreate {
	if id != nil {
		ac = ac.SetUserKeyID(*id)
	}
	return ac
}

// SetUserKey sets the "user_key" edge to the UserKey entity.
func (ac *AuthorityCreate) SetUserKey(u *UserKey) *AuthorityCreate {
	return ac.SetUserKeyID(u.ID)
}

// AddAPIKeyIDs adds the "api_keys" edge to the APIKey entity by IDs.
func (ac *AuthorityCreate) AddAPIKeyIDs(ids ...string) *AuthorityCreate {
	ac.mutation.AddAPIKeyIDs(ids...)
	return ac
}

// AddAPIKeys adds the "api_keys" edges to the APIKey entity.
func (ac *AuthorityCreate) AddAPIKeys(a ...*APIKey) *AuthorityCreate {
	ids := make([]string, len(a))
	for i := range a {
		ids[i] = a[i].ID
	}
	return ac.AddAPIKeyIDs(ids...)
}

// AddTemplateIDs adds the "templates" edge to the Template entity by IDs.
func (ac *AuthorityCreate) AddTemplateIDs(ids ...string) *AuthorityCreate {
	ac.mutation.AddTemplateIDs(ids...)
	return ac
}

// AddTemplates adds the "templates" edges to the Template entity.
func (ac *AuthorityCreate) AddTemplates(t ...*Template) *AuthorityCreate {
	ids := make([]string, len(t))
	for i := range t {
		ids[i] = t[i].ID
	}
	return ac.AddTemplateIDs(ids...)
}

// Mutation returns the AuthorityMutation object of the builder.
func (ac *AuthorityCreate) Mutation() *AuthorityMutation {
	return ac.mutation
}

// Save creates the Authority in the database.
func (ac *AuthorityCreate) Save(ctx context.Context) (*Authority, error) {
	ac.defaults()
	return withHooks(ctx, ac.sqlSave, ac.mutation, ac.hooks)
}

// SaveX calls Save and panics if Save returns an error.
func (ac *AuthorityCreate) SaveX(ctx context.Context) *Authority {
	v, err := ac.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (ac *AuthorityCreate) Exec(ctx context.Context) error {
	_, err := ac.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (ac *AuthorityCreate) ExecX(ctx context.Context) {
	if err := ac.Exec(ctx); err != nil {
		panic(err)
	}
}

// defaults sets the default values of the builder before save.
func (ac *AuthorityCreate) defaults() {
	if _, ok := ac.mutation.CreatedAt(); !ok {
		v := authority.DefaultCreatedAt()
		ac.mutation.SetCreatedAt(v)
	}
}

// check runs all checks and user-defined validators on the builder.
func (ac *AuthorityCreate) check() error {
	if _, ok := ac.mutation.CreatedAt(); !ok {
		return &ValidationError{Name: "created_at", err: errors.New(`ent: missing required field "Authority.created_at"`)}
	}
	if _, ok := ac.mutation.Name(); !ok {
		return &ValidationError{Name: "name", err: errors.New(`ent: missing required field "Authority.name"`)}
	}
	if v, ok := ac.mutation.Name(); ok {
		if err := authority.NameValidator(v); err != nil {
			return &ValidationError{Name: "name", err: fmt.Errorf(`ent: validator failed for field "Authority.name": %w`, err)}
		}
	}
	if _, ok := ac.mutation.CaCertificatePem(); !ok {
		return &ValidationError{Name: "ca_certificate_pem", err: errors.New(`ent: missing required field "Authority.ca_certificate_pem"`)}
	}
	if v, ok := ac.mutation.CaCertificatePem(); ok {
		if err := authority.CaCertificatePemValidator(v); err != nil {
			return &ValidationError{Name: "ca_certificate_pem", err: fmt.Errorf(`ent: validator failed for field "Authority.ca_certificate_pem": %w`, err)}
		}
	}
	if _, ok := ac.mutation.EncryptedPrivateKey(); !ok {
		return &ValidationError{Name: "encrypted_private_key", err: errors.New(`ent: missing required field "Authority.encrypted_private_key"`)}
	}
	if v, ok := ac.mutation.EncryptedPrivateKey(); ok {
		if err := authority.EncryptedPrivateKeyValidator(v); err != nil {
			return &ValidationError{Name: "encrypted_private_key", err: fmt.Errorf(`ent: validator failed for field "Authority.encrypted_private_key": %w`, err)}
		}
	}
	if v, ok := ac.mutation.ID(); ok {
		if err := authority.IDValidator(v); err != nil {
			return &ValidationError{Name: "id", err: fmt.Errorf(`ent: validator failed for field "Authority.id": %w`, err)}
		}
	}
	return nil
}

func (ac *AuthorityCreate) sqlSave(ctx context.Context) (*Authority, error) {
	if err := ac.check(); err != nil {
		return nil, err
	}
	_node, _spec := ac.createSpec()
	if err := sqlgraph.CreateNode(ctx, ac.driver, _spec); err != nil {
		if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return nil, err
	}
	if _spec.ID.Value != nil {
		if id, ok := _spec.ID.Value.(string); ok {
			_node.ID = id
		} else {
			return nil, fmt.Errorf("unexpected Authority.ID type: %T", _spec.ID.Value)
		}
	}
	ac.mutation.id = &_node.ID
	ac.mutation.done = true
	return _node, nil
}

func (ac *AuthorityCreate) createSpec() (*Authority, *sqlgraph.CreateSpec) {
	var (
		_node = &Authority{config: ac.config}
		_spec = sqlgraph.NewCreateSpec(authority.Table, sqlgraph.NewFieldSpec(authority.FieldID, field.TypeString))
	)
	if id, ok := ac.mutation.ID(); ok {
		_node.ID = id
		_spec.ID.Value = id
	}
	if value, ok := ac.mutation.CreatedAt(); ok {
		_spec.SetField(authority.FieldCreatedAt, field.TypeTime, value)
		_node.CreatedAt = value
	}
	if value, ok := ac.mutation.Name(); ok {
		_spec.SetField(authority.FieldName, field.TypeString, value)
		_node.Name = value
	}
	if value, ok := ac.mutation.CaCertificatePem(); ok {
		_spec.SetField(authority.FieldCaCertificatePem, field.TypeBytes, value)
		_node.CaCertificatePem = value
	}
	if value, ok := ac.mutation.EncryptedPrivateKey(); ok {
		_spec.SetField(authority.FieldEncryptedPrivateKey, field.TypeString, value)
		_node.EncryptedPrivateKey = value
	}
	if nodes := ac.mutation.UserKeyIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: true,
			Table:   authority.UserKeyTable,
			Columns: []string{authority.UserKeyColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(userkey.FieldID, field.TypeString),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_node.user_key_authorities = &nodes[0]
		_spec.Edges = append(_spec.Edges, edge)
	}
	if nodes := ac.mutation.APIKeysIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: false,
			Table:   authority.APIKeysTable,
			Columns: []string{authority.APIKeysColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(apikey.FieldID, field.TypeString),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges = append(_spec.Edges, edge)
	}
	if nodes := ac.mutation.TemplatesIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: false,
			Table:   authority.TemplatesTable,
			Columns: []string{authority.TemplatesColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(template.FieldID, field.TypeString),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges = append(_spec.Edges, edge)
	}
	return _node, _spec
}

// AuthorityCreateBulk is the builder for creating many Authority entities in bulk.
type AuthorityCreateBulk struct {
	config
	builders []*AuthorityCreate
}

// Save creates the Authority entities in the database.
func (acb *AuthorityCreateBulk) Save(ctx context.Context) ([]*Authority, error) {
	specs := make([]*sqlgraph.CreateSpec, len(acb.builders))
	nodes := make([]*Authority, len(acb.builders))
	mutators := make([]Mutator, len(acb.builders))
	for i := range acb.builders {
		func(i int, root context.Context) {
			builder := acb.builders[i]
			builder.defaults()
			var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
				mutation, ok := m.(*AuthorityMutation)
				if !ok {
					return nil, fmt.Errorf("unexpected mutation type %T", m)
				}
				if err := builder.check(); err != nil {
					return nil, err
				}
				builder.mutation = mutation
				var err error
				nodes[i], specs[i] = builder.createSpec()
				if i < len(mutators)-1 {
					_, err = mutators[i+1].Mutate(root, acb.builders[i+1].mutation)
				} else {
					spec := &sqlgraph.BatchCreateSpec{Nodes: specs}
					// Invoke the actual operation on the latest mutation in the chain.
					if err = sqlgraph.BatchCreate(ctx, acb.driver, spec); err != nil {
						if sqlgraph.IsConstraintError(err) {
							err = &ConstraintError{msg: err.Error(), wrap: err}
						}
					}
				}
				if err != nil {
					return nil, err
				}
				mutation.id = &nodes[i].ID
				mutation.done = true
				return nodes[i], nil
			})
			for i := len(builder.hooks) - 1; i >= 0; i-- {
				mut = builder.hooks[i](mut)
			}
			mutators[i] = mut
		}(i, ctx)
	}
	if len(mutators) > 0 {
		if _, err := mutators[0].Mutate(ctx, acb.builders[0].mutation); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

// SaveX is like Save, but panics if an error occurs.
func (acb *AuthorityCreateBulk) SaveX(ctx context.Context) []*Authority {
	v, err := acb.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (acb *AuthorityCreateBulk) Exec(ctx context.Context) error {
	_, err := acb.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (acb *AuthorityCreateBulk) ExecX(ctx context.Context) {
	if err := acb.Exec(ctx); err != nil {
		panic(err)
	}
}
