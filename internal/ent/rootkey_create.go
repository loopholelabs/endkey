// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"errors"
	"fmt"
	"time"

	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/loopholelabs/endkey/internal/ent/rootkey"
)

// RootKeyCreate is the builder for creating a RootKey entity.
type RootKeyCreate struct {
	config
	mutation *RootKeyMutation
	hooks    []Hook
}

// SetCreatedAt sets the "created_at" field.
func (rkc *RootKeyCreate) SetCreatedAt(t time.Time) *RootKeyCreate {
	rkc.mutation.SetCreatedAt(t)
	return rkc
}

// SetNillableCreatedAt sets the "created_at" field if the given value is not nil.
func (rkc *RootKeyCreate) SetNillableCreatedAt(t *time.Time) *RootKeyCreate {
	if t != nil {
		rkc.SetCreatedAt(*t)
	}
	return rkc
}

// SetIdentifier sets the "identifier" field.
func (rkc *RootKeyCreate) SetIdentifier(s string) *RootKeyCreate {
	rkc.mutation.SetIdentifier(s)
	return rkc
}

// SetSalt sets the "salt" field.
func (rkc *RootKeyCreate) SetSalt(b []byte) *RootKeyCreate {
	rkc.mutation.SetSalt(b)
	return rkc
}

// SetHash sets the "hash" field.
func (rkc *RootKeyCreate) SetHash(b []byte) *RootKeyCreate {
	rkc.mutation.SetHash(b)
	return rkc
}

// SetBootstrap sets the "bootstrap" field.
func (rkc *RootKeyCreate) SetBootstrap(s string) *RootKeyCreate {
	rkc.mutation.SetBootstrap(s)
	return rkc
}

// SetNillableBootstrap sets the "bootstrap" field if the given value is not nil.
func (rkc *RootKeyCreate) SetNillableBootstrap(s *string) *RootKeyCreate {
	if s != nil {
		rkc.SetBootstrap(*s)
	}
	return rkc
}

// Mutation returns the RootKeyMutation object of the builder.
func (rkc *RootKeyCreate) Mutation() *RootKeyMutation {
	return rkc.mutation
}

// Save creates the RootKey in the database.
func (rkc *RootKeyCreate) Save(ctx context.Context) (*RootKey, error) {
	rkc.defaults()
	return withHooks(ctx, rkc.sqlSave, rkc.mutation, rkc.hooks)
}

// SaveX calls Save and panics if Save returns an error.
func (rkc *RootKeyCreate) SaveX(ctx context.Context) *RootKey {
	v, err := rkc.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (rkc *RootKeyCreate) Exec(ctx context.Context) error {
	_, err := rkc.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (rkc *RootKeyCreate) ExecX(ctx context.Context) {
	if err := rkc.Exec(ctx); err != nil {
		panic(err)
	}
}

// defaults sets the default values of the builder before save.
func (rkc *RootKeyCreate) defaults() {
	if _, ok := rkc.mutation.CreatedAt(); !ok {
		v := rootkey.DefaultCreatedAt()
		rkc.mutation.SetCreatedAt(v)
	}
}

// check runs all checks and user-defined validators on the builder.
func (rkc *RootKeyCreate) check() error {
	if _, ok := rkc.mutation.CreatedAt(); !ok {
		return &ValidationError{Name: "created_at", err: errors.New(`ent: missing required field "RootKey.created_at"`)}
	}
	if _, ok := rkc.mutation.Identifier(); !ok {
		return &ValidationError{Name: "identifier", err: errors.New(`ent: missing required field "RootKey.identifier"`)}
	}
	if v, ok := rkc.mutation.Identifier(); ok {
		if err := rootkey.IdentifierValidator(v); err != nil {
			return &ValidationError{Name: "identifier", err: fmt.Errorf(`ent: validator failed for field "RootKey.identifier": %w`, err)}
		}
	}
	if _, ok := rkc.mutation.Salt(); !ok {
		return &ValidationError{Name: "salt", err: errors.New(`ent: missing required field "RootKey.salt"`)}
	}
	if v, ok := rkc.mutation.Salt(); ok {
		if err := rootkey.SaltValidator(v); err != nil {
			return &ValidationError{Name: "salt", err: fmt.Errorf(`ent: validator failed for field "RootKey.salt": %w`, err)}
		}
	}
	if _, ok := rkc.mutation.Hash(); !ok {
		return &ValidationError{Name: "hash", err: errors.New(`ent: missing required field "RootKey.hash"`)}
	}
	if v, ok := rkc.mutation.Hash(); ok {
		if err := rootkey.HashValidator(v); err != nil {
			return &ValidationError{Name: "hash", err: fmt.Errorf(`ent: validator failed for field "RootKey.hash": %w`, err)}
		}
	}
	return nil
}

func (rkc *RootKeyCreate) sqlSave(ctx context.Context) (*RootKey, error) {
	if err := rkc.check(); err != nil {
		return nil, err
	}
	_node, _spec := rkc.createSpec()
	if err := sqlgraph.CreateNode(ctx, rkc.driver, _spec); err != nil {
		if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return nil, err
	}
	id := _spec.ID.Value.(int64)
	_node.ID = int(id)
	rkc.mutation.id = &_node.ID
	rkc.mutation.done = true
	return _node, nil
}

func (rkc *RootKeyCreate) createSpec() (*RootKey, *sqlgraph.CreateSpec) {
	var (
		_node = &RootKey{config: rkc.config}
		_spec = sqlgraph.NewCreateSpec(rootkey.Table, sqlgraph.NewFieldSpec(rootkey.FieldID, field.TypeInt))
	)
	if value, ok := rkc.mutation.CreatedAt(); ok {
		_spec.SetField(rootkey.FieldCreatedAt, field.TypeTime, value)
		_node.CreatedAt = value
	}
	if value, ok := rkc.mutation.Identifier(); ok {
		_spec.SetField(rootkey.FieldIdentifier, field.TypeString, value)
		_node.Identifier = value
	}
	if value, ok := rkc.mutation.Salt(); ok {
		_spec.SetField(rootkey.FieldSalt, field.TypeBytes, value)
		_node.Salt = value
	}
	if value, ok := rkc.mutation.Hash(); ok {
		_spec.SetField(rootkey.FieldHash, field.TypeBytes, value)
		_node.Hash = value
	}
	if value, ok := rkc.mutation.Bootstrap(); ok {
		_spec.SetField(rootkey.FieldBootstrap, field.TypeString, value)
		_node.Bootstrap = value
	}
	return _node, _spec
}

// RootKeyCreateBulk is the builder for creating many RootKey entities in bulk.
type RootKeyCreateBulk struct {
	config
	builders []*RootKeyCreate
}

// Save creates the RootKey entities in the database.
func (rkcb *RootKeyCreateBulk) Save(ctx context.Context) ([]*RootKey, error) {
	specs := make([]*sqlgraph.CreateSpec, len(rkcb.builders))
	nodes := make([]*RootKey, len(rkcb.builders))
	mutators := make([]Mutator, len(rkcb.builders))
	for i := range rkcb.builders {
		func(i int, root context.Context) {
			builder := rkcb.builders[i]
			builder.defaults()
			var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
				mutation, ok := m.(*RootKeyMutation)
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
					_, err = mutators[i+1].Mutate(root, rkcb.builders[i+1].mutation)
				} else {
					spec := &sqlgraph.BatchCreateSpec{Nodes: specs}
					// Invoke the actual operation on the latest mutation in the chain.
					if err = sqlgraph.BatchCreate(ctx, rkcb.driver, spec); err != nil {
						if sqlgraph.IsConstraintError(err) {
							err = &ConstraintError{msg: err.Error(), wrap: err}
						}
					}
				}
				if err != nil {
					return nil, err
				}
				mutation.id = &nodes[i].ID
				if specs[i].ID.Value != nil {
					id := specs[i].ID.Value.(int64)
					nodes[i].ID = int(id)
				}
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
		if _, err := mutators[0].Mutate(ctx, rkcb.builders[0].mutation); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

// SaveX is like Save, but panics if an error occurs.
func (rkcb *RootKeyCreateBulk) SaveX(ctx context.Context) []*RootKey {
	v, err := rkcb.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (rkcb *RootKeyCreateBulk) Exec(ctx context.Context) error {
	_, err := rkcb.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (rkcb *RootKeyCreateBulk) ExecX(ctx context.Context) {
	if err := rkcb.Exec(ctx); err != nil {
		panic(err)
	}
}
