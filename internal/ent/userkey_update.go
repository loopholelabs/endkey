// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"errors"
	"fmt"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/loopholelabs/endkey/internal/ent/authority"
	"github.com/loopholelabs/endkey/internal/ent/predicate"
	"github.com/loopholelabs/endkey/internal/ent/rootkey"
	"github.com/loopholelabs/endkey/internal/ent/userkey"
)

// UserKeyUpdate is the builder for updating UserKey entities.
type UserKeyUpdate struct {
	config
	hooks    []Hook
	mutation *UserKeyMutation
}

// Where appends a list predicates to the UserKeyUpdate builder.
func (uku *UserKeyUpdate) Where(ps ...predicate.UserKey) *UserKeyUpdate {
	uku.mutation.Where(ps...)
	return uku
}

// SetRootKeyID sets the "root_key" edge to the RootKey entity by ID.
func (uku *UserKeyUpdate) SetRootKeyID(id string) *UserKeyUpdate {
	uku.mutation.SetRootKeyID(id)
	return uku
}

// SetNillableRootKeyID sets the "root_key" edge to the RootKey entity by ID if the given value is not nil.
func (uku *UserKeyUpdate) SetNillableRootKeyID(id *string) *UserKeyUpdate {
	if id != nil {
		uku = uku.SetRootKeyID(*id)
	}
	return uku
}

// SetRootKey sets the "root_key" edge to the RootKey entity.
func (uku *UserKeyUpdate) SetRootKey(r *RootKey) *UserKeyUpdate {
	return uku.SetRootKeyID(r.ID)
}

// AddAuthorityIDs adds the "authorities" edge to the Authority entity by IDs.
func (uku *UserKeyUpdate) AddAuthorityIDs(ids ...string) *UserKeyUpdate {
	uku.mutation.AddAuthorityIDs(ids...)
	return uku
}

// AddAuthorities adds the "authorities" edges to the Authority entity.
func (uku *UserKeyUpdate) AddAuthorities(a ...*Authority) *UserKeyUpdate {
	ids := make([]string, len(a))
	for i := range a {
		ids[i] = a[i].ID
	}
	return uku.AddAuthorityIDs(ids...)
}

// Mutation returns the UserKeyMutation object of the builder.
func (uku *UserKeyUpdate) Mutation() *UserKeyMutation {
	return uku.mutation
}

// ClearRootKey clears the "root_key" edge to the RootKey entity.
func (uku *UserKeyUpdate) ClearRootKey() *UserKeyUpdate {
	uku.mutation.ClearRootKey()
	return uku
}

// ClearAuthorities clears all "authorities" edges to the Authority entity.
func (uku *UserKeyUpdate) ClearAuthorities() *UserKeyUpdate {
	uku.mutation.ClearAuthorities()
	return uku
}

// RemoveAuthorityIDs removes the "authorities" edge to Authority entities by IDs.
func (uku *UserKeyUpdate) RemoveAuthorityIDs(ids ...string) *UserKeyUpdate {
	uku.mutation.RemoveAuthorityIDs(ids...)
	return uku
}

// RemoveAuthorities removes "authorities" edges to Authority entities.
func (uku *UserKeyUpdate) RemoveAuthorities(a ...*Authority) *UserKeyUpdate {
	ids := make([]string, len(a))
	for i := range a {
		ids[i] = a[i].ID
	}
	return uku.RemoveAuthorityIDs(ids...)
}

// Save executes the query and returns the number of nodes affected by the update operation.
func (uku *UserKeyUpdate) Save(ctx context.Context) (int, error) {
	return withHooks(ctx, uku.sqlSave, uku.mutation, uku.hooks)
}

// SaveX is like Save, but panics if an error occurs.
func (uku *UserKeyUpdate) SaveX(ctx context.Context) int {
	affected, err := uku.Save(ctx)
	if err != nil {
		panic(err)
	}
	return affected
}

// Exec executes the query.
func (uku *UserKeyUpdate) Exec(ctx context.Context) error {
	_, err := uku.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (uku *UserKeyUpdate) ExecX(ctx context.Context) {
	if err := uku.Exec(ctx); err != nil {
		panic(err)
	}
}

func (uku *UserKeyUpdate) sqlSave(ctx context.Context) (n int, err error) {
	_spec := sqlgraph.NewUpdateSpec(userkey.Table, userkey.Columns, sqlgraph.NewFieldSpec(userkey.FieldID, field.TypeString))
	if ps := uku.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if uku.mutation.RootKeyCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: true,
			Table:   userkey.RootKeyTable,
			Columns: []string{userkey.RootKeyColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(rootkey.FieldID, field.TypeString),
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := uku.mutation.RootKeyIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: true,
			Table:   userkey.RootKeyTable,
			Columns: []string{userkey.RootKeyColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(rootkey.FieldID, field.TypeString),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	if uku.mutation.AuthoritiesCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: false,
			Table:   userkey.AuthoritiesTable,
			Columns: []string{userkey.AuthoritiesColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(authority.FieldID, field.TypeString),
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := uku.mutation.RemovedAuthoritiesIDs(); len(nodes) > 0 && !uku.mutation.AuthoritiesCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: false,
			Table:   userkey.AuthoritiesTable,
			Columns: []string{userkey.AuthoritiesColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(authority.FieldID, field.TypeString),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := uku.mutation.AuthoritiesIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: false,
			Table:   userkey.AuthoritiesTable,
			Columns: []string{userkey.AuthoritiesColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(authority.FieldID, field.TypeString),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	if n, err = sqlgraph.UpdateNodes(ctx, uku.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{userkey.Label}
		} else if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return 0, err
	}
	uku.mutation.done = true
	return n, nil
}

// UserKeyUpdateOne is the builder for updating a single UserKey entity.
type UserKeyUpdateOne struct {
	config
	fields   []string
	hooks    []Hook
	mutation *UserKeyMutation
}

// SetRootKeyID sets the "root_key" edge to the RootKey entity by ID.
func (ukuo *UserKeyUpdateOne) SetRootKeyID(id string) *UserKeyUpdateOne {
	ukuo.mutation.SetRootKeyID(id)
	return ukuo
}

// SetNillableRootKeyID sets the "root_key" edge to the RootKey entity by ID if the given value is not nil.
func (ukuo *UserKeyUpdateOne) SetNillableRootKeyID(id *string) *UserKeyUpdateOne {
	if id != nil {
		ukuo = ukuo.SetRootKeyID(*id)
	}
	return ukuo
}

// SetRootKey sets the "root_key" edge to the RootKey entity.
func (ukuo *UserKeyUpdateOne) SetRootKey(r *RootKey) *UserKeyUpdateOne {
	return ukuo.SetRootKeyID(r.ID)
}

// AddAuthorityIDs adds the "authorities" edge to the Authority entity by IDs.
func (ukuo *UserKeyUpdateOne) AddAuthorityIDs(ids ...string) *UserKeyUpdateOne {
	ukuo.mutation.AddAuthorityIDs(ids...)
	return ukuo
}

// AddAuthorities adds the "authorities" edges to the Authority entity.
func (ukuo *UserKeyUpdateOne) AddAuthorities(a ...*Authority) *UserKeyUpdateOne {
	ids := make([]string, len(a))
	for i := range a {
		ids[i] = a[i].ID
	}
	return ukuo.AddAuthorityIDs(ids...)
}

// Mutation returns the UserKeyMutation object of the builder.
func (ukuo *UserKeyUpdateOne) Mutation() *UserKeyMutation {
	return ukuo.mutation
}

// ClearRootKey clears the "root_key" edge to the RootKey entity.
func (ukuo *UserKeyUpdateOne) ClearRootKey() *UserKeyUpdateOne {
	ukuo.mutation.ClearRootKey()
	return ukuo
}

// ClearAuthorities clears all "authorities" edges to the Authority entity.
func (ukuo *UserKeyUpdateOne) ClearAuthorities() *UserKeyUpdateOne {
	ukuo.mutation.ClearAuthorities()
	return ukuo
}

// RemoveAuthorityIDs removes the "authorities" edge to Authority entities by IDs.
func (ukuo *UserKeyUpdateOne) RemoveAuthorityIDs(ids ...string) *UserKeyUpdateOne {
	ukuo.mutation.RemoveAuthorityIDs(ids...)
	return ukuo
}

// RemoveAuthorities removes "authorities" edges to Authority entities.
func (ukuo *UserKeyUpdateOne) RemoveAuthorities(a ...*Authority) *UserKeyUpdateOne {
	ids := make([]string, len(a))
	for i := range a {
		ids[i] = a[i].ID
	}
	return ukuo.RemoveAuthorityIDs(ids...)
}

// Where appends a list predicates to the UserKeyUpdate builder.
func (ukuo *UserKeyUpdateOne) Where(ps ...predicate.UserKey) *UserKeyUpdateOne {
	ukuo.mutation.Where(ps...)
	return ukuo
}

// Select allows selecting one or more fields (columns) of the returned entity.
// The default is selecting all fields defined in the entity schema.
func (ukuo *UserKeyUpdateOne) Select(field string, fields ...string) *UserKeyUpdateOne {
	ukuo.fields = append([]string{field}, fields...)
	return ukuo
}

// Save executes the query and returns the updated UserKey entity.
func (ukuo *UserKeyUpdateOne) Save(ctx context.Context) (*UserKey, error) {
	return withHooks(ctx, ukuo.sqlSave, ukuo.mutation, ukuo.hooks)
}

// SaveX is like Save, but panics if an error occurs.
func (ukuo *UserKeyUpdateOne) SaveX(ctx context.Context) *UserKey {
	node, err := ukuo.Save(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// Exec executes the query on the entity.
func (ukuo *UserKeyUpdateOne) Exec(ctx context.Context) error {
	_, err := ukuo.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (ukuo *UserKeyUpdateOne) ExecX(ctx context.Context) {
	if err := ukuo.Exec(ctx); err != nil {
		panic(err)
	}
}

func (ukuo *UserKeyUpdateOne) sqlSave(ctx context.Context) (_node *UserKey, err error) {
	_spec := sqlgraph.NewUpdateSpec(userkey.Table, userkey.Columns, sqlgraph.NewFieldSpec(userkey.FieldID, field.TypeString))
	id, ok := ukuo.mutation.ID()
	if !ok {
		return nil, &ValidationError{Name: "id", err: errors.New(`ent: missing "UserKey.id" for update`)}
	}
	_spec.Node.ID.Value = id
	if fields := ukuo.fields; len(fields) > 0 {
		_spec.Node.Columns = make([]string, 0, len(fields))
		_spec.Node.Columns = append(_spec.Node.Columns, userkey.FieldID)
		for _, f := range fields {
			if !userkey.ValidColumn(f) {
				return nil, &ValidationError{Name: f, err: fmt.Errorf("ent: invalid field %q for query", f)}
			}
			if f != userkey.FieldID {
				_spec.Node.Columns = append(_spec.Node.Columns, f)
			}
		}
	}
	if ps := ukuo.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if ukuo.mutation.RootKeyCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: true,
			Table:   userkey.RootKeyTable,
			Columns: []string{userkey.RootKeyColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(rootkey.FieldID, field.TypeString),
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := ukuo.mutation.RootKeyIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: true,
			Table:   userkey.RootKeyTable,
			Columns: []string{userkey.RootKeyColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(rootkey.FieldID, field.TypeString),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	if ukuo.mutation.AuthoritiesCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: false,
			Table:   userkey.AuthoritiesTable,
			Columns: []string{userkey.AuthoritiesColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(authority.FieldID, field.TypeString),
			},
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := ukuo.mutation.RemovedAuthoritiesIDs(); len(nodes) > 0 && !ukuo.mutation.AuthoritiesCleared() {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: false,
			Table:   userkey.AuthoritiesTable,
			Columns: []string{userkey.AuthoritiesColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(authority.FieldID, field.TypeString),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Clear = append(_spec.Edges.Clear, edge)
	}
	if nodes := ukuo.mutation.AuthoritiesIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: false,
			Table:   userkey.AuthoritiesTable,
			Columns: []string{userkey.AuthoritiesColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(authority.FieldID, field.TypeString),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges.Add = append(_spec.Edges.Add, edge)
	}
	_node = &UserKey{config: ukuo.config}
	_spec.Assign = _node.assignValues
	_spec.ScanValues = _node.scanValues
	if err = sqlgraph.UpdateNode(ctx, ukuo.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{userkey.Label}
		} else if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return nil, err
	}
	ukuo.mutation.done = true
	return _node, nil
}
