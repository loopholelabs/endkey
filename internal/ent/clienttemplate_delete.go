// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/loopholelabs/endkey/internal/ent/clienttemplate"
	"github.com/loopholelabs/endkey/internal/ent/predicate"
)

// ClientTemplateDelete is the builder for deleting a ClientTemplate entity.
type ClientTemplateDelete struct {
	config
	hooks    []Hook
	mutation *ClientTemplateMutation
}

// Where appends a list predicates to the ClientTemplateDelete builder.
func (ctd *ClientTemplateDelete) Where(ps ...predicate.ClientTemplate) *ClientTemplateDelete {
	ctd.mutation.Where(ps...)
	return ctd
}

// Exec executes the deletion query and returns how many vertices were deleted.
func (ctd *ClientTemplateDelete) Exec(ctx context.Context) (int, error) {
	return withHooks(ctx, ctd.sqlExec, ctd.mutation, ctd.hooks)
}

// ExecX is like Exec, but panics if an error occurs.
func (ctd *ClientTemplateDelete) ExecX(ctx context.Context) int {
	n, err := ctd.Exec(ctx)
	if err != nil {
		panic(err)
	}
	return n
}

func (ctd *ClientTemplateDelete) sqlExec(ctx context.Context) (int, error) {
	_spec := sqlgraph.NewDeleteSpec(clienttemplate.Table, sqlgraph.NewFieldSpec(clienttemplate.FieldID, field.TypeInt))
	if ps := ctd.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	affected, err := sqlgraph.DeleteNodes(ctx, ctd.driver, _spec)
	if err != nil && sqlgraph.IsConstraintError(err) {
		err = &ConstraintError{msg: err.Error(), wrap: err}
	}
	ctd.mutation.done = true
	return affected, err
}

// ClientTemplateDeleteOne is the builder for deleting a single ClientTemplate entity.
type ClientTemplateDeleteOne struct {
	ctd *ClientTemplateDelete
}

// Where appends a list predicates to the ClientTemplateDelete builder.
func (ctdo *ClientTemplateDeleteOne) Where(ps ...predicate.ClientTemplate) *ClientTemplateDeleteOne {
	ctdo.ctd.mutation.Where(ps...)
	return ctdo
}

// Exec executes the deletion query.
func (ctdo *ClientTemplateDeleteOne) Exec(ctx context.Context) error {
	n, err := ctdo.ctd.Exec(ctx)
	switch {
	case err != nil:
		return err
	case n == 0:
		return &NotFoundError{clienttemplate.Label}
	default:
		return nil
	}
}

// ExecX is like Exec, but panics if an error occurs.
func (ctdo *ClientTemplateDeleteOne) ExecX(ctx context.Context) {
	if err := ctdo.Exec(ctx); err != nil {
		panic(err)
	}
}
