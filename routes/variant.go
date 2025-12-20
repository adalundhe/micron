package routes

import (
	"fmt"

	"github.com/adalundhe/micron/internal"
	"github.com/gin-gonic/gin"
	"github.com/wI2L/fizz"
)

type Variant struct {
	Version     string
	VariantPath string
	Group       *Group
	Service     *internal.Service
}

func NewVariant(version string, description string) *Variant {
	variantPath := fmt.Sprintf("/%s", version)
	return &Variant{
		Version:     version,
		VariantPath: variantPath,
		Group: CreateGroup(
			variantPath,
			GroupConfig{
				Description: description,
				Routes: []*Route{},
				Groups: []*Group{},
				Middleware: []gin.HandlerFunc{},
			}),
	}
}

func (v *Variant) setService(serv *internal.Service) {
	v.Service = serv
}

func (v *Variant) GetPath() string {
	return v.Group.Path
}

func (v *Variant) Build(spec *fizz.Fizz) {
	v.Group.Build(spec)
}

func (v *Variant) SetPath(path string) {
	v.Group.Path = path
}

func (v *Variant) AddMiddleware(middleware ...gin.HandlerFunc) {
	v.Group.AddMiddleware(middleware...)
}

func (v *Variant) AddRoutes(routes ...*Route) []*Route {
	return v.Group.AddRoutes(routes...)
}

func (v *Variant) AddGroups(groups ...*Group) []*Group {
	return v.Group.AddGroups(groups...)
}
