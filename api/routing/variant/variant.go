package variant

import (
	"fmt"

	"github.com/adalundhe/micron/api/routing/group"
	"github.com/adalundhe/micron/api/routing/route"
	"github.com/adalundhe/micron/api/service"
	"github.com/gin-gonic/gin"
	"github.com/wI2L/fizz"
)

type Variant struct {
	Version     string
	VariantPath string
	Group       *group.Group
	Service         *service.Service
}

func NewVariant(version string, description string) *Variant {
	variantPath := fmt.Sprintf("/%s", version)
	return &Variant{
		Version:     version,
		VariantPath: variantPath,
		Group: group.CreateGroup(
			variantPath,
			group.GroupConfig{
				Description: description,
			}),
	}
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

func (v *Variant) AddRoutes(routes ...*route.Route) []*route.Route {
	return v.Group.AddRoutes(routes...)
}

func (v *Variant) AddGroups(groups ...*group.Group) []*group.Group {
	return v.Group.AddGroups(groups...)
}
