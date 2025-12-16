package variant

import (
	"fmt"

	"github.com/adalundhe/micron/api/internal/group"
	api "github.com/adalundhe/micron/api/internal/provider"
	"github.com/adalundhe/micron/api/internal/route"
	"github.com/gin-gonic/gin"
	"github.com/wI2L/fizz"
)

type Variant struct {
	Version     string
	VariantPath string
	Group       *group.Group
	API         *api.API
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
