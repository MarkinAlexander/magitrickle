package models

import (
	"magitrickle/utils/intID"
)

type Group struct {
	ID        intID.ID `yaml:"id"`
	Name      string   `yaml:"name"`
	Color     string   `yaml:"color"`
	Interface string   `yaml:"interface"`
	Enable    bool     `yaml:"enable"`
	Sources   []string `yaml:"sources,omitempty"`
	Rules     []*Rule  `yaml:"rules"`
}
