package models

import (
	"gorm.io/gorm"
)

type Project struct {
	gorm.Model
	Title       string `json:"title"`
	Description string `json:"description"`
	Status      string `json:"status"`
}
