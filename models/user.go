package models

import (
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	FullName string `json:"fullName"`
	Email    string `gorm:"unique" json:"email"`
	Password string `json:"password"`
	Type     string `json:"type"`
}
