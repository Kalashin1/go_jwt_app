package controllers

import (
	"encoding/json"
	"go_jwt_app/helper"
	"go_jwt_app/models"
	"net/http"

	"github.com/gorilla/mux"
	"gorm.io/gorm"
)

type Payload struct {
	models.User
	Token string `json:"token"`
}

func Ping(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("pong"))
}

func CreateUser(db *gorm.DB) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		var payload models.User
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		hashedPassword := helper.HasUserPassword([]byte(payload.Password))
		user := models.User{
			FullName: payload.FullName,
			Email:    payload.Email,
			Password: string(hashedPassword),
			Type:     payload.Type,
		}

		result := db.Create(&user)
		if result.Error != nil {
			http.Error(w, result.Error.Error(), http.StatusInternalServerError)
			return
		}
		token, err := helper.CreateToken(user.Email, user.Type)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		resPayload := Payload{
			User:  user,
			Token: token,
		}

		json.NewEncoder(w).Encode(resPayload)
	}
}

func Login(db *gorm.DB) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		reqPayload, err := helper.ParseRequestBody[string, models.User](r)

		if len(err) > 1 {
			http.Error(w, err, http.StatusBadRequest)
			return
		}

		var user models.User
		db.Where("email =?", reqPayload.Email).First(&user) // Find user by email
		// if the user with that email does not exist throw an error
		if user.Email == "" {
			http.Error(w, "User not found", http.StatusNotFound)
			return
		}

		// compare their passwords
		helper.CompareHashAndPassword(
			[]byte(user.Password),
			[]byte(reqPayload.Password),
			w,
		)

		token, tokenErr := helper.CreateToken(user.Email, user.Type)
		if tokenErr != nil {
			http.Error(w, tokenErr.Error(), http.StatusInternalServerError)
			return
		}

		resPayload := Payload{
			User:  user,
			Token: token,
		}

		json.NewEncoder(w).Encode(resPayload)
	}
}

func CreateProject(db *gorm.DB) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {

		tokenString := r.Header.Get("Authorization")
		token, err := helper.VerifyToken(tokenString)

		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		isAdmin := helper.IsUserAdmin(token)

		if !isAdmin {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		project, reqPayloadErr := helper.ParseRequestBody[string, models.Project](r)

		if len(reqPayloadErr) > 1 {
			http.Error(w, reqPayloadErr, http.StatusBadRequest)
			return
		}

		result := db.Create(&project)

		if result.Error != nil {
			http.Error(w, result.Error.Error(), http.StatusInternalServerError)
			return
		}

		json.NewEncoder(w).Encode(project)
	}
}

func GetProjects(db *gorm.DB) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		tokenString := r.Header.Get("Authorization")
		_, err := helper.VerifyToken(tokenString)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		var projects []models.Project
		db.Find(&projects)

		json.NewEncoder(w).Encode(projects)
	}
}

func UpdateProjectStatus(db *gorm.DB) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		tokenString := r.Header.Get("Authorization")
		token, err := helper.VerifyToken(tokenString)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		isAdmin := helper.IsUserAdmin(token)
		if !isAdmin {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		params := mux.Vars(r)
		id := params["id"]
		status := params["status"]

		var project models.Project
		result := db.Where("id =?", id).First(&project).Update("status", status)
		if result.Error != nil {
			http.Error(w, result.Error.Error(), http.StatusBadRequest)
		}
		json.NewEncoder(w).Encode(project)
	}
}
