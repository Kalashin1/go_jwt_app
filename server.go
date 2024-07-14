package main

import (
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"

	"go_jwt_app/controllers"
	"go_jwt_app/models"
)

func main() {
	r := mux.NewRouter()

	db, err := gorm.Open(mysql.New(mysql.Config{
		DSN: "root@tcp(localhost:3306)/test?charset=utf8mb4&parseTime=true",
	}))

	if err != nil {
		panic("failed to connect database")
	}

	db.AutoMigrate(&models.User{})
	db.AutoMigrate(&models.Project{})

	r.HandleFunc("/", controllers.Ping).Methods("GET")
	r.HandleFunc("/user", controllers.CreateUser(db)).Methods("POST")
	r.HandleFunc("/login", controllers.Login(db)).Methods("POST")
	r.HandleFunc("/project", controllers.CreateProject(db)).Methods("POST")
	r.HandleFunc("/projects", controllers.GetProjects(db)).Methods("GET")
	r.HandleFunc("/project/{id}/{status}", controllers.UpdateProjectStatus(db)).Methods("PATCH")

	http.Handle("/", r)
	fmt.Println("Server started at port 3000")
	http.ListenAndServe(":8080", nil)
}
