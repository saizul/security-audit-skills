package main

import (
	"fmt"
	"net/http"
	"os/exec"
)

func handler(w http.ResponseWriter, r *http.Request) {
	db.Query(fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", r.FormValue("name")))
	exec.Command("sh", "-c", "echo "+r.FormValue("x"))
	http.Get(r.FormValue("url"))
}
