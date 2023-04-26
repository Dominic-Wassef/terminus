package main

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
)

func (app *application) readJSON(w http.ResponseWriter, r *http.Request, data interface{}) error {
	// sanity checks
	maxBytes := 1048576
	r.Body = http.MaxBytesReader(w, r.Body, int64(maxBytes))

	// decoder
	dec := json.NewDecoder(r.Body)
	err := dec.Decode(data)
	if err != nil {
		app.errorLog.Println(err)
		return err
	}

	// decode again
	err = dec.Decode(&struct{}{})
	if err != io.EOF {
		return errors.New("Body must only have a single JSON value!")
	}
	return nil
}

func (app *application) badRequest(w http.ResponseWriter, r *http.Request, err error) error {
	var payload struct {
		Error   bool   `json:"error"`
		Message string `json:"message"`
	}

	payload.Error = true
	payload.Message = err.Error()

	out, err := json.MarshalIndent(payload, "", "\t")
	if err != nil {
		return err
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(out)
	return nil
}
