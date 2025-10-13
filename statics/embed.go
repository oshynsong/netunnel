package statics

import (
	"embed"
	"io/fs"
)

//go:embed *.ico
//go:embed *.html
var statics embed.FS

func List() ([]string, error) {
	return fs.Glob(statics, "*")
}

func Get(filename string) ([]byte, error) {
	return statics.ReadFile(filename)
}
