package main

import (
	"fmt"
	"os"
	"testing"

	"github.com/tuotoo/qrcode"
)

func TestQrcode(t *testing.T) {
	fi, err := os.Open("../qrcode.png")
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	defer fi.Close()
	qrmatrix, err := qrcode.Decode(fi)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	t.Log(qrmatrix.Content)
}
