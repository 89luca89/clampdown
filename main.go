// SPDX-License-Identifier: GPL-3.0-only

package main

import (
	"log"
	"os"

	"github.com/89luca89/clampdown/pkg/cli"
)

func main() {
	err := cli.Run(os.Args)
	if err != nil {
		log.Fatalf("Error: %v\n", err)
	}
}
