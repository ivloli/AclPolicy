package main

import (
	"encoding/json"
	"flag"
	"fmt"
)

var Action string
var FilePath string
var WriteTo bool

func main() {
	flag.StringVar(&Action, "a", "get", "get/set acl policy")
	flag.StringVar(&FilePath, "f", "policy.json", "file path to the policy json")
	flag.BoolVar(&WriteTo, "w", false, "write to file")
	flag.Parse()

	dataPool := &DataPool{}
	dataPool.OpenDB()

	if Action == "get" {
		var org Organization
		dataPool.db.Model(&Organization{}).Select("AclPolicy").Take(&org)
		acl := org.AclPolicy
		jsonBytes, _ := json.MarshalIndent(acl, "", "  ")
		fmt.Println(string(jsonBytes))
		if WriteTo {
			ReWriteFile(GetFilePath(FilePath), string(jsonBytes))
		}
	} else if Action == "set" {
		acl, err := LoadConfig(GetFilePath(FilePath))
		if err != nil {
			fmt.Println(err)
			return
		}
		var org Organization
		org.AclPolicy = acl
		dataPool.db.Where("1=1").Select("AclPolicy").Updates(org)
	}
}
