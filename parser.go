package main

import (
    "fmt"
    "encoding/json"
    "bytes"
	peparser "github.com/saferwall/pe"
)

func prettyPrint(buff []byte) string {
	var prettyJSON bytes.Buffer
	error := json.Indent(&prettyJSON, buff, "", "\t")
	if error != nil {
		fmt.Println("JSON parse error: ", error)
		return string(buff)
	}

	return prettyJSON.String()
}

func main() {
    filename := "implant.exe"
    pe, err := peparser.New(filename, &peparser.Options{})
	if err != nil {
		fmt.Println("Error while opening file: %s, reason: %v", filename, err)
    }

    err = pe.Parse()
    if err != nil {
        fmt.Println("Error while parsing file: %s, reason: %v", filename, err)
    }

    fmt.Printf("Signature is: 0x%x\n", pe.NtHeader.Signature)
    fmt.Printf("Machine is: 0x%x, Meaning: %s\n", pe.NtHeader.FileHeader.Machine, pe.PrettyMachineType())
    for _, sec := range pe.Sections {
        fmt.Printf("Section Name : %s\n", sec.NameString())
        fmt.Printf("Section VirtualSize : %x\n", sec.Header.VirtualSize)
        fmt.Printf("Section Flags : %x, Meaning: %v\n\n",
            sec.Header.Characteristics, sec.PrettySectionFlags())
    }

    richHeader, _ := json.Marshal(pe.RichHeader)
    fmt.Print(prettyPrint(richHeader))
}