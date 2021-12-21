package main

import (
	"archive/zip"
	"bytes"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/spyderbat/libbat"

	gv "github.com/mcuadros/go-version"
	"github.com/pkg/profile"
)

// Build versioning
var Version = "none"
var Build = "none"

// Command Line args
var version = flag.Bool("version", false, "Display the version information")
var cpuprofile = flag.String("c", "", "Save a CPU profile to the specified file")
var memprofile = flag.String("h", "", "Save a Heap profile to the specified file")
var pathToSearch = flag.String("p", "/", "Path to scan")
var batchSize = flag.Int("b", 20000, "Batch size")
var emitJson = flag.Bool("j", false, "Use JSON output")

// File name filter
var file_filter = regexp.MustCompile("(?i).+\\.[w|e|j]ar$")

// Counter to use for throttling
var counter = uint64(0)

// Jar finder pattern
var zipPattern = regexp.MustCompile("log4j.+\\.jar")
var found_output = false

type Log4JFound struct {
	File       string `json:"file,omitempty"`
	Manifest   string `json:"manifest"`
	ReleaseV   string `json:"release_version"`
	Vulnerable bool   `json:"vulnerable"`
}

func main() {
	libbat.SetProcessName("Log4J")
	flag.Parse()

	if *version {
		fmt.Println(libbat.GetLogo30b30())
		fmt.Println("Log4J bat")
		fmt.Printf("Version: %s\n", Version)
		fmt.Printf("Build: %s\n", Build)
		fmt.Printf("Copyright 2021 Spyderbat\n")
		os.Exit(0)
	}

	// Do profiling
	if strings.Compare(*cpuprofile, "") != 0 {
		defer profile.Start(profile.CPUProfile).Stop()
	}
	if strings.Compare(*memprofile, "") != 0 {
		defer profile.Start(profile.MemProfile).Stop()
	}

	fileChannel := make(chan string, 5)

	// Scan for the file
	go scan_for_log4j(fileChannel)
	for {
		select {
		case f := <-fileChannel:
			if f == "" {
				if !found_output {
					fmt.Println("Did not find any Log4j instances.")
				}
				os.Exit(0)
			}
			scan_file(f)
		}
	}
}

func scan_for_log4j(out chan string) {
	scan_for_files(*pathToSearch, out)
	out <- ""
}

func scan_for_files(p string, out chan string) []string {
	ret := make([]string, 0)
	items, _ := ioutil.ReadDir(p)
	for _, item := range items {

		// Keep the load under control
		counter += 1
		if counter%uint64(*batchSize) == 0 {
			time.Sleep(1500 * time.Millisecond)
		}

		if item.IsDir() {
			scan_for_files(path.Join(p, item.Name()), out)
			//for _, subitem := range subitems {
			//ret = append(ret, subitem)
			//}
		} else {
			if file_filter.MatchString(path.Join(p, item.Name())) {
				//ret = append(ret, path.Join(p, item.Name()))
				out <- path.Join(p, item.Name())
			}
		}
	}
	return ret
}

func scan_file(fn string) {
	// Check to see if we have a simple log4j jar file.
	baseName := path.Base(fn)
	if zipPattern.MatchString(baseName) {
		zr, _ := zip.OpenReader(fn)
		defer zr.Close()
		for _, f := range zr.File {
			if strings.Compare(f.Name, "META-INF/MANIFEST.MF") == 0 {
				rc, err := f.Open()
				if err == nil {
					found_output = true
					manifest, _ := ioutil.ReadAll(rc)
					scan_release_version(string(manifest))
					o := Log4JFound{}
					o.Manifest = string(manifest)
					o.File = fn
					o.ReleaseV = scan_release_version(string(manifest))
					o.Vulnerable = is_version_vulnerable(o.ReleaseV)
					if *emitJson {
						libbat.OutputData(o)
					} else {
						var vuln string
						if o.Vulnerable {
							vuln = "vulnerable"
						} else {
							vuln = "not-vulnerable"
						}

						fmt.Printf("File: %s    contains version: %s  which is %s\n", o.File, o.ReleaseV, vuln)
					}
				}

				rc.Close()
			}
		}
	} else {
		zr, _ := zip.OpenReader(fn)
		defer zr.Close()
		for _, f := range zr.File {
			if file_filter.MatchString(f.Name) {
				bn := path.Base(f.Name)
				if zipPattern.MatchString(bn) {
					// Crack out the zipped zip
					rc, _ := f.Open()
					subzip, _ := ioutil.ReadAll(rc)
					br := bytes.NewReader(subzip)
					szr, _ := zip.NewReader(br, int64(len(subzip)))
					for _, sf := range szr.File {
						if strings.Compare(sf.Name, "META-INF/MANIFEST.MF") == 0 {
							src, err := sf.Open()
							if err == nil {
								found_output = true
								manifest, _ := ioutil.ReadAll(src)
								o := Log4JFound{}
								o.Manifest = string(manifest)
								o.File = fn
								o.ReleaseV = scan_release_version(string(manifest))
								o.Vulnerable = is_version_vulnerable(o.ReleaseV)
								if *emitJson {
									libbat.OutputData(o)
								} else {
									var vuln string
									if o.Vulnerable {
										vuln = "vulnerable"
									} else {
										vuln = "not-vulnerable"
									}

									fmt.Printf("File: %s    contains version: %s  which is %s\n", o.File, o.ReleaseV, vuln)
								}
							}

							src.Close()
						}
					}
					rc.Close()
				}
			}
		}
	}
}

func is_version_vulnerable(ver string) bool {
	/*
		vulnerable to CVE-2021-44228 and CVE-2021-45046:
		log4j 2.0 beta 9 -> 2.12.1
		log4j 2.13.0 -> 2.15.0
		vulnerable to CVE-2021-45105
		log4j 2.0 alpha 1 -> 2.16.0  (excluding 2.12.3)
	*/
	if gv.Compare(ver, "2.12.1", "<=") && gv.Compare(ver, "2.0", ">=") {
		return true
	}
	if gv.Compare(ver, "2.13.0", ">=") && gv.Compare(ver, "2.15.0", "<=") {
		return true
	}
	return false
}

func match_map(input string, expr *regexp.Regexp) map[string]string {
	match := expr.FindStringSubmatch(input)
	result := make(map[string]string)
	if len(input) == 0 {
		return result
	}
	for i, name := range expr.SubexpNames() {
		if i != 0 && name != "" {
			result[name] = match[i]
		}
	}
	return result
}

func scan_release_version(mf string) string {
	ver_reg := regexp.MustCompile(".+ReleaseVersion\\: (?P<version>\\S+).+")
	old_ver_reg := regexp.MustCompile(".+Implementation\\-Version\\: (?P<version>\\\\S+).+")
	m := match_map(ver_reg.FindString(mf), ver_reg)
	if len(m) == 0 {
		m = match_map(old_ver_reg.FindString(mf), old_ver_reg)
	}
	v := m["version"]
	return v
}
