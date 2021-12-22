package main

/*
 Log4Shell search tool - Scans the filesystem for java packages and looks for vulnerable versions of Log4j in them.

 Copyright 2021 Spyderbat Inc.
*/

import (
	"archive/zip"
	"bytes"
	"flag"
	"fmt"
	gv "github.com/hashicorp/go-version"
	"io"
	"io/ioutil"
	"os"
	"path"
	"regexp"
	"strings"
)

// Build versioning
var Version = "none"
var Build = "none"

// Command Line args
var version = flag.Bool("version", false, "Display the version information")
var pathToSearch = flag.String("p", "/", "Path to scan")
var batchSize = flag.Int("b", 20000, "Batch size")

// File name filter
var file_filter = regexp.MustCompile("(?i).+\\.[w|e|j]ar$")

// Counter to use for throttling
var counter = uint64(0)

// Jar finder pattern
var zipPattern = regexp.MustCompile("log4j.+\\.jar")

// Flag so we can report if we found nothing
var found_output = false

type Log4JFound struct {
	File       string `json:"file,omitempty"`
	Manifest   string `json:"manifest"`
	ReleaseV   string `json:"release_version"`
	Vulnerable bool   `json:"vulnerable"`
}

func main() {
	flag.Parse()

	if *version {
		fmt.Println(logo30b30)
		fmt.Println("Log4J Tool")
		fmt.Printf("Version: %s\n", Version)
		fmt.Printf("Build: %s\n", Build)
		fmt.Printf("Copyright 2021 Spyderbat\n")
		os.Exit(0)
	}

	fileChannel := make(chan string, 1)

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
		if item.IsDir() {
			scan_for_files(path.Join(p, item.Name()), out)
		} else {
			if file_filter.MatchString(path.Join(p, item.Name())) {
				out <- path.Join(p, item.Name())
			}
		}
	}
	return ret
}

func scan_manifest_file(z io.ReadCloser, fn string) {
	found_output = true
	manifest, _ := ioutil.ReadAll(z)
	scan_release_version(string(manifest))
	o := Log4JFound{}
	o.Manifest = string(manifest)
	o.File = fn
	o.ReleaseV = scan_release_version(string(manifest))
	o.Vulnerable = is_version_vulnerable(o.ReleaseV)
	emit_output(o)
}

func read_zip(zr zip.Reader, zipname string, fn string) {
	bn := path.Base(zipname)
	if zipPattern.MatchString(bn) {
		for _, f := range zr.File {
			if strings.Compare(f.Name, "META-INF/MANIFEST.MF") == 0 {
				rc, err := f.Open()
				if err == nil {
					scan_manifest_file(rc, fn)
				}
				rc.Close()
			}
		}
	} else {
		for _, f := range zr.File {
			bn := path.Base(f.Name)
			if file_filter.MatchString(bn) {
				rc, _ := f.Open()
				subzip, _ := ioutil.ReadAll(rc)
				br := bytes.NewReader(subzip)
				szr, _ := zip.NewReader(br, int64(len(subzip)))
				read_zip(*szr, f.Name, fn)
				rc.Close()
			}
		}
	}
}

func scan_file(fn string) {
	zipdata, _ := ioutil.ReadFile(fn)
	br := bytes.NewReader(zipdata)
	szr, _ := zip.NewReader(br, int64(len(zipdata)))
	read_zip(*szr, fn, fn)
}

func emit_output(o Log4JFound) {
	var vuln string
	if o.Vulnerable {
		vuln = "vulnerable"
	} else {
		vuln = "not-vulnerable"
	}

	fmt.Printf("File: %s    contains version: %s  which is %s\n", o.File, o.ReleaseV, vuln)
}

func is_version_vulnerable(ver string) bool {
	/*
		vulnerable to CVE-2021-44228 and CVE-2021-45046:
		log4j 2.0 beta 9 -> 2.12.1
		log4j 2.13.0 -> 2.15.0
		vulnerable to CVE-2021-45105
		log4j 2.0 alpha 1 -> 2.16.0  (excluding 2.12.3)
	*/
	versionValue, err := gv.NewVersion(ver)
	if err != nil {
		fmt.Printf("Error processing version: %s %v\n", ver, err)
	}
	constraints, err := gv.NewConstraint(">= 2.0, <= 2.12.1")
	if err != nil {
		fmt.Printf("Error processing constraint: %s %v\n", ver, err)
	}
	patchedconstraint, err := gv.NewConstraint(">= 2.13.0, <= 2.15.0")
	if err != nil {
		fmt.Printf("Error processing constraint: %s %v\n", ver, err)
	}
	if constraints.Check(versionValue) {
		return true
	}
	if patchedconstraint.Check(versionValue) {
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
	old_ver_reg := regexp.MustCompile(".*Implementation\\-Version\\: (?P<version>\\S+)")
	m := match_map(ver_reg.FindString(mf), ver_reg)
	if len(m) == 0 {
		m = match_map(old_ver_reg.FindString(mf), old_ver_reg)
	}
	v := m["version"]
	return v
}

const logo30b30 = "[0m [0m [0m [0m [0m [0m [0m [0m [0m[38;2;59;149;208m▂[0m[38;2;59;149;208m▄[0m[38;2;59;149;208m▅[0m[38;2;59;149;208m▆[0m[7m[38;2;59;149;208m▂[0m[7m[38;2;59;149;208m▂[0m[7m[38;2;59;149;208m▃[0m[7m[38;2;59;149;208m▃[0m[7m[38;2;59;149;208m▂[0m[38;2;59;149;208m▇[0m[38;2;59;149;208m▆[0m[38;2;59;149;208m▅[0m[38;2;59;149;208m▄[0m[38;2;59;149;208m▂[0m [0m [0m [0m [0m [0m [0m [0m [0m\n[0m [0m [0m [0m [0m [0m[38;2;59;149;208m▂[0m[38;2;59;149;208m▅[0m[7m[38;2;59;149;208m▂[0m[7m[38;2;59;149;208m▄[0m[7m[38;2;59;149;208m▆[0m [0m [0m [0m [0m [0m [0m[38;2;59;149;208m▄[0m[38;2;59;149;208m[48;2;59;149;208m [0m[38;2;59;149;208m▌[0m [0m[7m[38;2;59;149;208m▆[0m[7m[38;2;59;149;208m▄[0m[7m[38;2;59;149;208m▂[0m[38;2;59;149;208m▅[0m[38;2;59;149;208m▂[0m [0m [0m [0m [0m [0m\n[0m [0m [0m [0m[38;2;59;149;208m▗[0m[38;2;59;149;208m[48;2;31;82;115m▆[0m[7m[38;2;59;149;208m▃[0m [0m [0m [0m [0m [0m [0m [0m [0m[38;2;59;149;208m▗[0m[7m[38;2;59;149;208m▘[0m[38;2;59;149;208m[48;2;59;149;208m [0m[38;2;59;149;208m[48;2;59;149;208m [0m[38;2;59;149;208m[48;2;59;149;208m [0m[38;2;59;149;208m▄[0m[38;2;59;149;208m▃[0m[38;2;59;149;208m▁[0m [0m [0m[7m[38;2;59;149;208m▃[0m[38;2;59;149;208m[48;2;32;82;115m▆[0m[38;2;59;149;208m▖[0m [0m [0m [0m\n[0m [0m [0m[7m[38;2;59;149;208m▘[0m[7m[38;2;59;149;208m▗[0m[38;2;54;138;193m▘[0m [0m [0m [0m [0m [0m [0m [0m[38;2;44;114;160m▃[0m[7m[38;2;59;149;208m▘[0m[38;2;59;149;208m[48;2;59;149;208m [0m[38;2;59;149;208m[48;2;59;149;208m [0m[38;2;59;149;208m[48;2;59;149;208m [0m[38;2;59;149;208m[48;2;59;149;208m [0m[38;2;59;149;208m[48;2;59;149;208m [0m[38;2;59;149;208m[48;2;59;149;208m [0m[38;2;59;149;208m[48;2;59;149;208m [0m[38;2;59;149;208m▘[0m [0m [0m [0m[38;2;54;139;194m▝[0m[7m[38;2;59;149;208m▖[0m[7m[38;2;59;149;208m▝[0m [0m [0m\n[0m [0m[7m[38;2;59;149;208m▘[0m[7m[38;2;59;149;208m▗[0m [0m [0m [0m [0m [0m [0m [0m[38;2;59;149;208m▃[0m[38;2;59;149;208m▆[0m[38;2;59;149;208m[48;2;59;149;208m [0m[38;2;59;149;208m[48;2;59;149;208m [0m[38;2;59;149;208m[48;2;59;149;208m [0m[38;2;59;149;208m[48;2;59;149;208m [0m[38;2;59;149;208m[48;2;59;149;208m [0m[38;2;59;149;208m[48;2;59;149;208m [0m[38;2;59;149;208m[48;2;59;149;208m [0m[38;2;59;149;208m[48;2;59;149;208m [0m[38;2;59;149;208m▊[0m [0m [0m [0m [0m [0m [0m[7m[38;2;59;149;208m▖[0m[7m[38;2;59;149;208m▝[0m [0m\n[0m[7m[38;2;59;149;208m▌[0m[38;2;59;149;208m[48;2;59;149;208m [0m [0m [0m [0m [0m [0m [0m[38;2;59;149;208m▄[0m[38;2;59;149;208m[48;2;59;149;208m [0m[38;2;59;149;208m[48;2;59;149;208m [0m[38;2;59;149;208m[48;2;59;149;208m [0m[38;2;59;149;208m[48;2;59;149;208m [0m[38;2;59;149;208m[48;2;59;149;208m [0m[38;2;59;149;208m[48;2;59;149;208m [0m[38;2;59;149;208m[48;2;59;149;208m [0m[38;2;59;149;208m[48;2;59;149;208m [0m[38;2;59;149;208m[48;2;59;149;208m [0m[38;2;59;149;208m[48;2;59;149;208m [0m[38;2;59;149;208m[48;2;59;149;208m [0m[38;2;59;149;208m▋[0m [0m [0m [0m [0m [0m [0m [0m[38;2;59;149;208m[48;2;59;149;208m [0m[38;2;59;149;208m▌[0m\n[0m[38;2;59;149;208m[48;2;59;149;208m [0m[38;2;59;149;208m▌[0m [0m [0m [0m [0m [0m [0m[7m[38;2;59;149;208m▅[0m[38;2;59;149;208m[48;2;59;149;208m [0m[38;2;59;149;208m[48;2;59;149;208m [0m[38;2;59;149;208m[48;2;59;149;208m [0m[38;2;59;149;208m[48;2;59;149;208m [0m[38;2;59;149;208m[48;2;59;149;208m [0m[38;2;59;149;208m[48;2;59;149;208m [0m[38;2;59;149;208m[48;2;59;149;208m [0m[38;2;59;149;208m[48;2;59;149;208m [0m[38;2;59;149;208m[48;2;59;149;208m [0m[38;2;59;149;208m[48;2;59;149;208m [0m[38;2;59;149;208m[48;2;59;149;208m [0m[38;2;59;149;208m[48;2;59;149;208m [0m[38;2;59;149;208m▖[0m [0m [0m [0m [0m [0m [0m[7m[38;2;59;149;208m▌[0m[38;2;59;149;208m[48;2;59;149;208m [0m\n[0m[38;2;59;149;208m[48;2;59;149;208m [0m[38;2;59;149;208m▍[0m [0m [0m [0m [0m [0m [0m [0m [0m[7m[38;2;59;149;208m▅[0m[38;2;59;149;208m[48;2;59;149;208m [0m[38;2;59;149;208m[48;2;59;149;208m [0m[38;2;59;149;208m[48;2;59;149;208m [0m[38;2;59;149;208m[48;2;59;149;208m [0m[38;2;59;149;208m[48;2;59;149;208m [0m[38;2;59;149;208m[48;2;59;149;208m [0m[38;2;59;149;208m[48;2;59;149;208m [0m[38;2;59;149;208m[48;2;59;149;208m [0m[38;2;59;149;208m[48;2;59;149;208m [0m[38;2;59;149;208m[48;2;59;149;208m [0m[7m[38;2;59;149;208m▅[0m [0m [0m [0m [0m [0m [0m[7m[38;2;59;149;208m▋[0m[38;2;59;149;208m[48;2;59;149;208m [0m\n[0m[38;2;59;149;208m[48;2;59;149;208m [0m[38;2;59;149;208m▌[0m [0m [0m [0m [0m [0m [0m [0m [0m [0m [0m[7m[38;2;59;149;208m▅[0m[38;2;59;149;208m[48;2;59;149;208m [0m[38;2;59;149;208m[48;2;59;149;208m [0m[38;2;59;149;208m[48;2;59;149;208m [0m[38;2;59;149;208m[48;2;59;149;208m [0m[38;2;59;149;208m[48;2;59;149;208m [0m[38;2;59;149;208m[48;2;59;149;208m [0m[38;2;59;149;208m[48;2;59;149;208m [0m[38;2;59;149;208m[48;2;59;149;208m [0m [0m [0m [0m [0m [0m [0m [0m[7m[38;2;59;149;208m▌[0m[38;2;59;149;208m[48;2;59;149;208m [0m\n[0m[7m[38;2;59;149;208m▌[0m[38;2;59;149;208m[48;2;59;149;208m [0m [0m [0m [0m [0m [0m [0m [0m [0m[38;2;59;149;208m▖[0m [0m [0m[7m[38;2;59;149;208m▍[0m[38;2;59;149;208m[48;2;59;149;208m [0m[38;2;59;149;208m[48;2;59;149;208m [0m[38;2;59;149;208m[48;2;59;149;208m [0m[38;2;59;149;208m[48;2;59;149;208m [0m[38;2;59;149;208m[48;2;59;149;208m [0m[38;2;59;149;208m[48;2;59;149;208m [0m[38;2;59;149;208m[48;2;59;149;208m [0m[38;2;59;149;208m[48;2;59;149;208m [0m[38;2;59;149;208m▃[0m [0m [0m [0m [0m [0m[38;2;59;149;208m[48;2;59;149;208m [0m[38;2;59;149;208m▌[0m\n[0m [0m[7m[38;2;59;149;208m▖[0m[7m[38;2;59;149;208m▝[0m [0m [0m [0m [0m [0m [0m[7m[38;2;56;144;201m▊[0m[38;2;59;149;208m[48;2;59;149;208m [0m[7m[38;2;59;149;208m▝[0m[38;2;59;149;208m▃[0m[38;2;59;149;208m[48;2;59;149;208m [0m[38;2;59;149;208m[48;2;59;149;208m [0m[38;2;59;149;208m[48;2;59;149;208m [0m[38;2;59;149;208m[48;2;59;149;208m [0m[38;2;59;149;208m[48;2;59;149;208m [0m[38;2;59;149;208m[48;2;59;149;208m [0m[38;2;59;149;208m[48;2;59;149;208m [0m[38;2;59;149;208m[48;2;59;149;208m [0m[38;2;59;149;208m[48;2;59;149;208m [0m[38;2;59;149;208m[48;2;59;149;208m [0m[38;2;59;149;208m[48;2;32;85;119m▅[0m[38;2;59;149;208m▖[0m [0m [0m[7m[38;2;59;149;208m▘[0m[7m[38;2;59;149;208m▗[0m [0m\n[0m [0m [0m[7m[38;2;59;149;208m▖[0m[7m[38;2;59;149;208m▝[0m[38;2;54;138;194m▖[0m [0m[38;2;58;148;207m▗[0m[38;2;59;149;208m▄[0m[38;2;59;149;208m[48;2;59;149;208m [0m[38;2;59;149;208m[48;2;59;149;208m [0m[38;2;59;149;208m[48;2;59;149;208m [0m[38;2;59;149;208m[48;2;59;149;208m [0m[38;2;59;149;208m[48;2;59;149;208m [0m[38;2;59;149;208m[48;2;59;149;208m [0m[38;2;59;149;208m[48;2;59;149;208m [0m[38;2;59;149;208m[48;2;59;149;208m [0m[38;2;59;149;208m[48;2;59;149;208m [0m[38;2;59;149;208m[48;2;59;149;208m [0m[38;2;59;149;208m[48;2;59;149;208m [0m[38;2;59;149;208m[48;2;59;149;208m [0m[38;2;59;149;208m[48;2;59;149;208m [0m[38;2;59;149;208m[48;2;59;149;208m [0m[38;2;59;149;208m[48;2;59;149;208m [0m[38;2;59;149;208m[48;2;59;149;208m [0m[38;2;59;149;208m[48;2;59;149;208m [0m[7m[38;2;59;149;208m▝[0m[7m[38;2;59;149;208m▘[0m[7m[38;2;59;149;208m▗[0m [0m [0m\n[0m [0m [0m [0m[38;2;59;149;208m▝[0m[38;2;32;81;114m[48;2;59;149;208m▂[0m[38;2;59;149;208m▅[0m [0m[7m[38;2;59;149;208m▅[0m[7m[38;2;59;149;208m▄[0m[7m[38;2;59;149;208m▄[0m[7m[38;2;59;149;208m▄[0m[7m[38;2;59;149;208m▃[0m[7m[38;2;59;149;208m▃[0m[7m[38;2;59;149;208m▃[0m[7m[38;2;59;149;208m▂[0m[38;2;59;149;208m[48;2;59;149;208m [0m[38;2;59;149;208m[48;2;59;149;208m [0m[38;2;59;149;208m[48;2;59;149;208m [0m[38;2;59;149;208m[48;2;59;149;208m [0m[38;2;59;149;208m[48;2;59;149;208m [0m[38;2;59;149;208m[48;2;59;149;208m [0m[38;2;59;149;208m[48;2;59;149;208m [0m[38;2;59;149;208m[48;2;59;149;208m [0m[38;2;59;149;208m[48;2;59;149;208m [0m[38;2;59;149;208m[48;2;59;149;208m [0m[38;2;59;149;208m[48;2;59;149;208m [0m[38;2;59;149;208m▘[0m [0m [0m [0m\n[0m [0m [0m [0m [0m [0m[7m[38;2;59;149;208m▆[0m[7m[38;2;59;149;208m▃[0m[38;2;59;149;208m▆[0m[38;2;59;149;208m▄[0m[38;2;59;149;208m▂[0m [0m [0m [0m [0m [0m [0m [0m [0m[7m[38;2;59;149;208m▆[0m[7m[38;2;59;149;208m▅[0m[7m[38;2;59;149;208m╾[0m[38;2;46;118;166m[48;2;59;149;208m╴[0m[38;2;59;149;208m[48;2;59;149;208m [0m[7m[38;2;59;149;208m▃[0m[7m[38;2;59;149;208m▆[0m [0m [0m [0m [0m [0m\n[0m [0m [0m [0m [0m [0m [0m [0m [0m[7m[38;2;59;149;208m▆[0m[7m[38;2;59;149;208m▄[0m[7m[38;2;59;149;208m▃[0m[7m[38;2;59;149;208m▂[0m[38;2;59;149;208m▆[0m[38;2;59;149;208m▆[0m[38;2;59;149;208m▅[0m[38;2;59;149;208m▅[0m[38;2;59;149;208m▆[0m[38;2;59;149;208m▆[0m[7m[38;2;59;149;208m▂[0m[7m[38;2;59;149;208m▃[0m[7m[38;2;59;149;208m▄[0m[7m[38;2;59;149;208m▆[0m [0m [0m [0m [0m [0m [0m [0m [0m\n"
