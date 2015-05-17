package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"github.com/docker-exec/dexec/cli"
	"github.com/docker-exec/dexec/docker"
	"github.com/docker-exec/dexec/util"
)

// DexecImage consists of the file extension, Docker image name and Docker
// image version to use for a given Docker Exec image.
type DexecImage struct {
	extension string
	image     string
	version   string
}

// LookupImageByOverride takes an image that has been specified by the user
// to use instead of the one in the extension map. This function returns a
// DexecImage struct containing the image name & version, as well as the
// file extension that was passed in.
func LookupImageByOverride(image string, extension string) DexecImage {
	patternImage := regexp.MustCompile(`(.*):(.*)`)
	imageMatch := patternImage.FindStringSubmatch(image)
	if len(imageMatch) > 0 {
		return DexecImage{
			extension,
			imageMatch[1],
			imageMatch[2],
		}
	}
	return DexecImage{
		extension,
		image,
		"latest",
	}
}

// LookupImageByExtension is a closure storing a dictionary mapping source
// extensions to the names and versions of Docker Exec images.
var LookupImageByExtension = func() func(string) DexecImage {
	innerMap := map[string]DexecImage{
		"c":      {"c", "dexec/lang-c", "1.0.2"},
		"clj":    {"clj", "dexec/lang-clojure", "1.0.1"},
		"coffee": {"coffee", "dexec/lang-coffee", "1.0.2"},
		"cpp":    {"cpp", "dexec/lang-cpp", "1.0.2"},
		"cs":     {"cs", "dexec/lang-csharp", "1.0.2"},
		"d":      {"d", "dexec/lang-d", "1.0.1"},
		"erl":    {"erl", "dexec/lang-erlang", "1.0.1"},
		"fs":     {"fs", "dexec/lang-fsharp", "1.0.2"},
		"go":     {"go", "dexec/lang-go", "1.0.1"},
		"groovy": {"groovy", "dexec/lang-groovy", "1.0.1"},
		"hs":     {"hs", "dexec/lang-haskell", "1.0.1"},
		"java":   {"java", "dexec/lang-java", "1.0.2"},
		"lisp":   {"lisp", "dexec/lang-lisp", "1.0.1"},
		"lua":    {"lua", "dexec/lang-lua", "1.0.1"},
		"js":     {"js", "dexec/lang-node", "1.0.2"},
		"nim":    {"nim", "dexec/lang-nim", "1.0.1"},
		"m":      {"m", "dexec/lang-objc", "1.0.1"},
		"ml":     {"ml", "dexec/lang-ocaml", "1.0.1"},
		"p6":     {"p6", "dexec/lang-perl6", "1.0.1"},
		"pl":     {"pl", "dexec/lang-perl", "1.0.2"},
		"php":    {"php", "dexec/lang-php", "1.0.1"},
		"py":     {"py", "dexec/lang-python", "1.0.2"},
		"r":      {"r", "dexec/lang-r", "1.0.1"},
		"rkt":    {"rkt", "dexec/lang-racket", "1.0.1"},
		"rb":     {"rb", "dexec/lang-ruby", "1.0.1"},
		"rs":     {"rs", "dexec/lang-rust", "1.0.1"},
		"scala":  {"scala", "dexec/lang-scala", "1.0.1"},
		"sh":     {"sh", "dexec/lang-bash", "1.0.1"},
	}
	return func(key string) DexecImage {
		return innerMap[key]
	}
}()

const dexecPath = "/tmp/dexec/build"
const dexecImageTemplate = "%s:%s"
const dexecVolumeTemplate = "%s/%s:%s/%s"
const dexecSanitisedWindowsPathPattern = "/%s%s"

// ExtractBasenameAndPermission takes an include string and splits it into
// its file or folder name and the permission string if present or the empty
// string if not.
func ExtractBasenameAndPermission(path string) (string, string) {
	pathPattern := regexp.MustCompile("([\\w.:-]+)(:(rw|ro))")
	match := pathPattern.FindStringSubmatch(path)

	basename := path
	var permission string

	if len(match) == 4 {
		basename = match[1]
		permission = match[2]
	}
	return basename, permission
}

func buildVolumes(path string, targets []string) []docker.Volume {
	var volumes []docker.Volume

	for _, source := range targets {
		basename, _ := ExtractBasenameAndPermission(source)

		volumes = append(
			volumes, docker.Volume{
				Local:  fmt.Sprintf("%s/%s", path, basename),
				Remote: fmt.Sprintf("%s/%s", dexecPath, source),
			})
	}
	return volumes
}

// SanitisePath takes an absolute path as provided by filepath.Abs() and
// makes it ready to be passed to Docker based on the current OS. So far
// the only OS format that requires transforming is Windows which is provided
// in the form 'C:\some\path' but Docker requires '/c/some/path'.
func SanitisePath(path string, platform string) string {
	sanitised := path
	if platform == "windows" {
		windowsPathPattern := regexp.MustCompile("^([A-Za-z]):(.*)")
		match := windowsPathPattern.FindStringSubmatch(path)

		driveLetter := strings.ToLower(match[1])
		pathRemainder := strings.Replace(match[2], "\\", "/", -1)

		sanitised = fmt.Sprintf(dexecSanitisedWindowsPathPattern, driveLetter, pathRemainder)
	}
	return sanitised
}

// RetrievePath takes an array whose first element may contain an overridden
// path and converts either this, or the default of "." to an absolute path
// using Go's file utilities. This is then passed to SanitisedPath with the
// current OS to get it into a Docker ready format.
func RetrievePath(targetDirs []string) string {
	path := "."
	if len(targetDirs) > 0 {
		path = targetDirs[0]
	}
	absPath, _ := filepath.Abs(path)
	return SanitisePath(absPath, runtime.GOOS)
}

// RunDexecContainer runs an anonymous Docker container with a Docker Exec
// image, mounting the specified sources and includes and passing the
// list of sources and arguments to the entrypoint.
func RunDexecContainer(dexecImage DexecImage, options map[cli.OptionType][]string) {
	volumes := buildVolumes(
		RetrievePath(options[cli.TargetDir]),
		append(options[cli.Source], options[cli.Include]...))

	var sourceBasenames []string
	for _, source := range options[cli.Source] {
		basename, _ := ExtractBasenameAndPermission(source)
		sourceBasenames = append(sourceBasenames, []string{basename}...)
	}

	entrypointArgs := util.JoinStringSlices(
		sourceBasenames,
		util.AddPrefix(options[cli.BuildArg], "-b"),
		util.AddPrefix(options[cli.Arg], "-a"),
	)

	if len(options[cli.UpdateFlag]) > 0 {
		docker.DockerPull(dexecImage.image, dexecImage.version)
	}

	docker.RunAnonymousContainer(
		dexecImage.image,
		dexecImage.version,
		volumes,
		entrypointArgs,
	)
}

func validate(cliParser cli.CLI) bool {
	if !docker.IsDockerPresent() {
		log.Fatal("Docker not found")
	} else if !docker.IsDockerRunning() {
		log.Fatal("Docker not running")
	}

	valid := false
	if len(cliParser.Options[cli.VersionFlag]) != 0 {
		cli.DisplayVersion(cliParser.Filename)
	} else if len(cliParser.Options[cli.Source]) == 0 ||
		len(cliParser.Options[cli.HelpFlag]) != 0 ||
		len(cliParser.Options[cli.TargetDir]) > 1 ||
		len(cliParser.Options[cli.SpecifyImage]) > 1 {
		cli.DisplayHelp(cliParser.Filename)
	} else {
		valid = true
	}
	return valid
}

func main() {
	cliParser := cli.ParseOsArgs(os.Args)

	if validate(cliParser) {
		extension := util.ExtractFileExtension(cliParser.Options[cli.Source][0])
		image := LookupImageByExtension(extension)
		if len(cliParser.Options[cli.SpecifyImage]) == 1 {
			image = LookupImageByOverride(cliParser.Options[cli.SpecifyImage][0], extension)
		}
		RunDexecContainer(
			image,
			cliParser.Options,
		)
	}
}
