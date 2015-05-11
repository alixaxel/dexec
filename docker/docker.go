package docker

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	"github.com/docker-exec/dexec/util"
)

// DockerVersion shells out the command 'docker -v', returning the version
// information if the command is successful, and panicking if not.
var DockerVersion = func() string {
	out, err := exec.Command("docker", "-v").Output()
	if err != nil {
		panic(err.Error())
	} else {
		return string(out)
	}
}

// DockerInfo shells out the command 'docker -info', returning the information
// if the command is successful and panicking if not.
var DockerInfo = func() string {
	out, err := exec.Command("docker", "info").Output()
	if err != nil {
		panic(err.Error())
	} else {
		return string(out)
	}
}

// DockerPull shells out the command 'docker pull {{image}}' where image is
// the name of a Docker image to retrieve from the remote Docker repository.
var DockerPull = func(image string) {
	out := exec.Command("docker", "pull", image)
	out.Stdin = os.Stdin
	out.Stdout = os.Stderr
	out.Stderr = os.Stderr
	out.Run()
}

// Process is what it is.
type Process struct {
	ContainerID string
	Image       string
}

// ProcessHeader is what it is.
type ProcessHeader struct {
	Text           string
	CharacterWidth int
}

// DockerProcesses shells out the command 'docker ps'.
var DockerProcesses = func(args []string) []Process {
	dockerProcesses := []Process{}

	shellCommand := "docker"

	cmd := exec.Command(shellCommand, util.JoinStringSlices([]string{"ps"}, args)...)
	cmdReader, err := cmd.StdoutPipe()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error creating StdoutPipe for", err)
		os.Exit(1)
	}

	scanner := bufio.NewScanner(cmdReader)
	go func() {
		parsedHeaders := false

		headers := []*ProcessHeader{
			{"CONTAINER ID", 0},
			{"IMAGE", 0},
			{"COMMAND", 0},
			{"CREATED", 0},
			{"STATUS", 0},
			{"PORTS", 0},
			{"NAME", 0},
		}

		for scanner.Scan() {
			if !parsedHeaders {
				for _, header := range headers {
					r := regexp.MustCompile(fmt.Sprintf("%s\\s*", header.Text))
					containerHeader := r.FindString(scanner.Text())
					header.CharacterWidth = len(containerHeader)
				}
				parsedHeaders = true
			} else {
				var process Process

				cursor := 0
				for i := 0; i < len(headers); i++ {

					next := headers[i].CharacterWidth
					if i == len(headers)-1 {
						next = len(scanner.Text()) - cursor
					}

					headerKey := headers[i].Text
					headerValue := strings.TrimSpace(scanner.Text()[cursor : cursor+next])

					if headerKey == "CONTAINER ID" {
						process.ContainerID = headerValue
					} else if headerKey == "IMAGE" {
						process.Image = headerValue
					}

					cursor += next
				}

				dockerProcesses = append(dockerProcesses, []Process{process}...)
			}
		}
	}()

	err = cmd.Start()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error starting", err)
		os.Exit(1)
	}

	err = cmd.Wait()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error waiting for", err)
		os.Exit(1)
	}
	return dockerProcesses
}

// DockerImage shells out the command 'docker image'.
var DockerImage = func(args []string) {
	out := exec.Command("docker", util.JoinStringSlices([]string{"image"}, args)...)
	out.Stdin = os.Stdin
	out.Stdout = os.Stderr
	out.Stderr = os.Stderr
	out.Run()
}

// ExtractDockerVersion takes a Docker version string in the format:
// 'Docker version 1.0.0, build abcdef0', extracts the major, minor and patch
// versions and returns these as a tuple. If the string does not match, panic.
func ExtractDockerVersion(version string) (int, int, int) {
	dockerVersionPattern := regexp.MustCompile(`^Docker version (\d+)\.(\d+)\.(\d+), build [a-z0-9]{7}`)

	if dockerVersionPattern.MatchString(version) {
		match := dockerVersionPattern.FindStringSubmatch(version)
		major, _ := strconv.Atoi(match[1])
		minor, _ := strconv.Atoi(match[2])
		patch, _ := strconv.Atoi(match[3])
		return major, minor, patch
	}
	panic("Did not match Docker version string")
}

// IsDockerPresent tests for the presence of Docker by invoking DockerVersion
// to get the version of Docker if available, and then attempting to parse the
// version with ExtractDocker version. This function will return true only
// if neither of these functions panics.
func IsDockerPresent() (present bool) {
	present = true
	defer func() {
		if r := recover(); r != nil {
			present = false
		}
	}()
	ExtractDockerVersion(DockerVersion())
	return
}

// IsDockerRunning tests whether Docker is running by invoking DockerInfo
// which will only return information if Docker is up. This function will
// return true if DockerInfo does not panic.
func IsDockerRunning() (running bool) {
	running = true
	defer func() {
		if r := recover(); r != nil {
			running = false
		}
	}()
	DockerInfo()
	return
}

// RunAnonymousContainer shells out the command:
// 'docker run --rm {{extraDockerArgs}} -t {{image}} {{entrypointArgs}}'.
// This will run an anonymouse Docker container with the specified image, with
// any extra arguments to pass to Docker, for example directories to mount,
// as well as arguments to pass to the image's entrypoint.
func RunAnonymousContainer(image string, extraDockerArgs []string, entrypointArgs []string) {
	baseDockerArgs := []string{"run", "--rm"}
	imageDockerArgs := []string{"-t", image}
	out := exec.Command(
		"docker",
		util.JoinStringSlices(
			baseDockerArgs,
			extraDockerArgs,
			imageDockerArgs,
			entrypointArgs,
		)...,
	)
	out.Stdin = os.Stdin
	out.Stdout = os.Stdout
	out.Stderr = os.Stderr
	out.Run()
}
