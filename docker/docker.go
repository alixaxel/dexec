package docker

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"regexp"
	"strconv"
	"strings"
)

type httpMethod string

const (
	get    httpMethod = "GET"
	put    httpMethod = "PUT"
	post   httpMethod = "POST"
	delete httpMethod = "DELETE"
)

type dockerRequest struct {
	apiVersion string
	endpoint   string
	method     httpMethod
	payload    string
}

var executeDockerRemoteCommand = func(dr dockerRequest) (map[string]interface{}, error) {

	// TEMPORARY HARDCODED DEFAULT BOOT2DOCKER VALUES
	// TO BE REFACTORED AND GENERALISED TO INCLUDE UNIX SOCKETS AND NON-DEFAULT
	// BOOT2DOCKER VALUES

	apiVersion := "v1.18"

	url, _ := url.Parse(fmt.Sprintf("https://192.168.59.103:2376/%s%s", apiVersion, dr.endpoint))

	usr, err := user.Current()
	if err != nil {
		panic(err.Error())
	}

	cert, err := tls.LoadX509KeyPair(
		fmt.Sprintf("%s/.boot2docker/certs/boot2docker-vm/cert.pem", usr.HomeDir),
		fmt.Sprintf("%s/.boot2docker/certs/boot2docker-vm/key.pem", usr.HomeDir))

	if err != nil {
		panic(err.Error())
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			Certificates:       []tls.Certificate{cert},
			InsecureSkipVerify: true,
		},
		DisableCompression: true,
	}

	client := &http.Client{Transport: tr}
	request := http.Request{
		Method: string(dr.method),
		URL:    url,
	}

	log.Println(fmt.Sprintf("%s request to %s", string(dr.method), url.String()))

	resp, err := client.Do(&request)
	if err != nil {
		panic(err.Error())
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)

	log.Println(string(body))

	dec := json.NewDecoder(strings.NewReader(string(body)))

	var m map[string]interface{}

	err = dec.Decode(&m)
	if err != nil {
		panic(err.Error())
	}
	return m, err
}

// DockerVersion shells out the command 'docker -v', returning the version
// information if the command is successful, and panicking if not.
var DockerVersion = func() string {
	m, err := executeDockerRemoteCommand(dockerRequest{
		endpoint: "/version",
		method:   get,
	})

	dockerVersion := ""
	for k, v := range m {
		if k == "Version" {
			dockerVersion = v.(string)
		}
	}

	if err != nil {
		panic(err.Error())
	} else if dockerVersion == "" {
		panic("Docker Version was blank")
	}

	return dockerVersion
}

// DockerInfo shells out the command 'docker -info', returning the information
// if the command is successful and panicking if not.
var DockerInfo = func() map[string]interface{} {

	m, err := executeDockerRemoteCommand(dockerRequest{
		endpoint: "/info",
		method:   get,
	})

	if err != nil {
		panic(err.Error())
	}

	return m
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

// ExtractDockerVersion takes a Docker version string in the format:
// 'Docker version 1.0.0, build abcdef0', extracts the major, minor and patch
// versions and returns these as a tuple. If the string does not match, panic.
func ExtractDockerVersion(version string) (int, int, int) {
	dockerVersionPattern := regexp.MustCompile(`^(\d+)\.(\d+)\.(\d+)`)

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

// Volume is as Volume does.
type Volume struct {
	Local  string
	Remote string
}

// RunAnonymousContainer shells out the command:
// 'docker run --rm {{extraDockerArgs}} -t {{image}} {{entrypointArgs}}'.
// This will run an anonymouse Docker container with the specified image, with
// any extra arguments to pass to Docker, for example directories to mount,
// as well as arguments to pass to the image's entrypoint.
func RunAnonymousContainer(image string, volumes []Volume, entrypointArgs []string) {

	payload := map[string]interface{}{
		"Image": image,
	}

	enc, err := json.Marshal(payload)

	if err != nil {
		log.Println(err.Error())
	}

	log.Println(string(enc))

	defer func() {
		if r := recover(); r != nil {
			log.Println("err....", r)
		}
	}()

	_, err = executeDockerRemoteCommand(dockerRequest{
		endpoint: "/containers/create",
		method:   post,
		payload:  string(enc),
	})

	if err != nil {
		log.Println(err)
	}

	//log.Println(payload["bar"].(map[string]interface{})["key"])

	// baseDockerArgs := []string{"run", "--rm"}
	// imageDockerArgs := []string{"-t", image}
	// out := exec.Command(
	// 	"docker",
	// 	util.JoinStringSlices(
	// 		baseDockerArgs,
	// 		extraDockerArgs,
	// 		imageDockerArgs,
	// 		entrypointArgs,
	// 	)...,
	// )
	// out.Stdin = os.Stdin
	// out.Stdout = os.Stdout
	// out.Stderr = os.Stderr
	// out.Run()
}
