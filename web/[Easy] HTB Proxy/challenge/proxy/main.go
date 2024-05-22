package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"strings"
)

type HTTPRequest struct {
	RemoteAddr string
	Method     string
	URL        string
	Protocol   string
	Headers    map[string]string
	Body       string
}

type HTTPResponse struct {
	Protocol      string
	StatusCode    int
	StatusMessage string
	Headers       map[string]string
	Body          string
}

type HTTPStatusCodesStruct struct {
	Continue             int
	SwitchingProtocols   int
	OK                   int
	Created              int
	Accepted             int
	NonAuthoritativeInfo int
	NoContent            int
	ResetContent         int
	PartialContent       int
	MultipleChoices      int
	MovedPermanently     int
	Found                int
	BadRequest           int
	Unauthorized         int
	PaymentRequired      int
	Forbidden            int
	NotFound             int
	InternalServerError  int
	NotImplemented       int
	BadGateway           int
	ServiceUnavailable   int
}

var HTTPStatusCodes = HTTPStatusCodesStruct{
	Continue:             100,
	SwitchingProtocols:   101,
	OK:                   200,
	Created:              201,
	Accepted:             202,
	NonAuthoritativeInfo: 203,
	NoContent:            204,
	ResetContent:         205,
	PartialContent:       206,
	MultipleChoices:      300,
	MovedPermanently:     301,
	Found:                302,
	BadRequest:           400,
	Unauthorized:         401,
	PaymentRequired:      402,
	Forbidden:            403,
	NotFound:             404,
	InternalServerError:  500,
	NotImplemented:       501,
	BadGateway:           502,
	ServiceUnavailable:   503,
}

type HTTPMethodsStruct struct {
	GET     string
	POST    string
	PUT     string
	DELETE  string
	PATCH   string
	HEAD    string
	OPTIONS string
}

var HTTPMethods = HTTPMethodsStruct{
	GET:     "GET",
	POST:    "POST",
	PUT:     "PUT",
	DELETE:  "DELETE",
	PATCH:   "PATCH",
	HEAD:    "HEAD",
	OPTIONS: "OPTIONS",
}

type HTTPVersionsStruct struct {
	HTTP1_0 string
	HTTP1_1 string
	HTTP2   string
	HTTP3   string
}

var HTTPVersions = HTTPVersionsStruct{
	HTTP1_0: "HTTP/1.0",
	HTTP1_1: "HTTP/1.1",
	HTTP2:   "HTTP/2",
	HTTP3:   "HTTP/3",
}

type ContentTypesStruct struct {
	TextHTML          string
	ApplicationJSON   string
	ApplicationXML    string
	TextPlain         string
	ImagePNG          string
	ImageJPEG         string
	MultipartFormData string
}

var ContentTypes = ContentTypesStruct{
	TextHTML:          "text/html",
	ApplicationJSON:   "application/json",
	ApplicationXML:    "application/xml",
	TextPlain:         "text/plain",
	ImagePNG:          "image/png",
	ImageJPEG:         "image/jpeg",
	MultipartFormData: "multipart/form-data",
}

func logHeader(version string) {
	var header string = `
░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
░  ░░░░  ░░        ░░       ░░░░░░░░░       ░░░       ░░░░      ░░░  ░░░░  ░░  ░░░░  ░
▒  ▒▒▒▒  ▒▒▒▒▒  ▒▒▒▒▒  ▒▒▒▒  ▒▒▒▒▒▒▒▒  ▒▒▒▒  ▒▒  ▒▒▒▒  ▒▒  ▒▒▒▒  ▒▒▒  ▒▒  ▒▒▒▒  ▒▒  ▒▒
▓        ▓▓▓▓▓  ▓▓▓▓▓       ▓▓▓▓▓▓▓▓▓       ▓▓▓       ▓▓▓  ▓▓▓▓  ▓▓▓▓    ▓▓▓▓▓▓    ▓▓▓
█  ████  █████  █████  ████  ████████  ████████  ███  ███  ████  ███  ██  ██████  ████
█  ████  █████  █████       █████████  ████████  ████  ███      ███  ████  █████  ████
██████████████████████████████████████████████████████████████████████████████████████ v` + version + "\n"
	fmt.Println(header)
}

func readFile(filename string) (string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return "", err
	}
	defer file.Close()

	var sb strings.Builder
	_, err = io.Copy(&sb, file)
	if err != nil {
		return "", err
	}
	return sb.String(), nil
}

func prettyLog(logType int, content string) {
	var logger *log.Logger = log.New(os.Stdout, "", log.LstdFlags)
	switch logType {
	case 1:
		logger.Printf("[+] %s", content)
	case 2:
		logger.Printf("[-] %s", content)
	default:
		logger.Printf("[#] %s", content)
	}
}

func requestParser(requestBytes []byte, remoteAddr string) (*HTTPRequest, error) {
	var requestLines []string = strings.Split(string(requestBytes), "\r\n")
	var bodySplit []string = strings.Split(string(requestBytes), "\r\n\r\n")

	if len(requestLines) < 1 {
		return nil, fmt.Errorf("invalid request format")
	}

	var requestLine []string = strings.Fields(requestLines[0])
	if len(requestLine) != 3 {
		return nil, fmt.Errorf("invalid request line")
	}

	var request *HTTPRequest = &HTTPRequest{
		RemoteAddr: remoteAddr,
		Method:     requestLine[0],
		URL:        requestLine[1],
		Protocol:   requestLine[2],
		Headers:    make(map[string]string),
	}

	for _, line := range requestLines[1:] {
		if line == "" {
			break
		}

		headerParts := strings.SplitN(line, ": ", 2)
		if len(headerParts) != 2 {
			continue
		}

		request.Headers[headerParts[0]] = headerParts[1]
	}

	if request.Method == HTTPMethods.POST {
		contentLength, contentLengthExists := request.Headers["Content-Length"]
		if !contentLengthExists {
			return nil, fmt.Errorf("unknown content length for body")
		}

		contentLengthInt, err := strconv.Atoi(contentLength)
		if err != nil {
			return nil, fmt.Errorf("invalid content length")
		}

		if len(bodySplit) <= 1 {
			return nil, fmt.Errorf("invalid content length")
		}

		var bodyContent string = bodySplit[1]
		if len(bodyContent) != contentLengthInt {
			return nil, fmt.Errorf("invalid content length")
		}

		request.Body = bodyContent[0:contentLengthInt]
		return request, nil
	}

	if len(bodySplit) > 1 && bodySplit[1] != "" {
		return nil, fmt.Errorf("can't include body for non-POST requests")
	}

	return request, nil
}

func responseBuilder(response HTTPResponse) string {
	var statusLine string = fmt.Sprintf("%s %d %s\r\n", response.Protocol, response.StatusCode, response.StatusMessage)
	var headers string

	headers += "Server: HTB proxy\r\n"
	headers += fmt.Sprintf("Content-Length: %d\r\n", len(response.Body))
	for key, value := range response.Headers {
		headers += fmt.Sprintf("%s: %s\r\n", key, value)
	}

	return fmt.Sprintf("%s%s\r\n%s", statusLine, headers, response.Body)
}

func okResponse(statusMessage string) string {
	var response HTTPResponse = HTTPResponse{
		Protocol:      HTTPVersions.HTTP1_1,
		StatusCode:    HTTPStatusCodes.OK,
		StatusMessage: "OK",
		Headers: map[string]string{
			"Content-Type": ContentTypes.TextPlain,
		},
		Body: statusMessage,
	}

	return responseBuilder(response)
}

func htmlResponse(filename string) string {
	var body string
	content, err := readFile(filename)

	if err != nil {
		body = "Error reading file"
	} else {
		body = content
	}

	var response HTTPResponse = HTTPResponse{
		Protocol:      HTTPVersions.HTTP1_1,
		StatusCode:    HTTPStatusCodes.OK,
		StatusMessage: "OK",
		Headers: map[string]string{
			"Content-Type": ContentTypes.TextHTML,
		},
		Body: body,
	}

	return responseBuilder(response)
}

func movedPermResponse(redirectLocation string) string {
	var response HTTPResponse = HTTPResponse{
		Protocol:      HTTPVersions.HTTP1_1,
		StatusCode:    HTTPStatusCodes.MovedPermanently,
		StatusMessage: "Moved Permanently",
		Headers: map[string]string{
			"Location": redirectLocation,
		},
	}

	return responseBuilder(response)
}

func badReqResponse(statusMessage string) string {
	var response HTTPResponse = HTTPResponse{
		Protocol:      HTTPVersions.HTTP1_1,
		StatusCode:    HTTPStatusCodes.BadRequest,
		StatusMessage: "Bad Request",
		Headers: map[string]string{
			"Content-Type": ContentTypes.TextPlain,
		},
		Body: statusMessage,
	}

	return responseBuilder(response)
}

func notSupportedResponse(statusMessage string) string {
	var response HTTPResponse = HTTPResponse{
		Protocol:      HTTPVersions.HTTP1_1,
		StatusCode:    HTTPStatusCodes.NotImplemented,
		StatusMessage: "Not Implemented",
		Headers: map[string]string{
			"Content-Type": ContentTypes.TextPlain,
		},
		Body: statusMessage,
	}

	return responseBuilder(response)
}

func errorResponse(statusMessage string) string {
	var response HTTPResponse = HTTPResponse{
		Protocol:      HTTPVersions.HTTP1_1,
		StatusCode:    HTTPStatusCodes.InternalServerError,
		StatusMessage: "Internal Server Error",
		Headers: map[string]string{
			"Content-Type": ContentTypes.TextPlain,
		},
		Body: statusMessage,
	}

	return responseBuilder(response)
}

func blacklistCheck(input string) bool {
	var match bool = strings.Contains(input, string([]byte{108, 111, 99, 97, 108, 104, 111, 115, 116})) ||
		strings.Contains(input, string([]byte{48, 46, 48, 46, 48, 46, 48})) ||
		strings.Contains(input, string([]byte{49, 50, 55, 46})) ||
		strings.Contains(input, string([]byte{49, 55, 50, 46})) ||
		strings.Contains(input, string([]byte{49, 57, 50, 46})) ||
		strings.Contains(input, string([]byte{49, 48, 46}))

	return match
}

func isIPv4(input string) bool {
	if strings.Contains(input, string([]byte{48, 120})) {
		return false
	}
	var ipv4Pattern string = `^(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$`
	match, _ := regexp.MatchString(ipv4Pattern, input)
	return match && !blacklistCheck(input)
}

func isDomain(input string) bool {
	var domainPattern string = `^[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)*(\.[a-zA-Z]{2,})$`
	match, _ := regexp.MatchString(domainPattern, input)
	return match && !blacklistCheck(input)
}

func isDigitInRange(s string, min int, max int) (bool, error) {
	num, err := strconv.Atoi(s)
	if err != nil {
		return false, err
	}
	return num >= min && num <= max, nil
}

func checkIfLocalhost(address string) (bool, error) {
	IPs, err := net.LookupIP(address)
	if err != nil {
		return false, err
	}

	for _, ip := range IPs {
		if ip.IsLoopback() {
			return true, nil
		}
	}

	return false, nil
}

func checkMaliciousBody(body string) (bool, error) {
	patterns := []string{
		"[`;&|]",
		`\$\([^)]+\)`,
		`(?i)(union)(.*)(select)`,
		`<script.*?>.*?</script>`,
		`\r\n|\r|\n`,
		`<!DOCTYPE.*?\[.*?<!ENTITY.*?>.*?>`,
	}

	for _, pattern := range patterns {
		match, _ := regexp.MatchString(pattern, body)
		if match {
			return true, nil
		}
	}
	return false, nil
}

func GetServerInfo() string {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	addrs, err := net.InterfaceAddrs()
	if err != nil {
		addrs = []net.Addr{}
	}

	var ips []string
	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() {
			if ipNet.IP.To4() != nil {
				ips = append(ips, ipNet.IP.String())
			}
		}
	}

	ipList := strings.Join(ips, ", ")

	info := fmt.Sprintf("Hostname: %s, Operating System: %s, Architecture: %s, CPU Count: %d, Go Version: %s, IPs: %s",
		hostname, runtime.GOOS, runtime.GOARCH, runtime.NumCPU(), runtime.Version(), ipList)

	return info
}

func handleRequest(frontendConn net.Conn) {
	buffer := make([]byte, 1024)

	length, err := frontendConn.Read(buffer)
	var remoteAddr string = frontendConn.RemoteAddr().String()

	prettyLog(1, "Connection from: "+remoteAddr)

	if err != nil {
		prettyLog(2, "Error reading: "+err.Error())
		frontendConn.Close()
		return
	}

	var requestBytes = buffer[:length]
	request, err := requestParser(requestBytes, remoteAddr)

	if err != nil {
		var responseText string = badReqResponse(err.Error())
		frontendConn.Write([]byte(responseText))
		frontendConn.Close()
		return
	}

	if request.Protocol != HTTPVersions.HTTP1_1 {
		var responseText string = notSupportedResponse("Protocol version not supported")
		frontendConn.Write([]byte(responseText))
		frontendConn.Close()
		return
	}

	if request.URL == string([]byte{47}) {
		var responseText string = htmlResponse("/app/proxy/includes/index.html")
		frontendConn.Write([]byte(responseText))
		frontendConn.Close()
		return
	}

	if request.URL == string([]byte{47, 115, 101, 114, 118, 101, 114, 45, 115, 116, 97, 116, 117, 115}) {
		var serverInfo string = GetServerInfo()
		var responseText string = okResponse(serverInfo)
		frontendConn.Write([]byte(responseText))
		frontendConn.Close()
		return
	}

	if strings.Contains(strings.ToLower(request.URL), string([]byte{102, 108, 117, 115, 104, 105, 110, 116, 101, 114, 102, 97, 99, 101})) {
		var responseText string = badReqResponse("Not Allowed")
		frontendConn.Write([]byte(responseText))
		frontendConn.Close()
		return
	}

	host, hostExists := request.Headers["Host"]
	if !hostExists {
		var responseText string = badReqResponse("Host header not set")
		frontendConn.Write([]byte(responseText))
		frontendConn.Close()
		return
	}

	var hostArray []string = strings.Split(host, ":")
	if len(hostArray) != 2 || hostArray[1] == "" {
		var responseText string = badReqResponse("Invalid host")
		frontendConn.Write([]byte(responseText))
		frontendConn.Close()
		return
	}

	var hostPort string = hostArray[1]
	inRange, err := isDigitInRange(hostPort, 1, 65535)
	if err != nil || !inRange {
		var responseText string = badReqResponse("Invalid port")
		frontendConn.Write([]byte(responseText))
		frontendConn.Close()
		return
	}

	var hostAddress string = hostArray[0]
	var isIPv4Addr bool = isIPv4(hostAddress)
	var isDomainAddr bool = isDomain(hostAddress)

	if !isIPv4Addr && !isDomainAddr {
		var responseText string = badReqResponse("Invalid host")
		frontendConn.Write([]byte(responseText))
		frontendConn.Close()
		return
	}

	isLocal, err := checkIfLocalhost(hostAddress)
	if err != nil {
		var responseText string = errorResponse("Invalid host")
		frontendConn.Write([]byte(responseText))
		frontendConn.Close()
		return
	}

	if isLocal {
		var responseText string = movedPermResponse("/")
		frontendConn.Write([]byte(responseText))
		frontendConn.Close()
		return
	}

	isMalicious, err := checkMaliciousBody(request.Body)
	if err != nil || isMalicious {
		var responseText string = badReqResponse("Malicious request detected")
		prettyLog(1, "Malicious request detected")
		frontendConn.Write([]byte(responseText))
		frontendConn.Close()
		return
	}

	backendConn, err := net.Dial("tcp", host)
	if err != nil {
		var responseText string = errorResponse("Could not connect to backend server")
		frontendConn.Write([]byte(responseText))
		frontendConn.Close()
		return
	}

	_, err = backendConn.Write(requestBytes)
	if err != nil {
		var responseText string = errorResponse("Error sending request to backend")
		frontendConn.Write([]byte(responseText))
		frontendConn.Close()
		backendConn.Close()
		return
	}

	var backendResponse strings.Builder
	var scanner *bufio.Scanner = bufio.NewScanner(backendConn)

	for scanner.Scan() {
		var line string = scanner.Text()
		backendResponse.WriteString(line + "\n")
	}

	if err := scanner.Err(); err != nil {
		var responseText string = errorResponse("Error reading backend response")
		frontendConn.Write([]byte(responseText))
		frontendConn.Close()
		backendConn.Close()
		return
	}

	prettyLog(1, "Forwarding request to: "+host)
	var responseStr string = backendResponse.String()
	frontendConn.Write([]byte(responseStr))
	frontendConn.Close()
	backendConn.Close()
}

func main() {
	var serverPort string = "1337"
	var version string = "1.0.0"
	logHeader(version)

	ln, err := net.Listen("tcp", ":"+serverPort)
	if err != nil {
		prettyLog(2, "Error listening: "+err.Error())
		return
	}

	defer ln.Close()
	prettyLog(1, "HTB proxy listening on :"+serverPort)

	for {
		conn, err := ln.Accept()
		if err != nil {
			prettyLog(2, "Error accepting: "+err.Error())
			continue
		}

		go handleRequest(conn)
	}
}
