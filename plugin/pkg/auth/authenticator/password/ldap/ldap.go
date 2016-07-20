/*
Copyright 2015 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package ldap

import (
	"fmt"
	"strings"

	"github.com/golang/glog"
	"gopkg.in/ldap.v2"
	"k8s.io/kubernetes/pkg/auth/user"
)

type LdapAuthenticator struct {
	LdapURL    string
	LdapBaseDn string
}

const metaChars = "&|!=~*<>()"

func New(ldapURL string, ldapBaseDn string) (*LdapAuthenticator, error) {
	if ldapBaseDn == "" {
		return nil, fmt.Errorf("No base DN applied")
	}
	authenticator := &LdapAuthenticator{
		LdapURL:    ldapURL,
		LdapBaseDn: ldapBaseDn,
	}
	return authenticator, nil
}

func (a *LdapAuthenticator) AuthenticatePassword(username, password string) (user.Info, bool, error) {
	for _, c := range metaChars {
		if strings.ContainsRune(username, c) {
			return nil, false, fmt.Errorf("the username contains meta char: %q", c)
		}
	}
	l, err := ldap.Dial("tcp", a.LdapURL)
	if err != nil {
		return nil, false, err
	}
	defer l.Close()

	dn := fmt.Sprintf(a.LdapBaseDn, username)
	err = l.Bind(dn, password)
	if err != nil {
		return nil, false, err
	}

	searchRequest := ldap.NewSearchRequest(
		dn,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)",
		[]string{"ou", "uid"},
		nil,
	)

	result, err := l.Search(searchRequest)
	if err != nil {
		return nil, false, err
	}
	if len(result.Entries) != 1 {
		return nil, false, fmt.Errorf("Entry does not exist or too many entries returned")
	}
	uid := result.Entries[0].GetAttributeValue("uid")
	groups := result.Entries[0].GetAttributeValues("ou")
	if uid == "" {
		return nil, false, fmt.Errorf("No uid found")
	}

	obj := &user.DefaultInfo{
		Name: username,
		UID:  uid,
	}
	if len(groups) > 0 {
		obj.Groups = groups
	}

	return obj, true, nil
}
