package access

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/antonybholmes/go-sys"
	"github.com/antonybholmes/go-web/auth"
	"github.com/rs/zerolog/log"
)

// func matchesWildcardRule(rulePath, actualPath string) bool {
// 	if strings.HasSuffix(rulePath, "/*") {
// 		prefix := strings.TrimSuffix(rulePath, "/*")
// 		return strings.HasPrefix(actualPath, prefix)
// 	}
// 	return rulePath == actualPath
// }

type JsonTokenRule struct {
	Type  string   `json:"type"`
	Roles []string `json:"roles"`
}

// JSON structure for rules
type JsonRule struct {
	Method string   `json:"method"`
	Path   string   `json:"path"`
	Token  string   `json:"token"`
	Roles  []string `json:"roles"`
}

type TokenRule struct {
	Type  string         `json:"type"`
	Roles *sys.StringSet `json:"roles"`
}

// Rule represents an access control rule
type Rule struct {
	Method string         `json:"method"`
	Path   string         `json:"path"`
	Token  string         `json:"token"`
	Roles  *sys.StringSet `json:"roles"`
}

type RuleEngine struct {
	rules map[string]map[string]map[string]*sys.StringSet
	//wilcardRules map[string]map[string][]Rule
}

func NewRuleEngine() *RuleEngine {
	return &RuleEngine{rules: make(map[string]map[string]map[string]*sys.StringSet)} //wilcardRules: make(map[string]map[string][]Rule)

}

// LoadRules loads access control rules from a JSON file.
// This will panic if the file cannot be read or parsed since
// it is assumed that the rules file is correct and present at startup.
func (re *RuleEngine) LoadRules(filename string) {
	data := sys.Must(os.ReadFile(filename))

	var rules []JsonRule
	sys.BaseMust(json.Unmarshal(data, &rules))

	for _, r := range rules {

		path := r.Path
		if strings.HasSuffix(path, "/*") {
			prefix := strings.TrimSuffix(path, "/*")

			// Adjust the rule path to be the prefix without the wildcard
			path = prefix
		}

		// rule := Rule{
		// 	Method: strings.ToUpper(r.Method),
		// 	Path:   path,
		// 	Token:  r.Token,
		// 	Roles:  sys.NewStringSet().ListUpdate(r.Roles),
		// }

		if re.rules[r.Method] == nil {
			re.rules[r.Method] = make(map[string]map[string]*sys.StringSet)
		}

		if re.rules[r.Method][r.Token] == nil {
			re.rules[r.Method][r.Token] = make(map[string]*sys.StringSet)
		}

		// path is last as this is the most expensive to check
		// so we can quickly eliminate rules that don't match method or token
		// before checking path
		re.rules[r.Method][r.Token][path] = sys.NewStringSet().ListUpdate(r.Roles) //  = append(re.rules[rule.Method][rule.Token][rule.Path], rule)

	}

	log.Info().Msgf("Loaded %d access rules from %s", len(rules), filename)

}

func (re *RuleEngine) GetMatchingRoles(method string, tokenType string, path string) (*sys.StringSet, error) {
	method = strings.ToUpper(method)

	methodRules, ok := re.rules[method]

	if !ok {
		return nil, fmt.Errorf("no rules for method %s", method)
	}

	tokenRules, ok := methodRules[tokenType]

	if !ok {
		return nil, fmt.Errorf("no rules for token type %s", tokenType)
	}

	// Exact match rules, ideally all routes should be exact matches
	rules, ok := tokenRules[path]

	if ok {
		return rules, nil
	}

	// Wildcard match rules,
	// check each rulePath to see if path starts with rulePath prefix
	// which is more expensive so do it last
	for rulePath, rules := range tokenRules {
		// see if path starts with rulePath prefix
		if strings.HasPrefix(path, rulePath) {
			return rules, nil
		}
	}

	// No matching rules found
	return nil, fmt.Errorf("no matching rules found")
}

func (re *RuleEngine) IsAccessAllowed(method, path string, tokenType string, roles []string) error {

	matchingRoles, err := re.GetMatchingRoles(method, tokenType, path)

	if err != nil {
		return err
	}

	// route must contain at least one of the user's roles

	roleSet := sys.NewStringSet().ListUpdate(roles)

	if auth.HasAdminRole(roleSet) {
		// Admin has access to everything
		log.Debug().Msgf("Access allowed for admin roles %v", roles)
		return nil
	}

	userRoles := matchingRoles.WhichList(roles)

	if len(userRoles) > 0 {
		log.Debug().Msgf("Access allowed for roles %v", userRoles)
		return nil
	}

	// for _, rule := range matchingRules {
	// 	// Check if any of the user's roles match the rule's roles
	// 	if rule.Roles.Contains(roleSet) {
	// 		return nil
	// 	}
	// }

	// No rules matched the user's roles, deny access
	return fmt.Errorf("no matching roles")
}
