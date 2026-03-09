package access

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/antonybholmes/go-sys"
	"github.com/antonybholmes/go-sys/log"
	"github.com/antonybholmes/go-web/auth"
	"github.com/antonybholmes/go-web/auth/token"
	"github.com/golang-jwt/jwt/v5"
)

// func matchesWildcardRule(rulePath, actualPath string) bool {
// 	if strings.HasSuffix(rulePath, "/*") {
// 		prefix := strings.TrimSuffix(rulePath, "/*")
// 		return strings.HasPrefix(actualPath, prefix)
// 	}
// 	return rulePath == actualPath
// }

// const (
// 	MATCH_TYPE_EXACT    = "exact"
// 	MATCH_TYPE_WILDCARD = "wildcard"
// )

type (
	JsonTokenRule struct {
		Type        string   `json:"type"`
		Permissions []string `json:"permissions"`
	}

	JsonMethodRule struct {
		Type   string          `json:"type"`
		Tokens []JsonTokenRule `json:"tokens"`
	}

	// JSON structure for rules
	JsonRule struct {
		Methods  []JsonMethodRule `json:"methods"`
		Path     string           `json:"path"`
		Audience jwt.ClaimStrings `json:"audience"`
	}

	JsonRules struct {
		Version string     `json:"version"`
		Updated string     `json:"updated"`
		Rules   []JsonRule `json:"rules"`
	}

	AccessRuleError struct {
		s string
	}

	Rule struct {
		Path        string
		Permissions *sys.Set[string]
	}

	RuleEngine struct {
		//rules map[string]map[string]map[string]map[string]*sys.StringSet
		rules         map[string]Rule
		wildcardRules map[string][]Rule
	}
)

func NewAccessRuleError(s string) *AccessRuleError {
	return &AccessRuleError{s: s}
}

func (e *AccessRuleError) Error() string {
	return fmt.Sprintf("access rule error: %s", e.s)
}

// A rule key is a combination of method, token type, audience and path for exact matches of
// rules. We match info from the jwt and url request to find relevant rules for access control.
// For wildcard rules, the path is not included in the key
func makeExactPathRuleKey(method, tokenType string, audience jwt.ClaimStrings, path string) string {
	path = strings.TrimSuffix(path, "/") // remove trailing slash if present

	return makeWildcardRuleKey(method, tokenType, audience) + "|" + path
}

// Rules are indexed with a simple key of method|tokenType|audience for quick lookup.
func makeWildcardRuleKey(method, tokenType string, audience jwt.ClaimStrings) string {
	// if audience is empty, use wildcard to match any audience
	if len(audience) == 0 {
		audience = jwt.ClaimStrings{"*"}
	}

	sort.Strings(audience) // ensure consistent ordering for key generation

	return strings.ToLower(method + "|" + tokenType + "|" + strings.Join(audience, ","))

}

func NewRuleEngine() *RuleEngine {
	return &RuleEngine{
		rules:         make(map[string]Rule),
		wildcardRules: make(map[string][]Rule),
	}
}

// LoadRules loads access control rules from a JSON file.
// This will panic if the file cannot be read or parsed since
// it is assumed that the rules file is correct and present at startup.
func (re *RuleEngine) LoadRules(filename string) {
	data := sys.Must(os.ReadFile(filename))

	var rules JsonRules
	sys.VoidMust(json.Unmarshal(data, &rules))
	var isExact bool

	for _, r := range rules.Rules {

		path := r.Path

		isExact = !strings.HasSuffix(path, "/*")

		// remove trailing slash if present
		path = strings.TrimSuffix(strings.TrimSuffix(path, "/*"), "/")

		// which method types does this rule apply to e.g. GET, POST etc
		for _, m := range r.Methods {

			// which types of tokens are accepted for this rule
			for _, t := range m.Tokens {

				if isExact {
					re.rules[makeExactPathRuleKey(m.Type, t.Type, r.Audience, path)] = Rule{
						Path:        path,
						Permissions: sys.NewStringSet().ListUpdate(t.Permissions),
					}
				} else {
					key := makeWildcardRuleKey(m.Type, t.Type, r.Audience)

					re.wildcardRules[key] = append(re.wildcardRules[key], Rule{
						Path:        path,
						Permissions: sys.NewStringSet().ListUpdate(t.Permissions),
					})
				}

				// if re.rules[matchType] == nil {
				// 	re.rules[matchType] = make(map[string]map[string]map[string]*sys.StringSet)
				// }

				// if re.rules[matchType][methodType] == nil {
				// 	re.rules[matchType][methodType] = make(map[string]map[string]*sys.StringSet)
				// }

				// if re.rules[matchType][methodType][tokenType] == nil {
				// 	re.rules[matchType][methodType][tokenType] = make(map[string]*sys.StringSet)
				// }

				// // path is last as this is the most expensive to check
				// // so we can quickly eliminate rules that don't match method or token
				// // before checking path
				// re.rules[matchType][methodType][tokenType][path] = sys.NewStringSet().ListUpdate(t.Permissions) //  = append(re.rules[rule.Method][rule.Token][rule.Path], rule)
			}
		}
	}

	// sort wildcard rules by path length descending so that longest match is found first
	for key := range re.wildcardRules {

		sort.Slice(re.wildcardRules[key], func(i, j int) bool {
			return len(re.wildcardRules[key][i].Path) > len(re.wildcardRules[key][j].Path)
		})

	}

	log.Info().Msgf("Loaded %d access rules from %s", len(rules.Rules), filename)
}

func (re *RuleEngine) getWildCardRoles(method string, tokenType string, audience jwt.ClaimStrings, path string) (*sys.Set[string], error) {
	log.Debug().Msgf("GetWildCardRoles: method=%s, tokenType=%s, path=%s", method, tokenType, path)

	key := makeWildcardRuleKey(method, tokenType, audience)

	// matchTypeRules, ok := re.rules[MATCH_TYPE_WILDCARD]

	// if !ok {
	// 	return nil, fmt.Errorf("no rules for match type %s for path %s", MATCH_TYPE_EXACT, path)
	// }

	// methodRules, ok := matchTypeRules[method]

	// if !ok {
	// 	return nil, fmt.Errorf("no rules for method %s for path %s", method, path)
	// }

	tokenRules, ok := re.wildcardRules[key]

	if !ok {
		return nil, fmt.Errorf("no rules for token type %s for method %s for path %s", tokenType, method, path)
	}

	// sort paths descending by length so that the longest match is found first
	// rulePaths := make([]string, 0, len(tokenRules))

	// for rulePath := range tokenRules {
	// 	rulePaths = append(rulePaths, rulePath)
	// }

	// sort.Slice(rulePaths, func(i, j int) bool {
	// 	return len(rulePaths[i]) > len(rulePaths[j])
	// })

	// find the first matching rule that is longest
	for _, wc := range tokenRules {

		// see if path starts with rulePath prefix
		if strings.HasPrefix(path, wc.Path) {
			return wc.Permissions, nil
		}

	}

	// No matching rules found
	return nil, fmt.Errorf("no rules found")
}

// Get the rules for a given method, path and token. This is the core function that checks for matching rules based on the request and token info.
// It first checks for exact path matches and if no rules are found, it returns an error.
func (re *RuleEngine) getPermissionsForRoute(method string,
	path string,
	token *token.AuthUserJwtClaims) (*sys.Set[string], error) {

	log.Debug().Msgf("GetExactRoles: method=%s, tokenType=%s, path=%s", method, token.Type, path)

	// matchTypeRules, ok := re.rules[MATCH_TYPE_EXACT]

	// if !ok {
	// 	return nil, fmt.Errorf("no rules for match type %s for path %s", MATCH_TYPE_EXACT, path)
	// }

	// methodRules, ok := matchTypeRules[method]

	// if !ok {
	// 	return nil, fmt.Errorf("no rules for method %s for path %s", method, path)
	// }

	// tokenRules, ok := methodRules[tokenType]

	// if !ok {
	// 	return nil, fmt.Errorf("no rules for token type %s for method %s for path %s", tokenType, method, path)
	// }

	key := makeExactPathRuleKey(method, token.Type, token.Audience, path)

	//log.Debug().Msgf("Looking for exact rule with key=%s", key)
	//log.Debug().Msgf("Available exact rules: %v", strings.Join(sys.SortedMapKeys(re.rules), ", "))

	// Exact match rules, ideally all routes should be exact matches
	rule, ok := re.rules[key]

	if !ok {
		return nil, NewAccessRuleError("no rules found")
	}

	return rule.Permissions, nil
}

func (re *RuleEngine) GetRoutePermissions(method string, path string, token *token.AuthUserJwtClaims) (*sys.Set[string], error) {

	rules, err := re.getPermissionsForRoute(method, path, token)

	if err == nil {
		return rules, nil
	}

	// try wildcard rules if no exact match rules found

	return re.getWildCardRoles(method, token.Type, token.Audience, path)

}

func (re *RuleEngine) IsAccessAllowed(method, path string, token *token.AuthUserJwtClaims) error {

	log.Debug().Msgf("IsAccessAllowed: method=%s, path=%s, tokenType=%s, permissions=%v", method, path, token.Type, token.Permissions)

	matchingPermissions, err := re.GetRoutePermissions(method, path, token)

	if err != nil {
		return err
	}

	// Admin has access to everything so don't need to check permissions specifically.
	if auth.HasAdminPermission(token.Permissions) {

		log.Debug().Msgf("access allowed for admin permissions %v", token.Permissions)
		return nil
	}

	// route must contain at least one of the user's roles
	userPermissions := matchingPermissions.Which(token.Permissions)

	// no matching permissions found for user, access denied
	if len(userPermissions) == 0 {
		return NewAccessRuleError("no matching roles")
	}

	// for _, rule := range matchingRules {
	// 	// Check if any of the user's roles match the rule's roles
	// 	if rule.Roles.Contains(roleSet) {
	// 		return nil
	// 	}
	// }

	log.Debug().Msgf("Access allowed for permissions %v", userPermissions)
	return nil
}
