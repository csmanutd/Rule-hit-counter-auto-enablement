package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/csmanutd/pceutils"
)

type ReportStatus struct {
	Enabled bool `json:"enabled"`
}

type FirewallSettings struct {
	RuleHitCountEnabledScopes [][]interface{} `json:"rule_hit_count_enabled_scopes"`
}

type Label struct {
	Href  string `json:"href"`
	Value string `json:"value"`
}

func checkAndEnableReport(pceInfo pceutils.PCEInfo, insecure bool) error {
	fmt.Println("Checking if the report is already enabled...")

	// GET API to check report status
	url := fmt.Sprintf("https://%s:%s/api/v2/orgs/%s/report_templates/rule_hit_count_report", pceInfo.FQDN, pceInfo.Port, pceInfo.OrgID)
	statusCode, body, err := pceutils.MakeAPICall(url, "GET", pceInfo.APIKey, pceInfo.APISecret, "", insecure)
	if err != nil || statusCode < 200 || statusCode >= 300 {
		return fmt.Errorf("failed to fetch report status, HTTP Code: %d, Error: %v", statusCode, err)
	}

	var reportStatus ReportStatus
	err = json.Unmarshal(body, &reportStatus)
	if err != nil {
		return fmt.Errorf("failed to parse report status: %v", err)
	}

	// If the report is already enabled, skip this step
	if reportStatus.Enabled {
		fmt.Println("Report is already enabled. Skipping this API call.")
		return nil
	}

	// PUT API to enable the report
	fmt.Println("Enabling report in PCE...")
	enableURL := fmt.Sprintf("https://%s:%s/api/v2/orgs/%s/report_templates/rule_hit_count_report", pceInfo.FQDN, pceInfo.Port, pceInfo.OrgID)
	payload := `{"enabled": true}`

	statusCode, response, err := pceutils.MakeAPICall(enableURL, "PUT", pceInfo.APIKey, pceInfo.APISecret, payload, insecure)
	if err != nil || statusCode < 200 || statusCode >= 300 {
		return fmt.Errorf("failed to enable report, HTTP Code: %d, Error: %v", statusCode, err)
	}

	fmt.Printf("HTTP Code: %d\nResponse: %s\n", statusCode, string(response))
	return nil
}

func checkLabelHref(pceInfo pceutils.PCEInfo, labelValue string, insecure bool) (string, error) {
	// Fetch all labels
	url := fmt.Sprintf("https://%s:%s/api/v2/orgs/%s/labels", pceInfo.FQDN, pceInfo.Port, pceInfo.OrgID)
	statusCode, body, err := pceutils.MakeAPICall(url, "GET", pceInfo.APIKey, pceInfo.APISecret, "", insecure)
	if err != nil || statusCode < 200 || statusCode >= 300 {
		return "", fmt.Errorf("failed to fetch labels, HTTP Code: %d, Error: %v", statusCode, err)
	}

	// Parse the response
	var labels []Label
	err = json.Unmarshal(body, &labels)
	if err != nil {
		return "", fmt.Errorf("failed to parse label response: %v", err)
	}

	// Find the label href that matches the label value
	for _, label := range labels {
		if strings.EqualFold(strings.TrimSpace(label.Value), labelValue) {
			return label.Href, nil
		}
	}

	return "", fmt.Errorf("label not found")
}

func main() {
	// Handle command-line flags
	pceName := flag.String("pce", "", "Name of the PCE to use")
	insecure := flag.Bool("insecure", false, "Ignore SSL certificate errors")
	flag.Parse()

	// Load the configuration
	config, err := pceutils.LoadOrCreatePCEConfig("pce.json")
	if err != nil {
		log.Fatalf("Error loading or creating config: %v", err)
	}

	// If pceName is not provided, use the default
	if *pceName == "" {
		*pceName = config.DefaultPCEName
	}

	// Get the PCE info
	pceInfo, ok := config.PCEs[*pceName]
	if !ok {
		reader := bufio.NewReader(os.Stdin)
		fmt.Printf("PCE '%s' not found. Do you want to add it? (y/n): ", *pceName)
		answer, _ := reader.ReadString('\n')
		answer = strings.TrimSpace(strings.ToLower(answer))

		if answer == "y" || answer == "yes" {
			pceInfo = pceutils.CreateNewPCEInfo()
			config.PCEs[*pceName] = pceInfo
			pceutils.SaveConfig("pce.json", config)
			fmt.Println("New PCE added and saved to configuration.")
		} else {
			for {
				fmt.Print("Please enter an existing PCE name: ")
				*pceName, _ = reader.ReadString('\n')
				*pceName = strings.TrimSpace(*pceName)
				pceInfo, ok = config.PCEs[*pceName]
				if ok {
					break
				}
				fmt.Printf("PCE '%s' not found. Please try again.\n", *pceName)
			}
		}
	}

	// Step 1: Check and enable report in PCE (First API)
	err = checkAndEnableReport(pceInfo, *insecure)
	if err != nil {
		log.Fatalf("Error enabling report: %v", err)
	}

	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter label to define the scope (or 'All' to enable for all scopes, 'disable' to disable):")
	labelInput, _ := reader.ReadString('\n')
	labelInput = strings.TrimSpace(labelInput)

	// If the user enters "disable", handle accordingly
	var payload string
	if strings.EqualFold(labelInput, "disable") {
		payload = `{"rule_hit_count_enabled_scopes":[]}`
		fmt.Println("Disabling rule hit count for all scopes...")
	} else if strings.EqualFold(labelInput, "all") {
		payload = `{"rule_hit_count_enabled_scopes":[[]]}`
		fmt.Println("Enabling rule hit count for all scopes...")
	} else {
		// Handle label input
		var scopes []map[string]map[string]string
		for {
			labelHref, err := checkLabelHref(pceInfo, labelInput, *insecure)
			if err != nil {
				fmt.Println(err)
				fmt.Print("Please enter a valid label:")
				labelInput, _ = reader.ReadString('\n')
				labelInput = strings.TrimSpace(labelInput)
				continue
			}

			scopes = append(scopes, map[string]map[string]string{
				"label": {
					"href": labelHref,
				},
			})

			fmt.Print("Do you want to add another label? (y/N): ")
			moreLabels, _ := reader.ReadString('\n')
			if strings.ToLower(strings.TrimSpace(moreLabels)) != "y" {
				break
			}

			fmt.Print("Enter another label: ")
			labelInput, _ = reader.ReadString('\n')
			labelInput = strings.TrimSpace(labelInput)
		}

		// Create payload with the specified labels
		payloadBytes, _ := json.Marshal(map[string][][]map[string]map[string]string{
			"rule_hit_count_enabled_scopes": {scopes},
		})
		payload = string(payloadBytes)
	}

	// Update the API calls to use pceInfo
	url := fmt.Sprintf("https://%s:%s/api/v2/orgs/%s/sec_policy/draft/firewall_settings", pceInfo.FQDN, pceInfo.Port, pceInfo.OrgID)

	// First, check the current settings to see if the action is necessary
	fmt.Println("Checking current firewall settings to see if the rule hit count is already enabled...")
	statusCode, currentSettingsBody, err := pceutils.MakeAPICall(url, "GET", pceInfo.APIKey, pceInfo.APISecret, "", *insecure)
	if err != nil || statusCode < 200 || statusCode >= 300 {
		log.Fatalf("Failed to fetch current firewall settings, HTTP Code: %d, Error: %v", statusCode, err)
	}

	// Parse current firewall settings
	var currentSettings FirewallSettings
	err = json.Unmarshal(currentSettingsBody, &currentSettings)
	if err != nil {
		log.Fatalf("Failed to parse current firewall settings: %v", err)
	}

	// Compare current rule_hit_count_enabled_scopes with the new payload to decide whether to skip the API call
	var newPayloadSettings FirewallSettings
	err = json.Unmarshal([]byte(payload), &newPayloadSettings)
	if err != nil {
		log.Fatalf("Failed to parse new payload settings: %v", err)
	}

	// Compare the current settings with the new payload
	if len(currentSettings.RuleHitCountEnabledScopes) == len(newPayloadSettings.RuleHitCountEnabledScopes) {
		equal := true
		for i := range currentSettings.RuleHitCountEnabledScopes {
			if len(currentSettings.RuleHitCountEnabledScopes[i]) != len(newPayloadSettings.RuleHitCountEnabledScopes[i]) {
				equal = false
				break
			}
		}

		if equal {
			fmt.Println("Rule hit count is already configured as desired. No changes necessary.")
			return
		}
	}

	// If not equal, proceed with making the API call to enable rule hit count
	fmt.Println("Enabling rule hit count based on the new scope configuration...")
	statusCode, response, err := pceutils.MakeAPICall(url, "PUT", pceInfo.APIKey, pceInfo.APISecret, payload, *insecure)
	if err != nil || statusCode < 200 || statusCode >= 300 {
		log.Fatalf("Failed to enable rule hit count, HTTP Code: %d, Error: %v", statusCode, err)
	}

	fmt.Printf("HTTP Code: %d\nResponse: %s\n", statusCode, string(response))

	// Optionally, you can also handle provisioning here if needed (depends on your existing logic)
	// For example, ask for confirmation before making a provisioning API call
	fmt.Print("Do you want to proceed with provisioning changes? (Y/n): ")
	confirmation, _ := reader.ReadString('\n')
	confirmation = strings.TrimSpace(confirmation)
	if strings.ToLower(confirmation) == "y" || confirmation == "" {
		fmt.Println("Provisioning changes...")
		provisionURL := fmt.Sprintf("https://%s:%s/api/v2/orgs/%s/sec_policy", pceInfo.FQDN, pceInfo.Port, pceInfo.OrgID)
		provisionPayload := fmt.Sprintf(`{
            "update_description":"Enable rule hit count",
            "change_subset":{"firewall_settings":[{"href":"/orgs/%s/sec_policy/draft/firewall_settings"}]}
        }`, pceInfo.OrgID)

		statusCode, provisionResponse, err := pceutils.MakeAPICall(provisionURL, "POST", pceInfo.APIKey, pceInfo.APISecret, provisionPayload, *insecure)
		if err != nil || statusCode < 200 || statusCode >= 300 {
			log.Fatalf("Failed to provision changes, HTTP Code: %d, Error: %v", statusCode, err)
		}

		fmt.Printf("HTTP Code: %d\nProvisioning Response: %s\n", statusCode, string(provisionResponse))
	} else {
		fmt.Println("Provisioning skipped.")
	}
}
