package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
)

type PCEConfig struct {
	APIKey    string `json:"api_key"`
	APISecret string `json:"api_secret"`
	FQDN      string `json:"fqdn"`
	Port      string `json:"port"`
	OrgID     string `json:"org_id"`
}

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

func loadOrCreatePCEConfig(configFile string) (PCEConfig, error) {
	var config PCEConfig

	// Check if the specified config file exists
	if _, err := os.Stat(configFile); os.IsNotExist(err) {
		fmt.Println("Configuration file not found, please provide the following details:")
		reader := bufio.NewReader(os.Stdin)

		fmt.Print("API Key: ")
		apiKey, _ := reader.ReadString('\n')
		fmt.Print("API Secret: ")
		apiSecret, _ := reader.ReadString('\n')
		fmt.Print("FQDN: ")
		fqdn, _ := reader.ReadString('\n')
		fmt.Print("Port: ")
		port, _ := reader.ReadString('\n')
		fmt.Print("Org ID: ")
		orgID, _ := reader.ReadString('\n')

		config = PCEConfig{
			APIKey:    strings.TrimSpace(apiKey),
			APISecret: strings.TrimSpace(apiSecret),
			FQDN:      strings.TrimSpace(fqdn),
			Port:      strings.TrimSpace(port),
			OrgID:     strings.TrimSpace(orgID),
		}

		configData, _ := json.MarshalIndent(config, "", "  ")
		os.WriteFile(configFile, configData, 0644)
		fmt.Println("Configuration saved to", configFile)
	} else {
		configData, err := os.ReadFile(configFile)
		if err != nil {
			return config, err
		}
		json.Unmarshal(configData, &config)
	}

	// Check if any field is missing
	missing := false
	if config.APIKey == "" || config.APISecret == "" || config.FQDN == "" || config.Port == "" || config.OrgID == "" {
		missing = true
	}

	if missing {
		reader := bufio.NewReader(os.Stdin)
		if config.APIKey == "" {
			fmt.Print("API Key: ")
			apiKey, _ := reader.ReadString('\n')
			config.APIKey = strings.TrimSpace(apiKey)
		}
		if config.APISecret == "" {
			fmt.Print("API Secret: ")
			apiSecret, _ := reader.ReadString('\n')
			config.APISecret = strings.TrimSpace(apiSecret)
		}
		if config.FQDN == "" {
			fmt.Print("FQDN: ")
			fqdn, _ := reader.ReadString('\n')
			config.FQDN = strings.TrimSpace(fqdn)
		}
		if config.Port == "" {
			fmt.Print("Port: ")
			port, _ := reader.ReadString('\n')
			config.Port = strings.TrimSpace(port)
		}
		if config.OrgID == "" {
			fmt.Print("Org ID: ")
			orgID, _ := reader.ReadString('\n')
			config.OrgID = strings.TrimSpace(orgID)
		}

		configData, _ := json.MarshalIndent(config, "", "  ")
		os.WriteFile(configFile, configData, 0644)
		fmt.Println("Updated and saved configuration to", configFile)
	}

	return config, nil
}

func makeAPICall(url, method, apiKey, apiSecret, payload string, insecure bool) (int, []byte, error) {
	// Create an HTTP client
	client := &http.Client{}
	if insecure {
		// Disable certificate checking
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client = &http.Client{Transport: tr}
	}

	// Create the request
	req, err := http.NewRequest(method, url, bytes.NewBuffer([]byte(payload)))
	if err != nil {
		return 0, nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(apiKey, apiSecret)

	// Execute the request
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()

	// Read the response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, nil, err
	}

	return resp.StatusCode, body, nil
}

func checkAndEnableReport(config PCEConfig, insecure bool) error {
	fmt.Println("Checking if the report is already enabled...")

	// GET API to check report status
	url := fmt.Sprintf("https://%s:%s/api/v2/orgs/%s/report_templates/rule_hit_count_report", config.FQDN, config.Port, config.OrgID)
	statusCode, body, err := makeAPICall(url, "GET", config.APIKey, config.APISecret, "", insecure)
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
	enableURL := fmt.Sprintf("https://%s:%s/api/v2/orgs/%s/report_templates/rule_hit_count_report", config.FQDN, config.Port, config.OrgID)
	payload := `{"enabled": true}`

	statusCode, response, err := makeAPICall(enableURL, "PUT", config.APIKey, config.APISecret, payload, insecure)
	if err != nil || statusCode < 200 || statusCode >= 300 {
		return fmt.Errorf("failed to enable report, HTTP Code: %d, Error: %v", statusCode, err)
	}

	fmt.Printf("HTTP Code: %d\nResponse: %s\n", statusCode, string(response))
	return nil
}

func checkLabelHref(config PCEConfig, labelValue string, insecure bool) (string, error) {
	// Fetch all labels
	url := fmt.Sprintf("https://%s:%s/api/v2/orgs/%s/labels", config.FQDN, config.Port, config.OrgID)
	statusCode, body, err := makeAPICall(url, "GET", config.APIKey, config.APISecret, "", insecure)
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
	configFile := flag.String("config", "pce.json", "Path to the configuration file")
	insecure := flag.Bool("insecure", false, "Ignore SSL certificate errors")
	flag.Parse()

	// Load the configuration
	config, err := loadOrCreatePCEConfig(*configFile)
	if err != nil {
		log.Fatalf("Error loading or creating config: %v", err)
	}

	// Step 1: Check and enable report in PCE (First API)
	err = checkAndEnableReport(config, *insecure)
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
			labelHref, err := checkLabelHref(config, labelInput, *insecure)
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

	//	// 创建 payload 后
	//	fmt.Println("Generated payload:")
	//	fmt.Println(payload)

	//	reader = bufio.NewReader(os.Stdin)
	//	fmt.Print("Do you want to continue with this payload? (y/n): ")
	//	answer, _ := reader.ReadString('\n')
	//	answer = strings.TrimSpace(strings.ToLower(answer))

	//	if answer != "y" && answer != "yes" {
	//		fmt.Println("Operation cancelled by user.")
	//		return
	//	}

	// 继续执行 API 调用
	url := fmt.Sprintf("https://%s:%s/api/v2/orgs/%s/sec_policy/draft/firewall_settings", config.FQDN, config.Port, config.OrgID)

	// First, check the current settings to see if the action is necessary
	fmt.Println("Checking current firewall settings to see if the rule hit count is already enabled...")
	statusCode, currentSettingsBody, err := makeAPICall(url, "GET", config.APIKey, config.APISecret, "", *insecure)
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
	statusCode, response, err := makeAPICall(url, "PUT", config.APIKey, config.APISecret, payload, *insecure)
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
		provisionURL := fmt.Sprintf("https://%s:%s/api/v2/orgs/%s/sec_policy", config.FQDN, config.Port, config.OrgID)
		provisionPayload := fmt.Sprintf(`{
            "update_description":"Enable rule hit count",
            "change_subset":{"firewall_settings":[{"href":"/orgs/%s/sec_policy/draft/firewall_settings"}]}
        }`, config.OrgID)

		statusCode, provisionResponse, err := makeAPICall(provisionURL, "POST", config.APIKey, config.APISecret, provisionPayload, *insecure)
		if err != nil || statusCode < 200 || statusCode >= 300 {
			log.Fatalf("Failed to provision changes, HTTP Code: %d, Error: %v", statusCode, err)
		}

		fmt.Printf("HTTP Code: %d\nProvisioning Response: %s\n", statusCode, string(provisionResponse))
	} else {
		fmt.Println("Provisioning skipped.")
	}
}
