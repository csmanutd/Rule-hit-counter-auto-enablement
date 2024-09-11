package main

import (
    "bufio"
    "bytes"
    "encoding/json"
    "flag"
    "fmt"
    "io/ioutil"
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

func loadOrCreatePCEConfig(configFilePath string) (PCEConfig, error) {
    var config PCEConfig

    if _, err := os.Stat(configFilePath); os.IsNotExist(err) {
        fmt.Printf("Configuration file not found at %s, please provide the following details:\n", configFilePath)
        config = promptUserForConfig()
        saveConfigToFile(config, configFilePath)
    } else {
        configData, err := ioutil.ReadFile(configFilePath)
        if err != nil {
            return config, err
        }
        json.Unmarshal(configData, &config)

        // Check for missing fields and prompt for input
        if isConfigIncomplete(config) {
            fmt.Println("Some configuration details are missing. Please provide the missing details:")
            config = promptUserForMissingConfig(config)
            saveConfigToFile(config, configFilePath)
        }
    }

    return config, nil
}

func isConfigIncomplete(config PCEConfig) bool {
    return config.APIKey == "" || config.APISecret == "" || config.FQDN == "" || config.Port == "" || config.OrgID == ""
}

func promptUserForConfig() PCEConfig {
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

    return PCEConfig{
        APIKey:    strings.TrimSpace(apiKey),
        APISecret: strings.TrimSpace(apiSecret),
        FQDN:      strings.TrimSpace(fqdn),
        Port:      strings.TrimSpace(port),
        OrgID:     strings.TrimSpace(orgID),
    }
}

func promptUserForMissingConfig(config PCEConfig) PCEConfig {
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

    return config
}

func saveConfigToFile(config PCEConfig, configFilePath string) {
    configData, err := json.MarshalIndent(config, "", "  ")
    if err != nil {
        log.Fatalf("Failed to save configuration: %v", err)
    }
    err = ioutil.WriteFile(configFilePath, configData, 0644)
    if err != nil {
        log.Fatalf("Error writing to file: %v", err)
    }
    fmt.Printf("Configuration saved to %s.\n", configFilePath)
}

func makeAPICall(url, method, apiKey, apiSecret, payload string) (int, []byte, error) {
    client := &http.Client{}
    req, err := http.NewRequest(method, url, bytes.NewBuffer([]byte(payload)))
    if err != nil {
        return 0, nil, err
    }

    req.Header.Set("Content-Type", "application/json")
    req.SetBasicAuth(apiKey, apiSecret)

    resp, err := client.Do(req)
    if err != nil {
        return 0, nil, err
    }
    defer resp.Body.Close()

    body, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        return 0, nil, err
    }

    return resp.StatusCode, body, nil
}

func checkReportStatus(config PCEConfig) (bool, error) {
    fmt.Println("Checking if the report is already enabled...")
    url := fmt.Sprintf("https://%s:%s/api/v2/orgs/%s/report_templates/rule_hit_count_report", config.FQDN, config.Port, config.OrgID)
    statusCode, body, err := makeAPICall(url, "GET", config.APIKey, config.APISecret, "")
    if err != nil {
        return false, err
    }

    if statusCode != http.StatusOK {
        return false, fmt.Errorf("failed to fetch report status, HTTP Code: %d", statusCode)
    }

    var reportStatus struct {
        Enabled bool `json:"enabled"`
    }
    if err := json.Unmarshal(body, &reportStatus); err != nil {
        return false, err
    }

    return reportStatus.Enabled, nil
}

func checkFirewallSettings(config PCEConfig) (bool, error) {
    fmt.Println("Checking if counting on all VENs is already enabled...")
    url := fmt.Sprintf("https://%s:%s/api/v2/orgs/%s/sec_policy/draft/firewall_settings", config.FQDN, config.Port, config.OrgID)
    statusCode, body, err := makeAPICall(url, "GET", config.APIKey, config.APISecret, "")
    if err != nil {
        return false, err
    }

    if statusCode != http.StatusOK {
        return false, fmt.Errorf("failed to fetch firewall settings, HTTP Code: %d", statusCode)
    }

    var firewallSettings struct {
        RuleHitCountEnabledScopes [][]interface{} `json:"rule_hit_count_enabled_scopes"`
    }
    if err := json.Unmarshal(body, &firewallSettings); err != nil {
        return false, err
    }

    return len(firewallSettings.RuleHitCountEnabledScopes) == 1 && len(firewallSettings.RuleHitCountEnabledScopes[0]) == 0, nil
}

func main() {
    // Allow user to specify a config file path
    configFilePath := flag.String("config", "pce.json", "Path to the configuration file")
    flag.Parse()

    config, err := loadOrCreatePCEConfig(*configFilePath)
    if err != nil {
        log.Fatalf("Error loading or creating config: %v", err)
    }

    reportEnabled, err := checkReportStatus(config)
    if err != nil {
        log.Fatalf("Error checking report status: %v", err)
    }

    venCountingEnabled, err := checkFirewallSettings(config)
    if err != nil {
        log.Fatalf("Error checking firewall settings: %v", err)
    }

    if reportEnabled && venCountingEnabled {
        fmt.Println("Rule hit counter functionality is already enabled. No actions are necessary.")
        return
    }

    if !reportEnabled {
        fmt.Println("Enabling report in PCE...")
        url := fmt.Sprintf("https://%s:%s/api/v2/orgs/%s/report_templates/rule_hit_count_report", config.FQDN, config.Port, config.OrgID)
        payload := `{"enabled": true}`
        statusCode, response, err := makeAPICall(url, "PUT", config.APIKey, config.APISecret, payload)
        if err != nil {
            log.Fatalf("Error enabling report: %v", err)
        }
        fmt.Printf("HTTP Code: %d\nResponse: %s\n", statusCode, string(response))
    }

    if !venCountingEnabled {
        fmt.Println("Enabling counting on all VENs...")
        url := fmt.Sprintf("https://%s:%s/api/v2/orgs/%s/sec_policy/draft/firewall_settings", config.FQDN, config.Port, config.OrgID)
        payload := `{"rule_hit_count_enabled_scopes":[[]]}`
        statusCode, response, err := makeAPICall(url, "PUT", config.APIKey, config.APISecret, payload)
        if err != nil {
            log.Fatalf("Error enabling counting on all VENs: %v", err)
        }
        fmt.Printf("HTTP Code: %d\nResponse: %s\n", statusCode, string(response))
    }

    if !reportEnabled || !venCountingEnabled {
        fmt.Println("Provisioning changes...")

        reader := bufio.NewReader(os.Stdin)
        fmt.Print("Do you want to proceed with provisioning changes? (Y/n): ")
        confirmation, _ := reader.ReadString('\n')
        confirmation = strings.TrimSpace(confirmation)

        if strings.ToLower(confirmation) == "y" || confirmation == "" {
            url := fmt.Sprintf("https://%s:%s/api/v2/orgs/%s/sec_policy", config.FQDN, config.Port, config.OrgID)
            payload := `{"update_description":"Enable rule hit count","change_subset":{"firewall_settings":[{"href":"/orgs/%s/sec_policy/draft/firewall_settings"}]}}`
            payload = fmt.Sprintf(payload, config.OrgID)
            statusCode, response, err := makeAPICall(url, "POST", config.APIKey, config.APISecret, payload)
            if err != nil {
                log.Fatalf("Error provisioning changes: %v", err)
            }
            fmt.Printf("HTTP Code: %d\nResponse: %s\n", statusCode, string(response))
        } else {
            fmt.Println("Provisioning cancelled.")
        }
    }
}
