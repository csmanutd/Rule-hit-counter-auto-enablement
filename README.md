# Rule-hit-counter API enablement automation
This tool will help you automatically enable PCE Rule hit count feature without manually calling APIs.

For the 1st time run, it will ask for API key/secret and save all the info in the json file.

If rule hit count is already enabled, nothing will be updated.  
**You can enable rule hit count by specific labels.**  

Download the release and execute on Linux:  
  
./rhc_enable --pce \<pce name\>  
  
No need to use --pce for the 1st time.  
For the 1st time run, it will ask you to save pce config to pce.json in the local folder.  
You can save multiple pce configs in the json file and use --pce to specify the pce. By default, the 1st pce will be the default one.  
