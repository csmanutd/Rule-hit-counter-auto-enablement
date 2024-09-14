# Rule-hit-counter API enablement automation
This tool will help you automatically enable PCE Rule hit count feature without manually calling APIs.

For the 1st time run, it will ask for API key/secret and save all the info in the json file.

If rule hit count is already enabled, nothing will be updated.  
**You can enable rule hit count by specific labels.**  

Download the release and execute on Linux:  
  
./rhc_enable --config \<pce json file\>  
\* by default, it uses pce.json in the local directory
