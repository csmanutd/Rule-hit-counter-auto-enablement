# Rule-hit-counter API enablement automation
This tool will help you automatically enable PCE Rule hit count feature without manually calling APIs.

For the 1st time run, it will ask for API key/secret and save all the info in the json file.

If Rule hit count is already enabled, nothing will be updated.

Download the release and execute on Linux:  
  
./rhc_enable --config \<pce json file\>  
\* by default, it uses pce.json in the local directory


**By default, this script will enable rule hit count for all VENs.  
You can use the code in dev branch if you need to enable rhc by specific labels.**
