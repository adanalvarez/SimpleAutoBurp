# SimpleAutoBurp
Python script that takes a config.json file as config and uses Burp Suite Pro to scan a list of websites.

This script is a simplification of [AutoScanWithBurp](https://bitbucket.org/clr2of8/autoscanwithburp/src/master/), also AutoScanWithBurp uses an extension to execute the scan and Burp state files that were deprecated in 2018. 

SimpleAutoBurp uses the new Burp API and Burp project files. Authenticated Burp scans and Nikto are not yet implemented.

## Configure

The script needs a config.json with the configuration, here we have an example:

```
{
    "sites" : [{
        "scanURL" : "https://test-xss.000webhostapp.com",
        "project" : "/home/ec2-user/BurpSuitePro/2021-07-11-Test_1.burp",
        "apikey" : "APIKEY"
      },
      {
        "scanURL" : "http://test-xss.000webhostapp.com",
        "project" : "/home/ec2-user/BurpSuitePro/2021-07-11-Test_1.burp",
        "apikey" : "APIKEY"
      }
    ],
    "burpConfigs" : [{
        "memory" : "2048m",
        "headless" : "true",
        "java" : "/home/ec2-user/BurpSuitePro/jre/bin/java",
        "burpJar" : "/home/ec2-user/BurpSuitePro/burpsuite_pro.jar",
        "retry" : 5,
        "logPath" : "/home/ec2-user/BurpSuitePro/",
        "logfileName" : "SimpleAutoBurp",
        "loglevel" : "debug",
        "ScanOutput" : "/home/ec2-user/ScanOutput/"
      }
      ]
}
```

- Site (the config file can contain multiple sites):
    - scanURL: URL to scan.
    - project: Path to a [Burp project files](https://portswigger.net/burp/documentation/desktop/getting-started/launching/projects).
    - apikey: Burp API Key. User options - Misc - REST API, enable the service and create a new API Key. More info [here](https://portswigger.net/burp/documentation/desktop/options/misc-user#rest-api-options).
- burpConfigs
    - memory: Maximum amount of memory.
    - headless: Enable or disable headless mode.
    - java: Path to the Java binary.
    - burpJar: Path to the Burp Suite JAR file.
    - retry: How many times, the script will try to check if burp is up and running.
    - logPath: Path of the log file.
    - logfileName: Name of the log file.
    - loglevel: Log Level (DEBUG INFO WARNING ERROR CRITICAL).
    - ScanOutput: Path to results

## Execute

```
SimpleAutoBurp.py /home/ec2-user/config.json
```

## Schedule Scan

This script can be scheduled to execute using crontab in *nix systems like this:

```
0 2 * * * ec2-user /usr/bin/python3.7 /home/ec2-user/SimpleAutoBurp.py /home/ec2-user/config.json
```

## Output

The script generates a log of the execution and a file with a json that includes information about all the vulnerabilities found. It only shows vulnerabilities detected in this scan and not detected previously.

## Recommendations

To improve the results of the scan enable extensions like:
   - Active Scans++
   - Software Vulnerability Scanner
   - Backslash Powered Scanner
   - Additional Scanner Checks
   - Error Message Checks
