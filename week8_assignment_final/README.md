#secretscanner_final.py

A Python-based command line tool that scans directories or files for visible hardcoded secrets, including API keys, tokens, and any passwords using regex patterns. regex patterns sourced from https://github.com/odomojuli/regextokens

***Regex Patterns sampled for the project:***
* AWS Access ID Key ('AKIA[0-9A-Z]{16}')
* Slack Bot/User Access Token (OAuth v2): ('xoxb/xoxp-[0-9]{11}-[0-9]{11}-[0-9a-zA-Z]{24}')
* Stripe API Key ('sk_live_[0-9a-zA-Z]{24}')
* Heroku API Key ('[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}')
* Mailgun API Key ('key-[0-9a-zA-Z]{32}')

> The scanner meets project requirements to report filename, line number, and a matched string.

***Requirements:***
1. Python 3 or newer.
2. No external libraries necessary!


***How to Run:***
1. Open Powershell in the week8_assignment_final folder or open the project in VSCode and use a Terminal. 
2. To scan a single file (the demo file in the folder), use: ```python secretscanner_final.py demo_app.py```
3. To scan THE entire directory that secretscanner_final.py is in recursively, use: ```python secretscanner_final.py .```
4. To scan ANY entire directory on your system, use: ```python secretscanner_final.py /path/to/yourfolder```
5. To view any verbose debug information (skipped files, scan progress, etc), use: ```python secretscanner_final.py demo_app.py -v```
(you can use -v at the end of any scan type to display debug information in the output)
6. To display 'help', use ```python secretscanner_final.py -h```