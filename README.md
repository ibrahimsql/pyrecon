# **Google Dorking Tool - PyRecon**

**PyDorker** is a powerful Python-based tool for leveraging Google Dorking techniques to search for sensitive information, vulnerabilities, and public data exposed on the internet. It utilizes custom Google search queries to find a variety of hidden resources that are otherwise not easily discoverable. This tool can be an essential part of your **security auditing** and **penetration testing** toolkit.

## **Features**
- **Advanced Google Dork Queries**: Leverage a wide range of pre-configured and custom Google Dork queries for scanning websites and databases for sensitive information.
- **Fully Written in Python**: Easy to use, extend, and integrate into your existing Python projects.
- **Fast and Efficient**: Optimized to run quickly, even for large-scale queries across multiple websites.
- **Customizable Search**: Allow the user to define custom dorks or search patterns based on their needs.
- **JSON Export**: Save your results in **JSON,TXT,DB,CSV** format for easy parsing and further analysis.
- **Rate Limiting**: Prevent Google from blocking your requests by controlling the number of queries sent per minute.
- **Multi-threading**: Run multiple queries simultaneously to increase speed without losing performance.
- **User-friendly Interface**: Designed to be simple to use for both beginners and advanced users.
- İşte **PyDorker** projeniz için GitHub’a yükleyeceğiniz, daha dikkat çekici ve profesyonel bir açıklama. Bu sürüm, doğru formatta ve içerikte daha fazla ilgi çekebilir:

---

# **PyRecon: Powerful Python Google Dorking Tool for Security Audits**

**PyDorker** is a highly efficient, Python-based tool that uses advanced **Google Dorking** techniques to uncover hidden vulnerabilities, sensitive data, and publicly exposed information on the internet. Whether you’re a penetration tester, security auditor, or researcher, **PyRecon** will help you automate the process of finding hard-to-reach resources. 

This tool is perfect for **security auditing**, **penetration testing**, and **information gathering**, allowing you to find exposed databases, credentials, misconfigurations, and other sensitive data on websites.

## **Key Features**

- 🔍 **Advanced Google Dork Queries**: Pre-configured and customizable queries to discover hidden resources, databases, and security vulnerabilities.
- 🐍 **Built in Python**: Easy to use, extend, and integrate into your existing Python-based tools.
- ⚡ **Fast and Efficient**: Optimized to handle large-scale queries with speed, even across multiple websites at once.
- 🔧 **Customizable Search Parameters**: Create personalized search patterns to suit your specific security needs.
- 📥 **Export to JSON**: Save your results in **JSON,TXT,DB,CSV** format for easy parsing, analysis, and integration with other tools.
- 🛡️ **Rate Limiting**: Control your search frequency to avoid being blocked by Google, making your searches safer and more reliable.
- ⚙️ **Multi-threading Support**: Perform multiple queries in parallel for faster results.
- 🎯 **User-Friendly Interface**: Simple, intuitive, and designed for both beginners and experienced users.

## **Installation**

1. Clone the repository:
git clone https://github.com/ibrahimsql/pyrecon.git
  

2. Navigate to the project directory:
 cd pygoogledork
3.Install the required dependencies:
pip install -r requirements.txt
  
## **How to Use**

To run **PyRecon**, simply execute the following command with your desired search parameters:

python PyRecon -d "<dork_query>" -t <threads> -o output.json


### Example:

python PyRecon -d "inurl:admin site:example.com" -t 4 -o results.json


This will run the query `inurl:admin site:example.com` using **4 threads**, saving the results in a file called **results.json**.

### Available Options:

-h, --help: Show help message and exit.

-q QUERY [QUERY ...], --query QUERY [QUERY ...]: Google Dork query or queries (multiple allowed).

-n NUMBER, --number NUMBER: Max number of sites to fetch.

-o OUTPUT, --output OUTPUT: Output file name (without extension).

-t TLD, --tld TLD: Domain extension (e.g., com, org, net).

--remove-www: Remove www prefix from URLs.

--min-delay MIN_DELAY: Minimum wait time (in seconds) between queries.

--max-delay MAX_DELAY: Maximum wait time (in seconds) between queries.

--output-format {txt,json,csv,db}: Output format (default: "txt", supports .txt, .json, .csv, or .db).

--proxy PROXY [PROXY ...]: Proxy addresses to route queries through (e.g., http://proxy1, http://proxy2).

--check-cloudflare: Skip sites that are protected by Cloudflare.

--threads THREADS: Max number of threads to run concurrently.

--proxy-rotator: Use a different proxy for each request to avoid IP bans.

--captcha-bypass: Attempt to bypass CAPTCHA challenges during searches.

--scheduler SCHEDULER: Schedule scan to start at a specific time (e.g., '23:00').

--max-results MAX_RESULTS: Limit the max number of results to be returned.

--vulnerability-report: Automatically generate vulnerability reports based on findings.

--web-scraping-api: Integrate with a web scraping API for enhanced scraping capabilities.

--lang LANG: Filter search results by a specific language (e.g., 'en', 'tr').

--geo-target GEO_TARGET: Specify a geographic location for search queries (e.g., 'US', 'DE').

--dns-tunneling: Bypass network restrictions using DNS Tunneling methods.

--ssl-check: Perform SSL/TLS vulnerability checks on the discovered domains.

--dork-type {filetype,inurl,intitle}: Specify the dork type (e.g., filetype, inurl, intitle).

--category CATEGORY: Choose a category for the search query (e.g., 'admin', 'login').

--cookie COOKIE: Specify a custom cookie for use during the search session.

--agent AGENT: Use a custom User-Agent string for the HTTP requests.

--list: Perform a batch search using predefined dork lists.

--no-sandbox: Disable sandbox features to allow unrestricted search queries.

--save: Save the search results to a file.

-f FILE, --file FILE: Perform batch search using a file containing a list of dorks.

--timeout TIMEOUT: Set a custom request timeout (in seconds).

--domain DOMAIN: Focus the search on a specific domain (e.g., example.com).

--num-results NUM_RESULTS: Limit the number of results returned for each query.

--waf-bypass: Attempt to bypass Web Application Firewall (WAF) protections during searches.

--exploit-db: Search for vulnerabilities using Exploit-DB integration.

## **Contributing**

We welcome contributions to **PyDorker**! If you have ideas for improving the tool, want to add a new feature, or encounter a bug, feel free to **fork** the repository and submit a **pull request**. Here’s where you can contribute:

- Add more advanced dorks for specific penetration testing scenarios.
- Improve the rate-limiting algorithm to avoid Google blocking.
- Develop a graphical user interface (GUI) for easier interaction.
- Integrate with additional tools for enhanced data analysis and parsing.

## **License**

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for more details.

