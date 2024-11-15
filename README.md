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



## **Contributing**

We welcome contributions to **PyDorker**! If you have ideas for improving the tool, want to add a new feature, or encounter a bug, feel free to **fork** the repository and submit a **pull request**. Here’s where you can contribute:

- Add more advanced dorks for specific penetration testing scenarios.
- Improve the rate-limiting algorithm to avoid Google blocking.
- Develop a graphical user interface (GUI) for easier interaction.
- Integrate with additional tools for enhanced data analysis and parsing.

## **License**

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for more details.

