from urllib.parse import urlencode, quote_plus

BASE_URL = "https://www.google.com/search"

def create_google_search_url(query, language="en", num_results=10, time_range=None, filetype=None, site=None, 
                             geo_target=None, custom_user_agent=None, custom_cookie=None, date_filter=None, 
                             extra_filters=None, tbs_filters=None, safe_search=False, related_search=None, 
                             language_target=None, country_target=None, proxies=None, ssl_check=False, 
                             dork_type=None, category=None, batch_mode=False, user_time=None):
    """
    Dynamically constructs a Google search URL with a comprehensive set of filters and options.

    Args:
        query (str): The search query.
        language (str, optional): Language for search results. Defaults to "en".
        num_results (int, optional): Number of results to retrieve. Defaults to 10.
        time_range (str, optional): Time range for search results ("y", "m", "d").
        filetype (str, optional): Specific filetype to search for (e.g., "pdf").
        site (str, optional): Specific website to limit the search to (e.g., "example.com").
        geo_target (str, optional): Geo-targeting (e.g., "US" for the United States).
        custom_user_agent (str, optional): Custom User-Agent header for the search.
        custom_cookie (str, optional): Custom cookie to include in the search request.
        date_filter (str, optional): Filter results by date ("d" for day, "m" for month, "y" for year).
        extra_filters (dict, optional): Additional filters as key-value pairs (e.g., {'tbs': 'itp'}).
        tbs_filters (str, optional): Google-specific search filters (e.g., 'itp' for images, 'li:1' for live results).
        safe_search (bool, optional): Enable or disable SafeSearch.
        related_search (str, optional): Include related search terms.
        language_target (str, optional): Target language for the search results.
        country_target (str, optional): Target country (e.g., "US", "IN").
        proxies (dict, optional): A dictionary of proxy settings for the requests.
        ssl_check (bool, optional): Perform SSL checks on the search.
        dork_type (str, optional): Specify the type of Google dork query (e.g., "filetype", "inurl").
        category (str, optional): Specify a category for the search (e.g., "education").
        batch_mode (bool, optional): Enable batch mode for multiple queries at once.
        user_time (str, optional): Specify the user’s time zone for search results.

    Returns:
        str: The complete, dynamically generated Google search URL.
    """
    
    # Initialize search parameters
    params = {
        'q': query,               # The search query
        'hl': language,           # Language setting (e.g., "en", "tr")
        'num': num_results        # Number of results
    }
    
    # Time range filter (e.g., past year, month, or day)
    if time_range:
        params['tbs'] = f'qdr:{time_range}'
    
    # File type filter (e.g., "pdf", "doc")
    if filetype:
        params['q'] += f' filetype:{filetype}'
    
    # Site-specific search filter
    if site:
        params['q'] += f' site:{site}'
    
    # Geo-targeting filter (e.g., US for United States)
    if geo_target:
        params['gl'] = geo_target
    
    # Custom User-Agent header (optional)
    if custom_user_agent:
        params['user-agent'] = custom_user_agent
    
    # Custom cookie filter (optional)
    if custom_cookie:
        params['cookie'] = custom_cookie
    
    # Additional custom filters (e.g., 'itp' for images)
    if extra_filters:
        params.update(extra_filters)
    
    # TBS (Google's custom filters) (e.g., image search, live results)
    if tbs_filters:
        params['tbs'] = tbs_filters
    
    # SafeSearch setting (true or false)
    if safe_search:
        params['safe'] = "active"
    
    # Related search terms (e.g., "ataturk", "turkey")
    if related_search:
        params['related'] = related_search
    
    # Target language for search results (e.g., 'en' for English, 'tr' for Turkish)
    if language_target:
        params['lr'] = f'lang_{language_target}'
    
    # Country target for search results (e.g., 'US', 'IN')
    if country_target:
        params['cr'] = f'country{country_target}'
    
    # Proxies (optional, only applicable for requests)
    if proxies:
        params['proxy'] = proxies
    
    # SSL check (optional)
    if ssl_check:
        params['sslcheck'] = "true"
    
    # Google Dork type (e.g., 'filetype', 'inurl', 'intitle')
    if dork_type:
        params['dork'] = dork_type
    
    # Category for Google Dork queries (e.g., 'education', 'finance')
    if category:
        params['category'] = category
    
    # Batch mode for handling multiple queries at once
    if batch_mode:
        params['batch'] = "true"
    
    # User time zone (optional)
    if user_time:
        params['user_time'] = user_time

    # Construct the full URL with parameters
    url_with_params = f"{BASE_URL}?{urlencode(params)}"
    return url_with_params

# Example usage with an extended set of parameters
query = "ataturk"
language = "tr"
num_results = 20
time_range = "y"  # Last year
filetype = "pdf"
site = "example.com"
geo_target = "US"
custom_user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36"
custom_cookie = "session_id=abc123"
extra_filters = {'tbs': 'itp'}
safe_search = True
related_search = "turkey"
language_target = "en"
country_target = "US"
proxies = {"http": "http://proxy.com:8080"}
ssl_check = True
dork_type = "filetype"
category = "education"
batch_mode = True
user_time = "GMT+3"

# Generate and print the full URL with dynamic arguments
full_url = create_google_search_url(query, language, num_results, time_range, filetype, site, geo_target, 
                                    custom_user_agent, custom_cookie, date_filter="m", extra_filters=extra_filters, 
                                    safe_search=safe_search, related_search=related_search, 
                                    language_target=language_target, country_target=country_target, 
                                    proxies=proxies, ssl_check=ssl_check, dork_type=dork_type, category=category, 
                                    batch_mode=batch_mode, user_time=user_time)

print(full_url)
