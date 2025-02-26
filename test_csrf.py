import requests
import time
from prettytable import PrettyTable

def send_request(url, method="GET", data=None):
    """Send an HTTP request to the specified URL."""
    try:
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        if method.upper() == "POST":
            response = requests.post(url, data=data, headers=headers)
        else:
            response = requests.get(url, headers=headers)
        return response
    except requests.RequestException as e:
        print(f"Request failed: {e}")
        return None

def test_csrf(url, payloads):
    """Test for Cross-Site Request Forgery (CSRF) vulnerabilities."""
    table = PrettyTable(["URL", "CSRF Payload", "Status Code", "CSRF Detected", "Error Message"])
    table.align["CSRF Detected"] = "l"
    
    test_url = f"{url.rstrip('/')}/submit"  # Ensure the URL is well-formed
    
    for payload in payloads:
        data = {"csrf_token": payload}
        csrf_detected = "No"
        error_message = "N/A"

        try:
            response = send_request(test_url, method="POST", data=data)
            if response:
                status_code = response.status_code

                # Check if the payload is reflected in the response (indicating a CSRF vulnerability)
                if payload in response.text:
                    csrf_detected = "Yes"
                elif status_code in [401, 403]:
                    error_message = "Unauthorized access"
                elif status_code == 404:
                    error_message = "Endpoint not found"
                table.add_row([test_url, payload, status_code, csrf_detected, error_message])
            else:
                table.add_row([test_url, payload, "No Response", csrf_detected, "No response from server"])
        except requests.RequestException as e:
            table.add_row([test_url, payload, "Error", csrf_detected, str(e)])
        time.sleep(0.1)  # Delay between requests to avoid overloading the server

    print(table)

    # Additional checks for CSRF defenses
    print("\nAdditional Checks:")
    additional_table = PrettyTable(["URL", "Check Type", "Result"])
    additional_table.align["Check Type"] = "l"

    try:
        response = send_request(test_url, method="POST", data={"csrf_token": "test"})
        if response:
            # Check for CSRF token validation
            if "csrf token validation" in response.text.lower():
                additional_table.add_row([test_url, "CSRF Token Validation", "Present"])
            
            # Check for same-origin policy mentions
            if "same-origin policy" in response.text.lower():
                additional_table.add_row([test_url, "Same-Origin Policy", "Detected"])
            
            # Check for cross-site scripting defense mentions
            if "cross-site scripting" in response.text.lower():
                additional_table.add_row([test_url, "Cross-Site Scripting Mitigation", "Mentioned"])
    except requests.RequestException as e:
        print(f"       [!] Error during additional checks for {test_url}: {e}")

    time.sleep(0.1)
    print(additional_table)

# List of payloads for CSRF testing
payloads = [
    "<img src='x' onerror='alert(\"CSRF\")'>",
    "<script>alert('CSRF')</script>",
    "<iframe src='x' onload='alert(\"CSRF\")'></iframe>",
]

if __name__ == "__main__":
    url = input("Enter the URL to test: ")
    if not url.startswith("http"):
        print("Please enter a valid URL (including http:// or https://).")
    else:
        test_csrf(url, payloads)
