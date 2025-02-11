import requests
from requests.auth import HTTPBasicAuth
 
# Jira credentials
JIRA_DOMAIN = ""  # Replace with your Jira domain
EMAIL = ""           # Replace with your Atlassian email
API_TOKEN = ""               # Replace with your API token
 
# Function to get user details by email
def get_user_by_email(user_email):
    url = f"https://{JIRA_DOMAIN}/rest/api/3/user/search?query={user_email}"
    headers = {"Accept": "application/json"}
    response = requests.get(url, headers=headers, auth=HTTPBasicAuth(EMAIL, API_TOKEN))
 
    if response.status_code == 200 and response.json():
        return response.json()[0]  # Return the first matched user
    else:
        print(f"User not found: {response.text}")
        return None
 
# Function to get projects assigned to the user
def get_user_projects(account_id):
    url = f"https://{JIRA_DOMAIN}/rest/api/3/project/search"
    headers = {"Accept": "application/json"}
    response = requests.get(url, headers=headers, auth=HTTPBasicAuth(EMAIL, API_TOKEN))
 
    if response.status_code == 200:
        projects = response.json().get("values", [])
        assigned_projects = []
 
        for project in projects:
            project_key = project["key"]
 
            # Check if the user has issues in this project
            jql_url = f"https://{JIRA_DOMAIN}/rest/api/3/search?jql=assignee={account_id} AND project={project_key}"
            jql_response = requests.get(jql_url, headers=headers, auth=HTTPBasicAuth(EMAIL, API_TOKEN))
 
            if jql_response.status_code == 200 and jql_response.json()["total"] > 0:
                assigned_projects.append({
                    "name": project["name"],
                    "key": project["key"],
                    "id": project["id"]
                })
 
        return assigned_projects
    else:
        print(f"Error fetching projects: {response.text}")
        return None
 
# Main function to get project details for a user
def get_projects_for_user(user_email):
    user = get_user_by_email(user_email)
    if not user:
        return "User not found"
 
    account_id = user["accountId"]
    projects = get_user_projects(account_id)
 
    if projects:
        return projects
    else:
        return "No projects assigned to this user"
 
# Example usage
user_email = ""  # Replace with the actual user email
projects = get_projects_for_user(user_email)
print("Projects assigned to the user:", projects)
 
 