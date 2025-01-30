import pandas as pd
import json
import re
from datetime import datetime
import smtplib
from email.mime.text import MIMEText
from typing import Dict, List, Optional, Tuple
import logging

class SecurityLogger:
    def __init__(self, log_file: str = 'security_events.log'):
        logging.basicConfig(
            filename=log_file,
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger('SecurityLogger')

    def log_access_attempt(self, employee_id: str, resource: str, successful: bool, details: str):
        level = logging.INFO if successful else logging.WARNING
        self.logger.log(level, f"Access Attempt - Employee: {employee_id}, Resource: {resource}, "
                              f"Success: {successful}, Details: {details}")

class SecurityNotifier:
    def __init__(self, smtp_config: Dict):
        self.smtp_config = smtp_config
        
    def send_alert(self, incident: Dict):
        msg = MIMEText(
            f"""
            Security Alert:
            Employee ID: {incident['employee_id']}
            Attempted Action: {incident['action']}
            Resource: {incident['resource']}
            Timestamp: {incident['timestamp']}
            Details: {incident['details']}
            """
        )
        msg['Subject'] = f"Security Alert: Unauthorized Access Attempt"
        msg['From'] = self.smtp_config['from_email']
        msg['To'] = ', '.join(self.smtp_config['security_team'])

        try:
            with smtplib.SMTP(self.smtp_config['server'], self.smtp_config['port']) as server:
                server.starttls()
                server.login(self.smtp_config['username'], self.smtp_config['password'])
                server.send_message(msg)
        except Exception as e:
            logging.error(f"Failed to send security alert: {str(e)}")

class PermissionChecker:
    def __init__(self, org_data_file: str, security_logger: SecurityLogger, security_notifier: SecurityNotifier):
        self.df = pd.read_excel(org_data_file)
        self.security_logger = security_logger
        self.security_notifier = security_notifier
        
        # Cache employee permissions for faster lookup
        self.permission_cache = {}
        self.load_permission_cache()

    def load_permission_cache(self):
        for _, row in self.df.iterrows():
            self.permission_cache[row['employee_id']] = {
                'permissions': set(row['total_permissions'].split(',')),
                'band_id': row['band_id'],
                'department': row['department'],
                'role': row['role']
            }

    def get_employee_info(self, employee_id: str) -> Optional[Dict]:
        return self.permission_cache.get(employee_id)

    def has_permission(self, employee_id: str, required_permission: str) -> bool:
        employee_info = self.get_employee_info(employee_id)
        if not employee_info:
            return False
        return required_permission in employee_info['permissions']

class QueryAnalyzer:
    def __init__(self):
        # Define sensitive keywords and their required permissions
        self.sensitive_patterns = {
            r'\b(salary|compensation|pay)\b': 'manage_compensation',
            r'\b(fire|terminate|dismissal)\b': 'handle_disciplinary',
            r'\b(source\s*code|codebase)\b': 'access_codebase',
            r'\b(security|vulnerability)\b': 'security_tools_admin',
            r'\b(financial|revenue|profit)\b': 'view_financial_reports'
        }
        
        # Define department-specific keywords
        self.department_patterns = {
            'HR': r'\b(employee|hiring|benefits|recruitment)\b',
            'Engineering': r'\b(code|deployment|technical|system)\b',
            'Finance': r'\b(budget|expense|payment|invoice)\b'
        }

    def analyze_query(self, query: str) -> Dict:
        required_permissions = set()
        relevant_departments = set()

        # Check for sensitive keywords
        for pattern, permission in self.sensitive_patterns.items():
            if re.search(pattern, query.lower()):
                required_permissions.add(permission)

        # Check for department-specific keywords
        for dept, pattern in self.department_patterns.items():
            if re.search(pattern, query.lower()):
                relevant_departments.add(dept)

        return {
            'required_permissions': required_permissions,
            'relevant_departments': relevant_departments,
            'sensitivity_level': len(required_permissions)
        }

class AIResponseFilter:
    def __init__(self, permission_checker: PermissionChecker):
        self.permission_checker = permission_checker

    def filter_response(self, response: str, employee_id: str) -> str:
        """Filter AI response based on user's permissions."""
        employee_info = self.permission_checker.get_employee_info(employee_id)
        if not employee_info:
            return "Access denied. Please verify your employee ID."

        # Redact sensitive information if user lacks permissions
        redacted_response = response
        
        # Example redaction rules based on permissions
        if 'view_financial_reports' not in employee_info['permissions']:
            redacted_response = re.sub(r'\$\d+(?:,\d{3})*(?:\.\d{2})?', '[REDACTED]', redacted_response)
            redacted_response = re.sub(r'\b\d+(?:,\d{3})*(?:\.\d{2})?\s*(?:USD|EUR|GBP)\b', '[REDACTED]', redacted_response)

        if 'view_employee_all' not in employee_info['permissions']:
            redacted_response = re.sub(r'\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b', '[REDACTED]', redacted_response, flags=re.I)
            redacted_response = re.sub(r'\b(?:phone|tel|mobile)\s*:?\s*\+?\d[\d\s-]{8,}\b', '[REDACTED]', redacted_response, flags=re.I)

        return redacted_response

class AISecurityWrapper:
    def __init__(self, org_data_file: str, smtp_config: Dict):
        self.security_logger = SecurityLogger()
        self.security_notifier = SecurityNotifier(smtp_config)
        self.permission_checker = PermissionChecker(org_data_file, self.security_logger, self.security_notifier)
        self.query_analyzer = QueryAnalyzer()
        self.response_filter = AIResponseFilter(self.permission_checker)

    def process_query(self, employee_id: str, query: str) -> Tuple[bool, str, Dict]:
        """Process and validate a query before sending to AI."""
        
        # Get employee info
        employee_info = self.permission_checker.get_employee_info(employee_id)
        if not employee_info:
            return False, "Invalid employee ID", {}

        # Analyze query
        analysis = self.query_analyzer.analyze_query(query)
        
        # Check permissions
        has_access = True
        for required_permission in analysis['required_permissions']:
            if not self.permission_checker.has_permission(employee_id, required_permission):
                has_access = False
                break

        # Log attempt
        self.security_logger.log_access_attempt(
            employee_id=employee_id,
            resource=str(analysis['required_permissions']),
            successful=has_access,
            details=query
        )

        # Send alert if suspicious
        if not has_access:
            incident = {
                'employee_id': employee_id,
                'action': 'query',
                'resource': str(analysis['required_permissions']),
                'timestamp': datetime.now().isoformat(),
                'details': f"Unauthorized query: {query}"
            }
            self.security_notifier.send_alert(incident)
            return False, "You don't have permission to access this information", {}

        return True, "", {
            'employee_info': employee_info,
            'query_analysis': analysis
        }

    def filter_ai_response(self, employee_id: str, response: str) -> str:
        """Filter AI response based on user permissions."""
        return self.response_filter.filter_response(response, employee_id)

# Example usage:
def main():
    # Configuration
    smtp_config = {
        'server': 'smtp.company.com',
        'port': 587,
        'username': 'security@company.com',
        'password': 'your-password',
        'from_email': 'security@company.com',
        'security_team': ['security-team@company.com']
    }

    # Initialize the security wrapper
    security_wrapper = AISecurityWrapper('organization_data.xlsx', smtp_config)

    # Example query processing
    employee_id = "EMP0001"
    query = "Can you show me the salary information for all employees?"

    # Process query
    allowed, message, context = security_wrapper.process_query(employee_id, query)
    
    if not allowed:
        print(f"Access denied: {message}")
        return

    # If allowed, you would here:
    # 1. Send query to your AI model
    # 2. Get response
    # 3. Filter response
    example_ai_response = "The average salary is $75,000. Contact john@company.com for details."
    filtered_response = security_wrapper.filter_ai_response(employee_id, example_ai_response)
    print(f"Filtered response: {filtered_response}")

if __name__ == "__main__":
    main()