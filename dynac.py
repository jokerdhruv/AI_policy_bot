from dataclasses import dataclass
from typing import Dict, List, Set
import pandas as pd

@dataclass
class AccessLevel:
    base_tables: Set[str]
    additional_tables: Set[str] = None
    
    def get_all_tables(self) -> Set[str]:
        if self.additional_tables:
            return self.base_tables.union(self.additional_tables)
        return self.base_tables

class AccessControlManager:
    def __init__(self, employee_data: pd.DataFrame):
        self.employee_data = employee_data
        self.special_access_employees = set()  # Store employee IDs with special access
        self.band_permissions = {}  # Maps band_id to AccessLevel
        self.setup_default_permissions()
    
    def setup_default_permissions(self):
        """Setup default permissions based on band levels"""
        # Example band permission setup - customize based on your needs
        self.band_permissions = {
            1: AccessLevel(base_tables={'basic_employee_info', 'public_announcements'}),
            2: AccessLevel(base_tables={'basic_employee_info', 'public_announcements', 'department_info'}),
            3: AccessLevel(base_tables={'basic_employee_info', 'public_announcements', 'department_info', 'project_data'}),
            4: AccessLevel(base_tables={'basic_employee_info', 'public_announcements', 'department_info', 'project_data', 
                                      'financial_summary'}),
            5: AccessLevel(base_tables={'basic_employee_info', 'public_announcements', 'department_info', 'project_data',
                                      'financial_summary', 'hr_data'}),
            6: AccessLevel(base_tables={'basic_employee_info', 'public_announcements', 'department_info', 'project_data',
                                      'financial_summary', 'hr_data', 'executive_dashboard'}),
            7: AccessLevel(base_tables={'basic_employee_info', 'public_announcements', 'department_info', 'project_data',
                                      'financial_summary', 'hr_data', 'executive_dashboard', 'strategic_planning'})
        }
    
    def grant_special_access(self, employee_id: str, additional_tables: Set[str]):
        """Grant special access to specific employees"""
        if employee_id not in self.employee_data['employee_id'].values:
            raise ValueError(f"Employee {employee_id} not found")
            
        self.special_access_employees.add(employee_id)
        employee_band = self.employee_data.loc[
            self.employee_data['employee_id'] == employee_id, 'band_id'
        ].iloc[0]
        
        if self.band_permissions[employee_band].additional_tables is None:
            self.band_permissions[employee_band] = AccessLevel(
                base_tables=self.band_permissions[employee_band].base_tables,
                additional_tables=additional_tables
            )
        else:
            self.band_permissions[employee_band].additional_tables.update(additional_tables)
    
    def get_accessible_tables(self, employee_id: str) -> Set[str]:
        """Get all accessible tables for an employee"""
        if employee_id not in self.employee_data['employee_id'].values:
            raise ValueError(f"Employee {employee_id} not found")
            
        employee_info = self.employee_data.loc[
            self.employee_data['employee_id'] == employee_id
        ].iloc[0]
        
        band_id = employee_info['band_id']
        
        # If employee has special access, return all accessible tables
        if employee_id in self.special_access_employees:
            return self.band_permissions[band_id].get_all_tables()
        
        # Otherwise return only base tables for their band
        return self.band_permissions[band_id].base_tables

# Example usage
def load_tables(employee_id: str, access_manager: AccessControlManager) -> Dict:
    """Load tables based on employee's access level"""
    accessible_tables = access_manager.get_accessible_tables(employee_id)
    loaded_tables = {}
    
    for table_name in accessible_tables:
        # Here you would implement your actual table loading logic
        # This is just a placeholder
        loaded_tables[table_name] = f"Data for {table_name}"
    
    return loaded_tables    