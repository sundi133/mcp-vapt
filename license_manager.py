#!/usr/bin/env python3
"""
ExternalAttacker-MCP License Manager
30-Day Trial and Commercial Licensing System
"""

import os
import json
import hashlib
import base64
import time
import datetime
import uuid
import socket
import platform
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import requests

class LicenseManager:
    def __init__(self):
        self.license_file = "license.key"
        self.config_file = "license_config.json"
        self.master_key = self._get_master_key()
        self.fernet = self._get_cipher()
        
    def _get_master_key(self):
        """Generate master key based on hardware fingerprint"""
        # Create hardware fingerprint
        system_info = {
            'hostname': socket.gethostname(),
            'platform': platform.system(),
            'processor': platform.processor(),
            'machine': platform.machine()
        }
        
        # Create deterministic key from system info
        fingerprint = json.dumps(system_info, sort_keys=True).encode()
        salt = b'ExternalAttacker-MCP-License-Salt-2024'
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        
        return base64.urlsafe_b64encode(kdf.derive(fingerprint))
    
    def _get_cipher(self):
        """Get Fernet cipher for encryption/decryption"""
        return Fernet(self.master_key)
    
    def generate_trial_license(self, customer_email="trial@customer.com", 
                             customer_name="Trial Customer",
                             days=30):
        """Generate a 30-day trial license"""
        
        # License data
        license_data = {
            'license_type': 'trial',
            'customer_email': customer_email,
            'customer_name': customer_name,
            'issued_date': datetime.datetime.now().isoformat(),
            'expiry_date': (datetime.datetime.now() + datetime.timedelta(days=days)).isoformat(),
            'license_id': str(uuid.uuid4()),
            'features': {
                'max_targets': 50,
                'max_concurrent_scans': 5,
                'compliance_modules': True,
                'stealth_scanning': True,
                'reporting': True,
                'api_access': True
            },
            'hardware_fingerprint': self._get_hardware_fingerprint(),
            'version': '1.0.0'
        }
        
        # Encrypt and encode license
        license_json = json.dumps(license_data, indent=2)
        encrypted_license = self.fernet.encrypt(license_json.encode())
        encoded_license = base64.b64encode(encrypted_license).decode()
        
        # Save to file
        with open(self.license_file, 'w') as f:
            f.write(encoded_license)
        
        return license_data
    
    def generate_commercial_license(self, customer_email, customer_name, 
                                  expiry_date=None, features=None):
        """Generate a commercial license"""
        
        if not expiry_date:
            # Default to 1 year
            expiry_date = datetime.datetime.now() + datetime.timedelta(days=365)
        
        if not features:
            features = {
                'max_targets': 1000,
                'max_concurrent_scans': 20,
                'compliance_modules': True,
                'stealth_scanning': True,
                'reporting': True,
                'api_access': True,
                'enterprise_features': True,
                'priority_support': True
            }
        
        license_data = {
            'license_type': 'commercial',
            'customer_email': customer_email,
            'customer_name': customer_name,
            'issued_date': datetime.datetime.now().isoformat(),
            'expiry_date': expiry_date.isoformat() if isinstance(expiry_date, datetime.datetime) else expiry_date,
            'license_id': str(uuid.uuid4()),
            'features': features,
            'hardware_fingerprint': self._get_hardware_fingerprint(),
            'version': '1.0.0'
        }
        
        # Encrypt and encode license
        license_json = json.dumps(license_data, indent=2)
        encrypted_license = self.fernet.encrypt(license_json.encode())
        encoded_license = base64.b64encode(encrypted_license).decode()
        
        # Save to file
        with open(self.license_file, 'w') as f:
            f.write(encoded_license)
        
        return license_data
    
    def validate_license(self):
        """Validate the current license"""
        
        if not os.path.exists(self.license_file):
            return {
                'valid': False,
                'error': 'No license file found',
                'action': 'activate_trial'
            }
        
        try:
            # Read and decode license
            with open(self.license_file, 'r') as f:
                encoded_license = f.read().strip()
            
            encrypted_license = base64.b64decode(encoded_license)
            decrypted_license = self.fernet.decrypt(encrypted_license)
            license_data = json.loads(decrypted_license.decode())
            
            # Validate expiry date
            expiry_date = datetime.datetime.fromisoformat(license_data['expiry_date'])
            current_date = datetime.datetime.now()
            
            if current_date > expiry_date:
                days_expired = (current_date - expiry_date).days
                return {
                    'valid': False,
                    'error': f'License expired {days_expired} days ago',
                    'expiry_date': license_data['expiry_date'],
                    'action': 'renew_license'
                }
            
            # Validate hardware fingerprint
            current_fingerprint = self._get_hardware_fingerprint()
            if license_data.get('hardware_fingerprint') != current_fingerprint:
                return {
                    'valid': False,
                    'error': 'License not valid for this hardware',
                    'action': 'contact_support'
                }
            
            # Calculate days remaining
            days_remaining = (expiry_date - current_date).days
            
            return {
                'valid': True,
                'license_data': license_data,
                'days_remaining': days_remaining,
                'expiry_date': license_data['expiry_date']
            }
            
        except Exception as e:
            return {
                'valid': False,
                'error': f'License validation failed: {str(e)}',
                'action': 'activate_trial'
            }
    
    def _get_hardware_fingerprint(self):
        """Generate hardware fingerprint for license binding"""
        system_info = {
            'hostname': socket.gethostname(),
            'platform': platform.system(),
            'machine': platform.machine()
        }
        
        fingerprint_str = json.dumps(system_info, sort_keys=True)
        return hashlib.sha256(fingerprint_str.encode()).hexdigest()[:16]
    
    def activate_trial(self, customer_email=None, customer_name=None):
        """Activate a 30-day trial license"""
        
        if not customer_email:
            customer_email = input("Enter your email address: ").strip()
        
        if not customer_name:
            customer_name = input("Enter your name/company: ").strip()
        
        # Check if trial already exists
        validation = self.validate_license()
        if validation['valid'] and validation['license_data']['license_type'] == 'trial':
            print(f"⚠️ Trial license already active ({validation['days_remaining']} days remaining)")
            return validation['license_data']
        
        # Generate new trial license
        license_data = self.generate_trial_license(customer_email, customer_name)
        
        print("✅ 30-Day Trial License Activated!")
        print(f"Customer: {customer_name}")
        print(f"Email: {customer_email}")
        print(f"License ID: {license_data['license_id']}")
        print(f"Expires: {license_data['expiry_date']}")
        
        return license_data
    
    def get_license_info(self):
        """Get current license information"""
        validation = self.validate_license()
        
        if not validation['valid']:
            return validation
        
        license_data = validation['license_data']
        
        return {
            'valid': True,
            'license_type': license_data['license_type'],
            'customer_name': license_data['customer_name'],
            'customer_email': license_data['customer_email'],
            'license_id': license_data['license_id'],
            'issued_date': license_data['issued_date'],
            'expiry_date': license_data['expiry_date'],
            'days_remaining': validation['days_remaining'],
            'features': license_data['features']
        }
    
    def check_feature_access(self, feature_name):
        """Check if a specific feature is licensed"""
        validation = self.validate_license()
        
        if not validation['valid']:
            return False
        
        features = validation['license_data'].get('features', {})
        return features.get(feature_name, False)
    
    def enforce_limits(self, current_targets=0, current_scans=0):
        """Enforce license limits"""
        validation = self.validate_license()
        
        if not validation['valid']:
            return {
                'allowed': False,
                'error': validation['error']
            }
        
        features = validation['license_data'].get('features', {})
        max_targets = features.get('max_targets', 10)
        max_scans = features.get('max_concurrent_scans', 1)
        
        if current_targets > max_targets:
            return {
                'allowed': False,
                'error': f'Target limit exceeded ({current_targets}/{max_targets})'
            }
        
        if current_scans > max_scans:
            return {
                'allowed': False,
                'error': f'Concurrent scan limit exceeded ({current_scans}/{max_scans})'
            }
        
        return {
            'allowed': True,
            'limits': {
                'max_targets': max_targets,
                'max_scans': max_scans,
                'current_targets': current_targets,
                'current_scans': current_scans
            }
        }

def main():
    """CLI interface for license management"""
    import argparse
    
    parser = argparse.ArgumentParser(description='ExternalAttacker-MCP License Manager')
    parser.add_argument('action', choices=['activate', 'validate', 'info', 'generate-trial', 'generate-commercial'])
    parser.add_argument('--email', help='Customer email')
    parser.add_argument('--name', help='Customer name')
    parser.add_argument('--days', type=int, default=30, help='Trial days (default: 30)')
    
    args = parser.parse_args()
    
    lm = LicenseManager()
    
    if args.action == 'activate':
        lm.activate_trial(args.email, args.name)
    
    elif args.action == 'validate':
        validation = lm.validate_license()
        if validation['valid']:
            print("✅ License is valid")
            print(f"Days remaining: {validation['days_remaining']}")
        else:
            print(f"❌ License validation failed: {validation['error']}")
    
    elif args.action == 'info':
        info = lm.get_license_info()
        if info['valid']:
            print("📄 License Information:")
            print(f"Type: {info['license_type']}")
            print(f"Customer: {info['customer_name']}")
            print(f"Email: {info['customer_email']}")
            print(f"License ID: {info['license_id']}")
            print(f"Expires: {info['expiry_date']}")
            print(f"Days remaining: {info['days_remaining']}")
            print(f"Features: {json.dumps(info['features'], indent=2)}")
        else:
            print(f"❌ {info['error']}")
    
    elif args.action == 'generate-trial':
        email = args.email or input("Customer email: ")
        name = args.name or input("Customer name: ")
        license_data = lm.generate_trial_license(email, name, args.days)
        print(f"✅ Trial license generated: {license_data['license_id']}")
    
    elif args.action == 'generate-commercial':
        email = args.email or input("Customer email: ")
        name = args.name or input("Customer name: ")
        license_data = lm.generate_commercial_license(email, name)
        print(f"✅ Commercial license generated: {license_data['license_id']}")

if __name__ == "__main__":
    main() 