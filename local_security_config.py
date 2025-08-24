# Local Security Tools Configuration
# Use this file to configure ExternalAttacker-MCP with locally installed security tools

LOCAL_SECURITY_ENDPOINTS = {
    'nessus': {
        'url': 'https://localhost:8834',
        'access_key': 'your-nessus-access-key',
        'secret_key': 'your-nessus-secret-key',
        'verify_ssl': False  # For self-signed certs
    },
    
    'beef': {
        'server': 'http://localhost:3000',
        'username': 'beef',
        'password': 'beef'
    },
    
    'defectdojo': {
        'url': 'http://localhost:8080',
        'api_token': 'your-defectdojo-api-token'
    },
    
    'dradis': {
        'url': 'http://localhost:3001',
        'api_token': 'your-dradis-api-token'
    }
}

# Example usage functions for local testing
async def test_local_nessus():
    """Test local Nessus installation"""
    from ExternalAttacker_App import scan_with_nessus_direct
    
    result = await scan_with_nessus_direct(
        target="192.168.1.1/24",  # Local network
        scan_template="basic",
        nessus_url=LOCAL_SECURITY_ENDPOINTS['nessus']['url'],
        access_key=LOCAL_SECURITY_ENDPOINTS['nessus']['access_key'],
        secret_key=LOCAL_SECURITY_ENDPOINTS['nessus']['secret_key']
    )
    return result

async def test_local_beef():
    """Test local BeEF installation"""
    from ExternalAttacker_App import exploit_with_beef_direct
    
    result = await exploit_with_beef_direct(
        target_url="http://testphp.vulnweb.com",  # Test target
        beef_server=LOCAL_SECURITY_ENDPOINTS['beef']['server'],
        beef_user=LOCAL_SECURITY_ENDPOINTS['beef']['username'],
        beef_pass=LOCAL_SECURITY_ENDPOINTS['beef']['password']
    )
    return result

async def test_local_defectdojo():
    """Test local DefectDojo installation"""
    from ExternalAttacker_App import upload_to_defectdojo_direct
    
    # First create a test scan file
    import tempfile
    with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as f:
        f.write("""<?xml version="1.0"?>
<NessusClientData_v2>
    <Report name="test_scan">
        <ReportHost name="127.0.0.1">
            <ReportItem port="80" protocol="tcp" pluginName="Test Finding" severity="2">
                <description>Test vulnerability for local testing</description>
            </ReportItem>
        </ReportHost>
    </Report>
</NessusClientData_v2>""")
        test_file = f.name
    
    result = await upload_to_defectdojo_direct(
        file_path=test_file,
        engagement_id=1,  # Default engagement
        defectdojo_url=LOCAL_SECURITY_ENDPOINTS['defectdojo']['url'],
        api_token=LOCAL_SECURITY_ENDPOINTS['defectdojo']['api_token'],
        scan_type="Nessus Scan"
    )
    return result

async def test_local_dradis():
    """Test local Dradis installation"""
    from ExternalAttacker_App import create_dradis_project_direct
    
    result = await create_dradis_project_direct(
        project_name="Local Test Assessment",
        dradis_url=LOCAL_SECURITY_ENDPOINTS['dradis']['url'],
        api_token=LOCAL_SECURITY_ENDPOINTS['dradis']['api_token'],
        description="Local testing of Dradis integration",
        client_name="Internal Testing"
    )
    return result

# Quick setup guide
SETUP_GUIDE = """
🔧 LOCAL SETUP GUIDE

1. Run the setup script:
   ./setup_local_security_stack.sh

2. Configure API tokens:
   - Nessus: Login to https://localhost:8834 → Settings → API Keys
   - DefectDojo: Login to http://localhost:8080 → API v2 Key
   - Dradis: Login to http://localhost:3001 → Account → API Token
   - BeEF: Uses default credentials (beef/beef)

3. Update this config file with your tokens

4. Test the integrations:
   python3 -c "import local_security_config; import asyncio; asyncio.run(local_security_config.test_local_beef())"

5. Use in ExternalAttacker-MCP:
   - Set URLs to localhost endpoints
   - Use your generated API tokens
   - Test with internal networks (192.168.x.x, 10.x.x.x)

⚠️  Security Notes:
- Only use on isolated/lab networks
- Don't expose these services to the internet
- Change default passwords
- Use proper SSL certificates for production
"""

if __name__ == "__main__":
    print(SETUP_GUIDE) 