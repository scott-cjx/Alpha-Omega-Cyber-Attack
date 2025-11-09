import streamlit as st
import pandas as pd
import numpy as np
from datetime import datetime, timedelta

# Set page configuration
st.set_page_config(page_title="Cybersecurity Dashboard", layout="wide", page_icon="🔒")

# Create stub dataset for CVEs and Exploits
@st.cache_data
def load_cve_exploit_data():
    """Generate sample CVE and exploit data"""
    np.random.seed(42)
    
    cve_ids = [f"CVE-2024-{np.random.randint(1000, 9999)}" for _ in range(50)]
    severities = ['Critical', 'High', 'Medium', 'Low']
    statuses = ['Active', 'Patched', 'Under Investigation', 'Mitigated']
    exploit_types = ['Remote Code Execution', 'SQL Injection', 'XSS', 'Privilege Escalation', 
                     'Buffer Overflow', 'Authentication Bypass', 'DoS', 'Zero-Day']
    
    data = []
    for i, cve_id in enumerate(cve_ids):
        discovered_date = datetime.now() - timedelta(days=np.random.randint(1, 180))
        
        # A&O CyberAttack discovered vulnerabilities (20% of total)
        is_ao_discovered = np.random.random() < 0.2
        
        data.append({
            'cve_id': cve_id,
            'title': f"Vulnerability in {np.random.choice(['Web Server', 'Database', 'API', 'Network Device', 'Application', 'Cloud Infrastructure'])}",
            'severity': np.random.choice(severities, p=[0.15, 0.35, 0.35, 0.15]),
            'cvss_score': round(np.random.uniform(3.0, 10.0), 1),
            'status': np.random.choice(statuses, p=[0.3, 0.3, 0.2, 0.2]),
            'exploit_type': np.random.choice(exploit_types),
            'discovered_date': discovered_date,
            'discovered_by': 'A&O CyberAttack' if is_ao_discovered else 'Public CVE',
            'affected_systems': np.random.randint(5, 500),
            'description': f"Critical vulnerability allowing {np.random.choice(exploit_types).lower()} in affected systems"
        })
    
    return pd.DataFrame(data)

# Create stub dataset for vulnerabilities with sentiments
@st.cache_data
def load_vulnerability_sentiment_data():
    """Generate sample vulnerability data with detailed sentiments/attributes"""
    np.random.seed(43)
    
    cve_data = load_cve_exploit_data()
    
    # Define the sentiment attributes
    attack_vectors = ['Network', 'Adjacent Network', 'Local', 'Physical', 'Email', 'Web Application', 'API']
    
    attack_chains = ['Initial Access → Execution → Persistence', 
                     'Reconnaissance → Weaponization → Delivery',
                     'Initial Access → Privilege Escalation → Data Exfiltration',
                     'Phishing → Credential Theft → Lateral Movement',
                     'Exploit → Command & Control → Impact']
    
    attack_surfaces = ['External-Facing Web Services', 'Internal Network', 'Cloud Infrastructure', 
                       'Mobile Applications', 'IoT Devices', 'Third-Party Integrations', 
                       'Supply Chain', 'Remote Access Services']
    
    pressure_points = ['Authentication Mechanism', 'Data Storage', 'Network Perimeter', 
                       'Access Controls', 'API Endpoints', 'Update Mechanism', 
                       'Encryption Implementation', 'Session Management']
    
    vulnerability_categories = ['Injection Flaws', 'Broken Authentication', 'Sensitive Data Exposure',
                                'XML External Entities', 'Broken Access Control', 'Security Misconfiguration',
                                'Cross-Site Scripting', 'Insecure Deserialization', 
                                'Using Components with Known Vulnerabilities', 'Insufficient Logging']
    
    remediation_actions = ['Apply Security Patch', 'Update to Latest Version', 'Reconfigure Settings',
                           'Implement Access Controls', 'Deploy WAF Rules', 'Network Segmentation',
                           'Remove Vulnerable Component', 'Apply Temporary Workaround', 
                           'Enable Security Features', 'Restrict Network Access']
    
    exploitation_methods = ['Automated Scanning Tools', 'Manual Exploitation', 'Social Engineering',
                            'Credential Stuffing', 'Brute Force Attack', 'Man-in-the-Middle',
                            'Code Injection', 'Protocol Manipulation', 'Configuration Abuse']
    
    vulnerable_points = ['Login Portal', 'Database Connection', 'File Upload Feature', 
                         'REST API Endpoint', 'Admin Interface', 'Service Port', 
                         'Configuration File', 'Third-Party Library', 'Authentication Service']
    
    data = []
    for _, cve in cve_data.iterrows():
        risk_score = cve['cvss_score'] * 10
        
        data.append({
            'cve_id': cve['cve_id'],
            'title': cve['title'],
            'severity': cve['severity'],
            'cvss_score': cve['cvss_score'],
            'status': cve['status'],
            'discovered_by': cve['discovered_by'],
            'attack_vector': np.random.choice(attack_vectors),
            'attack_chain': np.random.choice(attack_chains),
            'attack_surface': np.random.choice(attack_surfaces),
            'pressure_point': np.random.choice(pressure_points),
            'vulnerability_category': np.random.choice(vulnerability_categories),
            'remediation': np.random.choice(remediation_actions),
            'risk_level': int(risk_score),
            'exploitation_method': np.random.choice(exploitation_methods),
            'vulnerable_point': np.random.choice(vulnerable_points),
            'patch_available': np.random.choice(['Yes', 'No', 'Partial'], p=[0.5, 0.3, 0.2]),
            'estimated_remediation_hours': np.random.randint(2, 72),
            'exploitability': np.random.choice(['High', 'Medium', 'Low'], p=[0.3, 0.5, 0.2])
        })
    
    return pd.DataFrame(data)

# Load data
cve_exploit_df = load_cve_exploit_data()
vulnerability_sentiment_df = load_vulnerability_sentiment_data()

# Header
st.title("🔒 Cybersecurity Dashboard")
st.markdown("### CVE & Vulnerability Repository")
st.markdown("---")

# Sidebar filters
st.sidebar.header("🔍 Filters")

# Severity filter
severity_filter = st.sidebar.multiselect(
    "Severity Level",
    options=['Critical', 'High', 'Medium', 'Low'],
    default=['Critical', 'High', 'Medium', 'Low']
)

# Status filter
status_filter = st.sidebar.multiselect(
    "Status",
    options=['Active', 'Patched', 'Under Investigation', 'Mitigated'],
    default=['Active', 'Patched', 'Under Investigation', 'Mitigated']
)

# Discovery source filter
discovery_filter = st.sidebar.multiselect(
    "Discovered By",
    options=['A&O CyberAttack', 'Public CVE'],
    default=['A&O CyberAttack', 'Public CVE']
)

# Attack surface filter
attack_surface_filter = st.sidebar.multiselect(
    "Attack Surface",
    options=vulnerability_sentiment_df['attack_surface'].unique(),
    default=vulnerability_sentiment_df['attack_surface'].unique()
)

# Apply filters
filtered_cve_df = cve_exploit_df[
    (cve_exploit_df['severity'].isin(severity_filter)) &
    (cve_exploit_df['status'].isin(status_filter)) &
    (cve_exploit_df['discovered_by'].isin(discovery_filter))
]

filtered_sentiment_df = vulnerability_sentiment_df[
    (vulnerability_sentiment_df['severity'].isin(severity_filter)) &
    (vulnerability_sentiment_df['status'].isin(status_filter)) &
    (vulnerability_sentiment_df['discovered_by'].isin(discovery_filter)) &
    (vulnerability_sentiment_df['attack_surface'].isin(attack_surface_filter))
]

# Key Metrics
col1, col2, col3, col4, col5 = st.columns(5)

with col1:
    total_cves = len(filtered_cve_df)
    st.metric("Total CVEs", total_cves)

with col2:
    ao_discovered = len(filtered_cve_df[filtered_cve_df['discovered_by'] == 'A&O CyberAttack'])
    st.metric("A&O Discovered", ao_discovered)

with col3:
    critical_count = len(filtered_cve_df[filtered_cve_df['severity'] == 'Critical'])
    st.metric("Critical", critical_count)

with col4:
    active_count = len(filtered_cve_df[filtered_cve_df['status'] == 'Active'])
    st.metric("Active Threats", active_count)

with col5:
    avg_risk = filtered_sentiment_df['risk_level'].mean()
    st.metric("Avg Risk Level", f"{avg_risk:.0f}/100")

st.markdown("---")

# Main content area with two panels
col_left, col_right = st.columns([1, 1])

# LEFT PANEL: CVEs & Exploits
with col_left:
    st.subheader("📋 CVEs & Exploits Found")
    
    # Tabs for different views
    tab1, tab2 = st.tabs(["All Vulnerabilities", "A&O CyberAttack Discoveries"])
    
    with tab1:
        st.markdown(f"**Total Records:** {len(filtered_cve_df)}")
        
        # Display dataframe
        display_df = filtered_cve_df.copy()
        display_df['discovered_date'] = display_df['discovered_date'].dt.strftime('%Y-%m-%d')
        
        st.dataframe(
            display_df[['cve_id', 'title', 'severity', 'cvss_score', 'status', 
                       'exploit_type', 'discovered_by', 'affected_systems']],
            use_container_width=True,
            height=400
        )
    
    with tab2:
        ao_df = filtered_cve_df[filtered_cve_df['discovered_by'] == 'A&O CyberAttack'].copy()
        st.markdown(f"**A&O Discovered:** {len(ao_df)} vulnerabilities")
        
        if len(ao_df) > 0:
            ao_df['discovered_date'] = ao_df['discovered_date'].dt.strftime('%Y-%m-%d')
            st.dataframe(
                ao_df[['cve_id', 'title', 'severity', 'cvss_score', 'status', 
                      'exploit_type', 'affected_systems']],
                use_container_width=True,
                height=400
            )
        else:
            st.info("No A&O CyberAttack discoveries match current filters")
    
    # Severity distribution chart
    st.markdown("#### Severity Distribution")
    severity_counts = filtered_cve_df['severity'].value_counts()
    st.bar_chart(severity_counts)

# RIGHT PANEL: Vulnerabilities by Sentiment Categories
with col_right:
    st.subheader("🎯 Vulnerability Attributes & Sentiments")
    
    # Sentiment breakdown tabs
    sentiment_tabs = st.tabs([
        "Attack Vectors", "Attack Chains", "Attack Surfaces", "Pressure Points",
        "Vulnerability Categories", "Remediation", "Risk Level", "Exploitation Methods", "Vulnerable Points"
    ])
    
    with sentiment_tabs[0]:  # Attack Vectors
        st.markdown("#### Attack Vectors")
        attack_vector_data = filtered_sentiment_df.groupby('attack_vector').agg({
            'cve_id': 'count',
            'risk_level': 'mean',
            'cvss_score': 'mean'
        }).round(2)
        attack_vector_data.columns = ['Count', 'Avg Risk', 'Avg CVSS']
        st.dataframe(attack_vector_data, use_container_width=True)
        st.bar_chart(filtered_sentiment_df['attack_vector'].value_counts())
    
    with sentiment_tabs[1]:  # Attack Chains
        st.markdown("#### Attack Chains")
        st.dataframe(
            filtered_sentiment_df[['cve_id', 'title', 'attack_chain', 'severity', 'risk_level']],
            use_container_width=True,
            height=350
        )
    
    with sentiment_tabs[2]:  # Attack Surfaces
        st.markdown("#### Attack Surfaces")
        attack_surface_data = filtered_sentiment_df.groupby('attack_surface').agg({
            'cve_id': 'count',
            'risk_level': 'mean'
        }).round(2)
        attack_surface_data.columns = ['Count', 'Avg Risk']
        st.dataframe(attack_surface_data, use_container_width=True)
        st.bar_chart(filtered_sentiment_df['attack_surface'].value_counts())
    
    with sentiment_tabs[3]:  # Pressure Points
        st.markdown("#### Pressure Points")
        st.dataframe(
            filtered_sentiment_df[['cve_id', 'title', 'pressure_point', 'severity', 'exploitability']],
            use_container_width=True,
            height=350
        )
    
    with sentiment_tabs[4]:  # Vulnerability Categories
        st.markdown("#### Vulnerability Categories")
        vuln_cat_data = filtered_sentiment_df.groupby('vulnerability_category').agg({
            'cve_id': 'count',
            'risk_level': 'mean',
            'cvss_score': 'mean'
        }).round(2)
        vuln_cat_data.columns = ['Count', 'Avg Risk', 'Avg CVSS']
        st.dataframe(vuln_cat_data, use_container_width=True)
        st.bar_chart(filtered_sentiment_df['vulnerability_category'].value_counts())
    
    with sentiment_tabs[5]:  # Remediation
        st.markdown("#### Remediation Actions")
        remediation_data = filtered_sentiment_df.groupby('remediation').agg({
            'cve_id': 'count',
            'estimated_remediation_hours': 'mean',
            'patch_available': lambda x: (x == 'Yes').sum()
        }).round(2)
        remediation_data.columns = ['Count', 'Avg Hours', 'Patches Available']
        st.dataframe(remediation_data, use_container_width=True)
    
    with sentiment_tabs[6]:  # Risk Level
        st.markdown("#### Risk Level Distribution")
        risk_bins = pd.cut(filtered_sentiment_df['risk_level'], 
                          bins=[0, 25, 50, 75, 100], 
                          labels=['Low (0-25)', 'Medium (26-50)', 'High (51-75)', 'Critical (76-100)'])
        st.bar_chart(risk_bins.value_counts())
        
        high_risk = filtered_sentiment_df[filtered_sentiment_df['risk_level'] > 75]
        st.markdown(f"**High Risk (>75):** {len(high_risk)} vulnerabilities")
        st.dataframe(
            high_risk[['cve_id', 'title', 'risk_level', 'severity', 'remediation']].head(10),
            use_container_width=True
        )
    
    with sentiment_tabs[7]:  # Exploitation Methods
        st.markdown("#### Exploitation Methods")
        exploitation_data = filtered_sentiment_df.groupby('exploitation_method').agg({
            'cve_id': 'count',
            'exploitability': lambda x: (x == 'High').sum(),
            'risk_level': 'mean'
        }).round(2)
        exploitation_data.columns = ['Count', 'High Exploitability', 'Avg Risk']
        st.dataframe(exploitation_data, use_container_width=True)
        st.bar_chart(filtered_sentiment_df['exploitation_method'].value_counts())
    
    with sentiment_tabs[8]:  # Vulnerable Points
        st.markdown("#### Vulnerable Points")
        vulnerable_point_data = filtered_sentiment_df.groupby('vulnerable_point').agg({
            'cve_id': 'count',
            'risk_level': 'mean',
            'patch_available': lambda x: (x == 'Yes').sum()
        }).round(2)
        vulnerable_point_data.columns = ['Count', 'Avg Risk', 'Patches Available']
        st.dataframe(vulnerable_point_data, use_container_width=True)

st.markdown("---")

# Additional analytics
st.subheader("📊 Detailed Analytics")

col1, col2, col3 = st.columns(3)

with col1:
    st.markdown("#### Top Vulnerability Categories")
    top_categories = filtered_sentiment_df['vulnerability_category'].value_counts().head(5)
    st.bar_chart(top_categories)

with col2:
    st.markdown("#### Exploitability Distribution")
    exploit_dist = filtered_sentiment_df['exploitability'].value_counts()
    st.bar_chart(exploit_dist)

with col3:
    st.markdown("#### Patch Availability")
    patch_dist = filtered_sentiment_df['patch_available'].value_counts()
    st.bar_chart(patch_dist)

# Detailed vulnerability table
st.markdown("---")
st.subheader("🔍 Detailed Vulnerability Analysis")

# Show all attributes in expandable sections
with st.expander("View Complete Vulnerability Details"):
    st.dataframe(
        filtered_sentiment_df[[
            'cve_id', 'title', 'severity', 'cvss_score', 'risk_level',
            'attack_vector', 'attack_chain', 'attack_surface', 'pressure_point',
            'vulnerability_category', 'exploitation_method', 'vulnerable_point',
            'remediation', 'patch_available', 'estimated_remediation_hours',
            'exploitability', 'status'
        ]],
        use_container_width=True,
        height=400
    )

# Download section
st.markdown("---")
st.subheader("💾 Export Data")

col1, col2 = st.columns(2)

with col1:
    csv_cve = filtered_cve_df.to_csv(index=False)
    st.download_button(
        label="📥 Download CVE Data",
        data=csv_cve,
        file_name=f"cve_data_{datetime.now().strftime('%Y%m%d')}.csv",
        mime="text/csv"
    )

with col2:
    csv_sentiment = filtered_sentiment_df.to_csv(index=False)
    st.download_button(
        label="📥 Download Full Vulnerability Analysis",
        data=csv_sentiment,
        file_name=f"vulnerability_analysis_{datetime.now().strftime('%Y%m%d')}.csv",
        mime="text/csv"
    )