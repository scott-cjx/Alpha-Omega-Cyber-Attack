import streamlit as st
import pandas as pd
import plotly.graph_objects as go
from datetime import datetime
import random

# Page configuration
st.set_page_config(
    page_title="Α&Ω CyberATTech", 
    layout="wide", 
    initial_sidebar_state="expanded",
    page_icon="🛡️"
)

# Custom CSS
st.markdown("""
<style>
    .main-header {
        text-align: center;
        padding: 1rem;
        background: linear-gradient(90deg, #1e3c72 0%, #2a5298 100%);
        color: white;
        border-radius: 10px;
        margin-bottom: 2rem;
    }
    .warning-banner {
        background-color: #fff3cd;
        border-left: 4px solid #ffc107;
        padding: 1rem;
        margin: 1rem 0;
        color: #856404;
    }
</style>
""", unsafe_allow_html=True)

# Initialize session state
if 'cves' not in st.session_state:
    st.session_state.cves = [
        {"id": "CVE-2024-1234", "severity": "CRITICAL", "score": 9.8, "description": "Remote Code Execution in Apache Server", "status": "unpatched"},
        {"id": "CVE-2024-5678", "severity": "HIGH", "score": 7.5, "description": "SQL Injection in MySQL Connector", "status": "patched"},
        {"id": "CVE-2024-9012", "severity": "MEDIUM", "score": 5.3, "description": "XSS in Web Framework", "status": "unpatched"},
        {"id": "CVE-2024-3456", "severity": "CRITICAL", "score": 9.1, "description": "Buffer Overflow in Network Stack", "status": "unpatched"},
    ]

if 'scan_history' not in st.session_state:
    st.session_state.scan_history = []

if 'exploits' not in st.session_state:
    st.session_state.exploits = []

if 'agents' not in st.session_state:
    st.session_state.agents = {
        "block_day": "D8h",
        "framework": "langchain",
        "lazy_graph": True,
        "gan_model": "active"
    }

# Header
st.markdown("""
<div class="main-header">
    <h1>Α&Ω CyberATTech</h1>
    <p>Alpha & Omega Adversarial Threat Technology</p>
    <small>ano-cyberat.tech</small>
</div>
""", unsafe_allow_html=True)

st.markdown("""
<div class="warning-banner">
    ⚠️ <strong>Demo Environment:</strong> This system performs local scanning only. 
    Web deployment is for demonstration purposes. All exploit generation uses adversarial GAN architecture.
</div>
""", unsafe_allow_html=True)

# Sidebar navigation
st.sidebar.title("🛡️ Α&Ω System")
st.sidebar.caption("ano-cyberat.tech")
page = st.sidebar.radio("Select Module", ["🔍 Local Scan & Fuzz", "🤖 Adversarial Exploit Lab", "🚀 Deploy"])

st.sidebar.markdown("---")
st.sidebar.subheader("Agent Status")
st.sidebar.write(f"**Block Day:** {st.session_state.agents['block_day']}")
st.sidebar.write(f"**Framework:** {st.session_state.agents['framework']}")
st.sidebar.write(f"**GAN Status:** {st.session_state.agents['gan_model']}")

with st.sidebar.expander("⚙️ Configuration"):
    st.session_state.agents['block_day'] = st.text_input("Block Day", value=st.session_state.agents['block_day'])
    st.session_state.agents['framework'] = st.selectbox("Framework", ["langchain", "custom"], 
                                                         index=0 if st.session_state.agents['framework'] == "langchain" else 1)
    st.session_state.agents['lazy_graph'] = st.checkbox("Lazy Graph Mode", value=st.session_state.agents['lazy_graph'])
    st.session_state.agents['gan_model'] = st.selectbox("GAN Model", ["active", "training", "disabled"])

# =======================
# LOCAL SCAN & FUZZ PAGE
# =======================
if page == "🔍 Local Scan & Fuzz":
    st.title("🎯 Local System Analysis")
    st.caption("Fuzzing & vulnerability scanning on local system only")
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.subheader("🖥️ Local System Scanner")
        
        with st.form("scan_form"):
            scan_target = st.selectbox(
                "Scan Target",
                ["localhost", "127.0.0.1", "Local Docker Containers", "Local VMs", "Custom Local Path"]
            )
            
            if scan_target == "Custom Local Path":
                custom_path = st.text_input("Path", placeholder="/var/www/html")
            
            col_a, col_b = st.columns(2)
            with col_a:
                scan_type = st.multiselect(
                    "Scan Type",
                    ["Port Scan", "Fuzz Testing", "Service Enumeration", "CVE Detection", "Configuration Audit"],
                    default=["CVE Detection"]
                )
            
            with col_b:
                intensity = st.slider("Scan Intensity", 1, 10, 5)
            
            col_c, col_d = st.columns(2)
            with col_c:
                submit_scan = st.form_submit_button("🚀 Run Local Scan", use_container_width=True)
            with col_d:
                stop_scan = st.form_submit_button("⛔ Stop Scan", use_container_width=True)
        
        if submit_scan:
            with st.spinner(f"Scanning {scan_target}..."):
                import time
                progress_bar = st.progress(0)
                status_text = st.empty()
                
                for i in range(100):
                    time.sleep(0.02)
                    progress_bar.progress(i + 1)
                    if i < 30:
                        status_text.text("🔍 Enumerating local services...")
                    elif i < 60:
                        status_text.text("🔨 Fuzzing local endpoints...")
                    elif i < 80:
                        status_text.text("🔐 Checking configurations...")
                    else:
                        status_text.text("📋 Detecting CVEs...")
                
                st.session_state.scan_history.insert(0, {
                    "target": scan_target,
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "scans": scan_type,
                    "cves_found": random.randint(2, 8)
                })
                
                progress_bar.empty()
                status_text.empty()
                st.success(f"✅ Scan completed! Found {st.session_state.scan_history[0]['cves_found']} vulnerabilities")
        
        st.markdown("---")
        st.subheader("📊 Discovered CVEs")
        
        # Filter controls
        col_filter1, col_filter2, col_filter3 = st.columns(3)
        with col_filter1:
            severity_filter = st.multiselect("Severity", ["CRITICAL", "HIGH", "MEDIUM", "LOW"], default=["CRITICAL", "HIGH", "MEDIUM"])
        with col_filter2:
            status_filter = st.multiselect("Status", ["unpatched", "patched"], default=["unpatched", "patched"])
        with col_filter3:
            min_score = st.slider("Min CVSS Score", 0.0, 10.0, 0.0)
        
        # Filter and display CVEs
        filtered_cves = [
            cve for cve in st.session_state.cves 
            if cve['severity'] in severity_filter 
            and cve['status'] in status_filter
            and cve['score'] >= min_score
        ]
        
        if filtered_cves:
            for cve in filtered_cves:
                severity_color = {
                    "CRITICAL": "🔴",
                    "HIGH": "🟠", 
                    "MEDIUM": "🟡",
                    "LOW": "🟢"
                }
                
                with st.expander(f"{severity_color[cve['severity']]} {cve['id']} - {cve['severity']} (CVSS: {cve['score']})"):
                    st.markdown(f"**Description:** {cve['description']}")
                    st.markdown(f"**Status:** `{cve['status']}`")
                    st.markdown(f"**CVSS Score:** {cve['score']}/10.0")
                    
                    col_btn1, col_btn2, col_btn3 = st.columns(3)
                    with col_btn1:
                        if st.button("📋 View Details", key=f"details_{cve['id']}"):
                            st.info("Opening CVE database...")
                    with col_btn2:
                        if st.button("🎯 Add to Exploit Lab", key=f"exploit_{cve['id']}"):
                            st.success(f"Added {cve['id']} to exploit generator queue")
                    with col_btn3:
                        if st.button("🗑️ Remove", key=f"remove_{cve['id']}"):
                            st.session_state.cves.remove(cve)
                            st.rerun()
        else:
            st.info("No CVEs match the current filters")
        
        # Add manual CVE
        with st.expander("➕ Add Manual CVE Discovery"):
            with st.form("add_cve"):
                new_id = st.text_input("CVE ID", placeholder="CVE-2024-XXXX or NEW-DISCOVERY")
                new_severity = st.selectbox("Severity", ["CRITICAL", "HIGH", "MEDIUM", "LOW"])
                new_score = st.slider("CVSS Score", 0.0, 10.0, 5.0)
                new_desc = st.text_input("Description")
                
                if st.form_submit_button("Add CVE"):
                    st.session_state.cves.append({
                        "id": new_id,
                        "severity": new_severity,
                        "score": new_score,
                        "description": new_desc,
                        "status": "unpatched"
                    })
                    st.rerun()
    
    with col2:
        st.subheader("📈 System Overview")
        
        total_cves = len(st.session_state.cves)
        critical_count = sum(1 for c in st.session_state.cves if c['severity'] == 'CRITICAL')
        unpatched_count = sum(1 for c in st.session_state.cves if c['status'] == 'unpatched')
        
        st.metric("Total CVEs", total_cves)
        st.metric("Critical", critical_count, delta=f"{critical_count} unpatched" if critical_count > 0 else None)
        st.metric("Unpatched", unpatched_count)
        
        st.markdown("---")
        st.markdown("**Severity Distribution**")
        severity_counts = {}
        for cve in st.session_state.cves:
            severity_counts[cve['severity']] = severity_counts.get(cve['severity'], 0) + 1
        
        fig = go.Figure(data=[go.Pie(
            labels=list(severity_counts.keys()),
            values=list(severity_counts.values()),
            marker=dict(colors=['#dc3545', '#fd7e14', '#ffc107', '#28a745'])
        )])
        fig.update_layout(height=250, margin=dict(l=0, r=0, t=30, b=0))
        st.plotly_chart(fig, use_container_width=True)
        
        st.markdown("---")
        st.markdown("**Recent Scans**")
        if st.session_state.scan_history:
            for scan in st.session_state.scan_history[:5]:
                st.caption(f"🎯 {scan['target']}")
                st.caption(f"   {scan['timestamp']} - {scan['cves_found']} CVEs")
        else:
            st.info("No scans yet")

# =======================
# ADVERSARIAL EXPLOIT LAB
# =======================
elif page == "🤖 Adversarial Exploit Lab":
    st.title("🤖 GAN-Based Adversarial Exploit System")
    st.caption("Alpha (Generator) vs Omega (Discriminator) Architecture")
    
    # CVE Selection
    st.subheader("🎯 Select CVEs for Exploit Combination")
    
    col_select1, col_select2 = st.columns([3, 1])
    
    with col_select1:
        selected_cves = st.multiselect(
            "Select CVEs (existing or new discoveries)",
            [cve['id'] for cve in st.session_state.cves],
            format_func=lambda x: f"{x} - {next(c['description'] for c in st.session_state.cves if c['id'] == x)}"
        )
    
    with col_select2:
        if st.button("Select All Critical", use_container_width=True):
            selected_cves = [cve['id'] for cve in st.session_state.cves if cve['severity'] == 'CRITICAL']
            st.rerun()
    
    if selected_cves:
        st.info(f"✅ Selected {len(selected_cves)} CVE(s) for combination")
        
        # Display selected CVEs
        with st.expander("📋 View Selected CVEs"):
            for cve_id in selected_cves:
                cve_data = next(c for c in st.session_state.cves if c['id'] == cve_id)
                st.markdown(f"**{cve_id}** - {cve_data['description']} (CVSS: {cve_data['score']})")
    
    st.markdown("---")
    
    # GAN Configuration
    col_config1, col_config2 = st.columns(2)
    
    with col_config1:
        st.subheader("⚙️ Exploit Configuration")
        
        exploit_algo = st.selectbox(
            "Primary Algorithm",
            ["ROP Chain", "Heap Spray", "Format String", "Race Condition", "Type Confusion", "UAF (Use-After-Free)", "Custom Combination"]
        )
        
        target_platform = st.selectbox(
            "Target Platform",
            ["Linux x64", "Windows x64", "ARM", "Web Application", "IoT Device", "Multi-platform"]
        )
        
        complexity = st.slider("Exploit Complexity", 1, 10, 7, help="Higher complexity creates more sophisticated exploits")
    
    with col_config2:
        st.subheader("🎛️ GAN Parameters")
        
        iterations = st.number_input("Training Iterations", 100, 10000, 2000, step=100)
        creativity = st.slider("Generator Creativity", 0, 100, 75, help="Alpha's innovation level")
        defense_strength = st.slider("Discriminator Strength", 0, 100, 70, help="Omega's defense capability")
    
    # Generate button
    st.markdown("---")
    
    if st.button("🚀 Generate Adversarial Exploit", type="primary", use_container_width=True, disabled=not selected_cves):
        if not selected_cves:
            st.error("Please select at least one CVE")
        else:
            # Create tabs for the GAN process
            tab1, tab2, tab3 = st.tabs(["🔄 Generation Process", "📊 Results", "🛡️ Mitigation"])
            
            with tab1:
                st.subheader("Adversarial Training Process")
                
                col_gan1, col_gan2 = st.columns(2)
                
                with col_gan1:
                    st.markdown("### 🔴 Alpha (Generator)")
                    alpha_status = st.empty()
                    alpha_progress = st.progress(0)
                    alpha_thoughts = st.container()
                
                with col_gan2:
                    st.markdown("### 🔵 Omega (Discriminator)")
                    omega_status = st.empty()
                    omega_progress = st.progress(0)
                    omega_thoughts = st.container()
                
                # Simulate adversarial training
                import time
                
                alpha_chain = []
                omega_chain = []
                
                for i in range(10):
                    time.sleep(0.3)
                    
                    # Alpha (Generator) steps
                    if i < 3:
                        alpha_status.text("🔍 Analyzing CVE combinations...")
                        alpha_chain.append(f"Step {i+1}: Identified vulnerable code paths in {', '.join(selected_cves[:2])}")
                    elif i < 6:
                        alpha_status.text("🎨 Generating exploit variants...")
                        alpha_chain.append(f"Step {i+1}: Crafted payload using {exploit_algo} technique")
                    elif i < 8:
                        alpha_status.text("🔧 Optimizing exploit chain...")
                        alpha_chain.append(f"Step {i+1}: Chained {len(selected_cves)} CVEs for maximum impact")
                    else:
                        alpha_status.text("✅ Exploit generation complete")
                        alpha_chain.append(f"Step {i+1}: Final exploit achieves {random.randint(85, 98)}% success rate")
                    
                    alpha_progress.progress((i + 1) * 10)
                    
                    # Omega (Discriminator) steps
                    time.sleep(0.2)
                    
                    if i < 3:
                        omega_status.text("🔍 Analyzing attack vectors...")
                        omega_chain.append(f"Step {i+1}: Detected {len(selected_cves)} CVE exploitation attempts")
                    elif i < 6:
                        omega_status.text("🛡️ Generating defensive solutions...")
                        omega_chain.append(f"Step {i+1}: Proposed mitigation for {exploit_algo} attack")
                    elif i < 8:
                        omega_status.text("🔧 Validating defenses...")
                        omega_chain.append(f"Step {i+1}: Testing mitigation effectiveness")
                    else:
                        omega_status.text("✅ Defense analysis complete")
                        omega_chain.append(f"Step {i+1}: Generated comprehensive mitigation strategy")
                    
                    omega_progress.progress((i + 1) * 10)
                
                # Display chain of thought
                with alpha_thoughts:
                    st.markdown("**Chain of Thought:**")
                    for thought in alpha_chain:
                        st.caption(f"💭 {thought}")
                
                with omega_thoughts:
                    st.markdown("**Chain of Thought:**")
                    for thought in omega_chain:
                        st.caption(f"💭 {thought}")
            
            with tab2:
                st.subheader("📊 Exploit Analysis")
                
                # Generate exploit data
                exploit_confidence = random.randint(80, 97)
                impact_score = random.randint(7, 10)
                
                col_result1, col_result2, col_result3 = st.columns(3)
                
                with col_result1:
                    st.metric("Exploit Confidence", f"{exploit_confidence}%")
                with col_result2:
                    st.metric("Impact Score", f"{impact_score}/10")
                with col_result3:
                    st.metric("CVEs Combined", len(selected_cves))
                
                st.markdown("---")
                
                # CVEs Used
                st.markdown("**🎯 CVEs Used in Exploit:**")
                for cve_id in selected_cves:
                    cve_data = next(c for c in st.session_state.cves if c['id'] == cve_id)
                    st.markdown(f"- **{cve_id}**: {cve_data['description']} (CVSS: {cve_data['score']})")
                
                st.markdown("---")
                
                # Algorithm Details
                st.markdown(f"**⚙️ Exploit Algorithm:** {exploit_algo}")
                st.code(f"""
# Exploit Chain Algorithm
# Primary Technique: {exploit_algo}
# Target: {target_platform}
# CVEs: {', '.join(selected_cves)}

def exploit_chain():
    # Phase 1: Initial Access via {selected_cves[0]}
    initial_vector = trigger_vulnerability("{selected_cves[0]}")
    
    # Phase 2: Privilege Escalation
    if len({selected_cves}) > 1:
        escalate_privileges("{selected_cves[1] if len(selected_cves) > 1 else 'N/A'}")
    
    # Phase 3: Execute {exploit_algo}
    payload = craft_{exploit_algo.lower().replace(' ', '_')}_payload()
    
    # Phase 4: Persistence
    establish_persistence()
    
    return execute_exploit(payload)

# Success Rate: {exploit_confidence}%
# Impact: {impact_score}/10
                """, language="python")
                
                st.markdown("---")
                
                # Impact Analysis
                st.markdown("**💥 Exploit Impact:**")
                
                impact_areas = {
                    "Confidentiality": random.randint(7, 10),
                    "Integrity": random.randint(6, 10),
                    "Availability": random.randint(5, 10)
                }
                
                for area, score in impact_areas.items():
                    col_a, col_b = st.columns([1, 3])
                    with col_a:
                        st.write(f"**{area}:**")
                    with col_b:
                        st.progress(score / 10)
                        st.caption(f"{score}/10")
                
                # Save exploit
                st.session_state.exploits.insert(0, {
                    "cves": selected_cves,
                    "algorithm": exploit_algo,
                    "platform": target_platform,
                    "confidence": exploit_confidence,
                    "impact": impact_score,
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "alpha_chain": alpha_chain,
                    "omega_chain": omega_chain,
                    "impact_areas": impact_areas
                })
            
            with tab3:
                st.subheader("🛡️ Omega's Mitigation Strategy")
                
                # Determine if mitigation exists
                has_solution = impact_score < 9 or len(selected_cves) <= 2
                
                if has_solution:
                    st.success("✅ Mitigation solution available")
                    
                    st.markdown("**📋 Recommended Mitigations:**")
                    
                    # Existing mitigation combination
                    st.markdown("**Combination of Existing Solutions:**")
                    
                    mitigations = [
                        f"Apply security patch for {selected_cves[0]}",
                        f"Implement input validation to prevent {exploit_algo}",
                        f"Enable ASLR and DEP on {target_platform}",
                        "Deploy network segmentation",
                        "Implement least privilege access controls"
                    ]
                    
                    for i, mitigation in enumerate(mitigations[:min(len(selected_cves) + 2, 5)], 1):
                        st.markdown(f"{i}. {mitigation}")
                    
                    st.markdown("---")
                    
                    st.markdown("**🔧 Implementation Steps:**")
                    st.code(f"""
# Mitigation Implementation
# Generated by Omega (Discriminator)

# Step 1: Patch vulnerable components
for cve in {selected_cves}:
    apply_security_patch(cve)

# Step 2: Harden system configuration
enable_security_features([
    "ASLR",
    "DEP", 
    "Stack Canaries",
    "CFI"
])

# Step 3: Deploy detection rules
configure_monitoring("{exploit_algo}", alert_level="HIGH")

# Step 4: Implement compensating controls
deploy_waf_rules()
restrict_network_access()

# Estimated effectiveness: {random.randint(85, 98)}%
                    """, language="python")
                    
                else:
                    st.error("⚠️ No existing solution - Highly impactful exploit")
                    
                    st.markdown("**🚨 Critical Findings:**")
                    st.warning(f"""
This exploit combines {len(selected_cves)} CVEs in a novel way that bypasses existing mitigations.
                    
**Characteristics:**
- Impact Score: {impact_score}/10 (CRITICAL)
- No known patches address this combination
- Requires new defensive research
                    
**Recommended Actions:**
1. Immediately isolate affected systems
2. Implement emergency network segmentation
3. Deploy custom detection signatures
4. Begin development of new mitigation techniques
5. Notify security community and vendors
                    """)
                    
                    st.markdown("**🔬 Research Required:**")
                    st.info("""
Omega's analysis indicates this exploit represents a novel attack vector.
Recommended for immediate security research and potential CVE disclosure.
                    """)
                
                st.markdown("---")
                
                st.markdown("**📊 Mitigation Effectiveness:**")
                if has_solution:
                    effectiveness = random.randint(85, 98)
                    st.progress(effectiveness / 100)
                    st.caption(f"{effectiveness}% effectiveness against this exploit")
                else:
                    st.progress(0.2)
                    st.caption("20% effectiveness - Requires new solution development")

# =======================
# DEPLOY PAGE
# =======================
elif page == "🚀 Deploy":
    st.title("🚀 Exploit Deployment & Testing")
    st.caption("Demo environment - Local testing only")
    
    if not st.session_state.exploits:
        st.warning("⚠️ No exploits available. Generate exploits in the Adversarial Exploit Lab first!")
    else:
        col1, col2 = st.columns([2, 1])
        
        with col1:
            st.subheader("🎯 Select Exploit")
            
            selected_exploit_idx = st.selectbox(
                "Generated Exploits",
                range(len(st.session_state.exploits)),
                format_func=lambda i: f"{st.session_state.exploits[i]['timestamp']} - {st.session_state.exploits[i]['algorithm']} ({len(st.session_state.exploits[i]['cves'])} CVEs, Impact: {st.session_state.exploits[i]['impact']}/10)"
            )
            
            if selected_exploit_idx is not None:
                exploit = st.session_state.exploits[selected_exploit_idx]
                
                st.info(f"**Algorithm:** {exploit['algorithm']} | **Platform:** {exploit['platform']} | **Confidence:** {exploit['confidence']}%")
                
                with st.expander("📋 View Exploit Details"):
                    st.markdown(f"**CVEs Used:** {', '.join(exploit['cves'])}")
                    st.markdown(f"**Impact Score:** {exploit['impact']}/10")
                    
                    st.markdown("**Alpha's Chain of Thought:**")
                    for thought in exploit['alpha_chain']:
                        st.caption(f"🔴 {thought}")
                    
                    st.markdown("**Omega's Chain of Thought:**")
                    for thought in exploit['omega_chain']:
                        st.caption(f"🔵 {thought}")
            
            st.markdown("---")
            st.subheader("🧪 Testing Configuration")
            
            test_env = st.selectbox(
                "Test Environment",
                ["Local Sandbox", "Docker Container", "Virtual Machine", "Test Lab"]
            )
            
            test_options = st.multiselect(
                "Test Options",
                ["Verbose Logging", "Step-by-Step Execution", "Capture Network Traffic", "Record Screenshots"],
                default=["Verbose Logging"]
            )
            
            col_btn1, col_btn2 = st.columns(2)
            
            with col_btn1:
                if st.button("🧪 Run Test", type="primary", use_container_width=True):
                    with st.spinner("Testing exploit..."):
                        import time
                        time.sleep(2)
                        st.success(f"✅ Test completed in {test_env}")
            
            with col_btn2:
                if st.button("📥 Export Report", use_container_width=True):
                    report = f"""
Α&Ω CyberATTech Exploit Report
=============================
Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

CVEs Used: {', '.join(exploit['cves'])}
Algorithm: {exploit['algorithm']}
Platform: {exploit['platform']}
Confidence: {exploit['confidence']}%
Impact: {exploit['impact']}/10

Alpha Chain of Thought:
{chr(10).join(['- ' + t for t in exploit['alpha_chain']])}

Omega Chain of Thought:
{chr(10).join(['- ' + t for t in exploit['omega_chain']])}
                    """
                    st.download_button(
                        "Download Report",
                        report,
                        file_name=f"exploit_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                        mime="text/plain"
                    )
        
        with col2:
            st.subheader("📊 Test Results")
            
            if st.button("▶️ Start Test", use_container_width=True):
                st.rerun()
            
            st.markdown("---")
            
            log_container = st.container(height=400)
            with log_container:
                st.code(f"""[{datetime.now().strftime('%H:%M:%S')}] System initialized
[{datetime.now().strftime('%H:%M:%S')}] Alpha & Omega GANs loaded
[{datetime.now().strftime('%H:%M:%S')}] Exploit selected: {exploit['algorithm']}
[{datetime.now().strftime('%H:%M:%S')}] CVEs: {', '.join(exploit['cves'])}
[{datetime.now().strftime('%H:%M:%S')}] Target: {test_env}
[{datetime.now().strftime('%H:%M:%S')}] Confidence: {exploit['confidence']}%
[{datetime.now().strftime('%H:%M:%S')}] 
[READY] Awaiting deployment command
[INFO] Demo mode: Local testing only
[INFO] All agents active
[STANDBY] System ready for testing...
                """, language="text")

# Exploit History
st.sidebar.markdown("---")
st.sidebar.subheader("📜 Generated Exploits")
if st.session_state.exploits:
    st.sidebar.caption(f"Total: {len(st.session_state.exploits)}")
    for i, exp in enumerate(st.session_state.exploits[:3]):
        with st.sidebar.expander(f"#{i+1} - {exp['algorithm'][:20]}..."):
            st.caption(f"CVEs: {len(exp['cves'])}")
            st.caption(f"Impact: {exp['impact']}/10")
            st.caption(f"Confidence: {exp['confidence']}%")
else:
    st.sidebar.caption("No exploits generated yet")

# Footer
st.sidebar.markdown("---")
st.sidebar.caption("⚠️ For authorized security research only")
st.sidebar.caption("Α&Ω CyberATTech v1.0")
st.sidebar.caption("[ano-cyberat.tech](https://ano-cyberat.tech)")
