"""
Global configuration for the OT Security Assessment Platform.
"""

# Purdue Reference Model levels
PURDUE_LEVELS = {
    0: "Level 0 – Field Devices (Sensors, Actuators, Drives)",
    1: "Level 1 – Basic Control (PLCs, RTUs, DCS Controllers)",
    2: "Level 2 – Supervisory Control (HMI, SCADA Servers)",
    3: "Level 3 – Site Operations & Control (Historian, MES, OPC Server)",
    4: "Level 4 – Site Business Planning (ERP, Data Warehouse)",
    5: "Level 5 – Enterprise Network (Corporate IT)",
}

PURDUE_LEVEL_SHORT = {
    0: "Field Devices",
    1: "Basic Control",
    2: "Supervisory",
    3: "Site Operations",
    4: "Business Planning",
    5: "Enterprise",
}

# IEC 62443 Security Level definitions
SECURITY_LEVELS = {
    0: "SL 0 – No specific requirements",
    1: "SL 1 – Protection against casual or coincidental violation",
    2: "SL 2 – Protection against intentional violation using simple means",
    3: "SL 3 – Protection against sophisticated attack with moderate resources",
    4: "SL 4 – Protection against nation-state level attack with extensive resources",
}

# IEC 62443 Foundational Requirements
FOUNDATIONAL_REQUIREMENTS = {
    1: {
        "code": "FR 1",
        "name": "Identification & Authentication Control (IAC)",
        "description": "Identify and authenticate all users, software processes and devices before allowing access.",
    },
    2: {
        "code": "FR 2",
        "name": "Use Control (UC)",
        "description": "Enforce assigned privileges of authenticated users, software processes and devices.",
    },
    3: {
        "code": "FR 3",
        "name": "System Integrity (SI)",
        "description": "Ensure integrity of the IACS to prevent unauthorized manipulation.",
    },
    4: {
        "code": "FR 4",
        "name": "Data Confidentiality (DC)",
        "description": "Ensure confidentiality of information on communication channels and data repositories.",
    },
    5: {
        "code": "FR 5",
        "name": "Restricted Data Flow (RDF)",
        "description": "Segment the IACS into zones and conduits to limit unnecessary data flow.",
    },
    6: {
        "code": "FR 6",
        "name": "Timely Response to Events (TRE)",
        "description": "Respond to security violations by notifying the proper authority and reporting evidence.",
    },
    7: {
        "code": "FR 7",
        "name": "Resource Availability (RA)",
        "description": "Ensure availability of the IACS against degradation or denial of service.",
    },
}

# NIST CSF functions
NIST_CSF_FUNCTIONS = {
    "ID": "Identify",
    "PR": "Protect",
    "DE": "Detect",
    "RS": "Respond",
    "RC": "Recover",
}

# FR to NIST CSF mapping
FR_TO_CSF = {
    1: ["PR.AC-1", "PR.AC-2", "PR.AC-3", "PR.AC-5", "PR.AC-6", "PR.AC-7"],
    2: ["PR.AC-4", "PR.DS-5", "PR.PT-3", "ID.AM-3"],
    3: ["PR.DS-6", "PR.DS-8", "PR.IP-1", "PR.IP-3", "DE.CM-4"],
    4: ["PR.DS-1", "PR.DS-2", "PR.DS-5"],
    5: ["PR.AC-5", "PR.DS-7", "DE.CM-1", "ID.AM-4"],
    6: ["DE.AE-1", "DE.AE-2", "DE.CM-7", "RS.AN-1", "RS.CO-2"],
    7: ["PR.IP-9", "PR.MA-1", "RC.RP-1", "RC.CO-1", "DE.CM-6"],
}

# Industrial protocol ports
OT_PROTOCOL_PORTS = {
    502:   "Modbus/TCP",
    20000: "DNP3",
    44818: "EtherNet/IP (TCP)",
    2222:  "EtherNet/IP (UDP)",
    4840:  "OPC-UA",
    47808: "BACnet",
    2404:  "IEC 60870-5-104",
    102:   "S7comm (Siemens S7)",
    1089:  "FF HSE",
    1090:  "FF Annunciation",
    9600:  "SRTP (GE)",
    789:   "EtherNet/IP (Allen-Bradley)",
    18245: "GE-SRTP",
    20547: "ProConOs",
    1962:  "PCWorx (Phoenix Contact)",
    2455:  "WAGO Ethernet",
    9600:  "Omron FINS/TCP",
}

# Scoring thresholds
SL_PASS_THRESHOLD = 0.80  # 80% of applicable questions must be "fully" for a SL to be achieved

# Roadmap priority weights
PRIORITY_WEIGHTS = {
    "severity":          0.35,
    "gap_magnitude":     0.25,
    "purdue_exposure":   0.20,
    "csf_criticality":   0.10,
    "exploit_likelihood": 0.10,
}

# Severity scores for priority calculation
SEVERITY_SCORES = {
    "CRITICAL": 100,
    "HIGH":      75,
    "MEDIUM":    50,
    "LOW":       25,
    "INFO":       5,
}

# Purdue level exposure scores (higher = more exposed/critical)
PURDUE_EXPOSURE_SCORES = {
    0: 100,  # Field devices - physical impact
    1: 90,   # PLCs/RTUs - direct process control
    2: 70,   # SCADA/HMI - supervisory
    3: 50,   # Historian/MES
    4: 30,   # ERP
    5: 20,   # Enterprise IT
}

# Industry sectors
INDUSTRY_SECTORS = [
    "Energy & Utilities (Electric)",
    "Oil & Gas",
    "Water & Wastewater",
    "Manufacturing (Discrete)",
    "Manufacturing (Process/Chemical)",
    "Pharmaceuticals",
    "Food & Beverage",
    "Transportation (Rail, Pipeline)",
    "Building Management",
    "Other",
]

# Asset types per Purdue level
ASSET_TYPES_BY_LEVEL = {
    0: ["Sensor", "Actuator", "Motor Drive", "Valve Positioner", "Flow Meter", "Transmitter"],
    1: ["PLC", "RTU", "DCS Controller", "Safety Instrumented System (SIS)", "PAC"],
    2: ["HMI", "SCADA Server", "Engineering Workstation", "Operator Workstation"],
    3: ["Historian Server", "MES Server", "OPC Server", "Domain Controller (OT)", "Batch Server"],
    4: ["ERP System", "Data Warehouse", "Reporting Server"],
    5: ["Corporate Firewall", "Active Directory", "Email Server", "Internet Gateway"],
}

# Database path
DB_PATH = "ot_assessment.db"

# Report output path
REPORT_OUTPUT_DIR = "reports"
