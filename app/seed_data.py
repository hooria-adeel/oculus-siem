"""Demo data: the fictional company's employees and files. Ported from the original seed.sql."""

DEMO_PASSWORD = "Oculus#Demo26"
ADMIN_PASSWORD = "Oculus#Admin26"

# (username, full name, employee id, role)
USERS = [
    ('ahmed.khan@oculus.com', 'Ahmed Khan', 'OC-1001', 'IT'),
    ('bilal.siddiqui@oculus.com', 'Bilal Siddiqui', 'OC-1002', 'IT'),
    ('hassan.raza@oculus.com', 'Hassan Raza', 'OC-1003', 'IT'),
    ('sara.malik@oculus.com', 'Sara Malik', 'OC-1004', 'Finance'),
    ('omar.farooq@oculus.com', 'Omar Farooq', 'OC-1005', 'Finance'),
    ('ayesha.siddiqa@oculus.com', 'Ayesha Siddiqa', 'OC-1006', 'Finance'),
    ('ali.hassan@oculus.com', 'Ali Hassan', 'OC-1007', 'HR'),
    ('fatima.noor@oculus.com', 'Fatima Noor', 'OC-1008', 'HR'),
    ('zainab.qureshi@oculus.com', 'Zainab Qureshi', 'OC-1009', 'HR'),
    ('usman.tariq@oculus.com', 'Usman Tariq', 'OC-1010', 'Marketing'),
    ('mahnoor.baig@oculus.com', 'Mahnoor Baig', 'OC-1011', 'Marketing'),
    ('hamza.sheikh@oculus.com', 'Hamza Sheikh', 'OC-1012', 'Marketing'),
    ('javeria.khan@oculus.com', 'Javeria Khan', 'OC-1013', 'Operations'),
    ('danish.iqbal@oculus.com', 'Danish Iqbal', 'OC-1014', 'Operations'),
    ('noman.aslam@oculus.com', 'Noman Aslam', 'OC-1015', 'Operations'),
    ('imran.shah@oculus.com', 'Imran Shah', 'OC-9001', 'Admin'),
]

# name, is_honeypot, description, content, allowed roles (honeypots: nobody)
ALL = ('IT', 'HR', 'Finance', 'Marketing', 'Operations', 'Admin')

RESOURCES = [
    ('Firewall.config', False, 'Network firewall settings', 'Firewall Status: ACTIVE\nBlocked IPs: 42\nLast Rule Update: 2026-10-01\nInbound Policy: DENY ALL (allowlist only)\nOutbound Policy: ALLOW ALL (logged)', ('IT', 'Admin')),
    ('Server_Logs.txt', False, 'Server activity logs', '09:58 Backup job started (nightly-full)\n10:03 Backup job completed - 412GB\n10:15 CPU load normal across all nodes\n11:40 SSH login from 10.0.4.22 (ahmed.khan)\n14:02 Disk usage on db-02 at 78%', ('IT', 'Admin')),
    ('VPN_Access_List.csv', False, 'Approved VPN users and device IDs', 'ahmed.khan | Device: OCULUS-LAP-04 | Status: Active\nbilal.siddiqui | Device: OCULUS-LAP-11 | Status: Active\nhassan.raza | Device: OCULUS-LAP-07 | Status: Active - Flagged for review', ('IT', 'Admin')),
    ('Network_Topology.pdf', False, 'Internal network diagram and subnet map', 'Core Switch: SW-CORE-01 (10.0.0.1)\nVLAN 10: Corporate (10.0.1.0/24)\nVLAN 20: Finance (10.0.2.0/24)\nVLAN 99: DMZ (10.0.99.0/24)', ('IT', 'Admin')),
    ('Payroll.xlsx', False, 'Employee salary records', 'Employee ID: OC-1001 | Monthly Salary: PKR 185,000\nEmployee ID: OC-1004 | Monthly Salary: PKR 165,000\nEmployee ID: OC-1007 | Monthly Salary: PKR 150,000\n(15 more rows...)', ('Finance', 'Admin')),
    ('Budget_2026.xlsx', False, 'Company budget planning', 'Q1 2026 Budget: PKR 42,000,000\nQ2 2026 Budget: PKR 38,500,000\nQ3 2026 Budget: PKR 45,200,000 (forecast)\nMarketing allocation: 18%', ('Finance', 'Admin')),
    ('Vendor_Invoices.pdf', False, 'Pending vendor payments', 'Invoice #INV-4471 | Vendor: TechSupply Co. | Amount: PKR 320,000 | Due: 2026-10-20\nInvoice #INV-4472 | Vendor: CloudHost PK | Amount: PKR 85,000 | Due: 2026-10-25', ('Finance', 'Admin')),
    ('Tax_Filings_2025.pdf', False, 'Annual tax filing records', 'Fiscal Year 2025\nTotal Revenue Declared: PKR 310,000,000\nTax Paid: PKR 46,500,000\nFiled: 2026-01-15 | Status: Accepted', ('Finance', 'Admin')),
    ('HR_Records.pdf', False, 'Employee personal records', 'Name: [Access Restricted to HR]\nDept: [Access Restricted to HR]\nJoining Date: [Access Restricted to HR]\nEmergency Contact: [Access Restricted to HR]', ('HR', 'Admin')),
    ('Leave_Requests.xlsx', False, 'Employee leave applications', 'Ahmed Khan - Annual Leave - Oct 20-22 - Approved\nMahnoor Baig - Sick Leave - Oct 10 - Approved\nDanish Iqbal - Annual Leave - Nov 1-5 - Pending', ('HR', 'Admin')),
    ('Performance_Reviews_Q3.pdf', False, 'Quarterly performance review summaries', 'Q3 2026 Review Cycle\nAverage Rating (Company-wide): 3.8 / 5\nPromotions Recommended: 3\nPIPs Issued: 1', ('HR', 'Admin')),
    ('Recruitment_Pipeline.xlsx', False, 'Open roles and candidate pipeline', 'Role: Junior SOC Analyst | Stage: Final Interview | Candidates: 3\nRole: Backend Developer | Stage: Technical Screen | Candidates: 7', ('HR', 'Admin')),
    ('Campaign_Analytics.xlsx', False, 'Ad campaign performance data', 'Campaign: Autumn Launch 2026\nImpressions: 1,240,000 | Clicks: 38,200 | CTR: 3.08%\nSpend: PKR 1,800,000 | Conversions: 2,110', ('Marketing', 'Admin')),
    ('Brand_Guidelines.pdf', False, 'Internal brand style guide', 'Primary Color: #0B1F3A\nLogo Clear Space: minimum 20px\nTone of Voice: Confident, precise, human\nDo not stretch or recolor the logo mark.', ('Marketing', 'Admin')),
    ('Social_Media_Calendar.xlsx', False, 'Upcoming posts and content schedule', 'Oct 18 - Product teaser - Instagram/LinkedIn\nOct 22 - Customer spotlight - LinkedIn\nOct 29 - Webinar announcement - All channels', ('Marketing', 'Admin')),
    ('Competitor_Analysis.pdf', False, 'Market and competitor research', 'Competitor A: 22% market share, strong in enterprise\nCompetitor B: 14% market share, aggressive pricing\nOculus positioning: mid-market, security-first differentiation', ('Marketing', 'Admin')),
    ('Supply_Chain_Status.xlsx', False, 'Vendor and shipment tracking', 'Shipment #SC-2291 | Vendor: GlobalParts Ltd | Status: In Transit | ETA: Oct 19\nShipment #SC-2292 | Vendor: Nexline Logistics | Status: Delivered', ('Operations', 'Admin')),
    ('Facility_Access_Log.csv', False, 'Building entry/exit records', '08:02 javeria.khan - Main Entrance - Entry\n08:15 danish.iqbal - Server Room - Entry (Badge: OC-1014)\n17:45 noman.aslam - Main Entrance - Exit', ('Operations', 'Admin')),
    ('Equipment_Inventory.xlsx', False, 'Company hardware and asset tracking', 'Laptops Assigned: 42 | Spare Stock: 6\nServer Room Racks: 8 | Utilization: 71%\nPending Asset Requests: 2', ('Operations', 'Admin')),
    ('Employee_Handbook.pdf', False, 'Policies, benefits and working hours', 'OCULUS EMPLOYEE HANDBOOK 2026\n1. Working hours: 09:00-17:30, Monday to Friday\n2. Leave: 21 annual days, 10 sick days\n3. Acceptable use of company systems\n4. Reporting a security concern: it-helpdesk@oculus.com', ALL),
    ('Holiday_Calendar_2026.pdf', False, 'Public holidays and office closures', 'Nov 9   Iqbal Day (office closed)\nDec 25  Quaid-e-Azam Day (office closed)\nDec 31  Early close, 13:00\nJan 1   New Year (office closed)', ALL),
    ('Org_Chart.pdf', False, 'Company structure and reporting lines', 'Executive Committee\n  Engineering / IT   Finance   HR   Marketing   Operations\nSecurity team reports to the Head of IT.', ALL),
    ('Expense_Policy.pdf', False, 'How to claim travel and equipment expenses', 'Claims must be filed within 30 days with receipts.\nTravel above PKR 50,000 needs manager approval.\nEquipment purchases go through Operations.', ALL),
    ('IT_Helpdesk_Guide.docx', False, 'Password resets, VPN and printer setup', 'Reset your password: Settings > Account > Change password.\nVPN: install the Oculus client, sign in with your work email.\nPrinters: \\\\print-01 (Floor 2), \\\\print-02 (Floor 3).', ALL),
    ('Passwords.txt', True, 'Shared service logins', 'Shared service accounts (do not email)\nsvc-backup   | Bk#2025-nightly!x\nsvc-reports  | Rpt$Q3-ro-4471\ndb-master    | M4ster!pg-prod-09\nvpn-breakglass | Brk-Glass#7731', ()),
    ('CEO_Salary.xlsx', True, 'Executive compensation 2025', 'Executive Compensation FY2025 (confidential)\nCEO  | Base PKR 48,000,000 | Bonus PKR 21,500,000\nCFO  | Base PKR 31,000,000 | Bonus PKR 12,000,000\nCTO  | Base PKR 29,500,000 | Bonus PKR 11,250,000', ()),
    ('Confidential_Project_Phoenix.pdf', True, 'Project Phoenix: board draft', 'PROJECT PHOENIX - BOARD DRAFT v3\nAcquisition target: Northgate Logistics Ltd.\nIndicative valuation: PKR 3.2B | Close target: Q1 2026\nDistribution restricted to the Executive Committee.', ()),
    ('Client_Database_Export.sql', True, 'Customer export (nightly dump)', '-- customers_export_2026-10-20.sql\nINSERT INTO customers (id, name, email, tier) VALUES\n(1041, \'Halcyon Traders\', \'accounts@halcyon.example\', \'gold\'),\n(1042, \'Meridian Foods\', \'ap@meridianfoods.example\', \'silver\');', ()),
    ('IT_Admin_Credentials.docx', True, 'IT admin access sheet', 'IT ADMIN ACCESS SHEET\nDomain admin : adm-oculus | Dm#Adm-2026-Q4!\nFirewall web : fw-admin    | Fw!c0nsole-81\nBackup NAS   : nas-root    | Nas#R00t-2025', ()),
]
