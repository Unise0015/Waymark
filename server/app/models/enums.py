import enum

class OrgRole(str, enum.Enum):
    OWNER = "owner"
    MEMBER = "member"
    VIEWER = "viewer"

class TargetStatus(str, enum.Enum):
    ACTIVE = "active"
    PAUSED = "paused"
    ARCHIVED = "archived"

class ScopeStatus(str, enum.Enum):
    IN_SCOPE = "in_scope"
    OUT_OF_SCOPE = "out_of_scope"
    PENDING_REVIEW = "pending_review"

class ScanMode(str, enum.Enum):
    FULL = "full"
    PASSIVE_ONLY = "passive_only"
    SINGLE_TOOL = "single_tool"

class ScanJobStatus(str, enum.Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

class ToolRunStatus(str, enum.Enum):
    QUEUED = "queued"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"

class FindingSeverity(str, enum.Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class FindingStatus(str, enum.Enum):
    OPEN = "open"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    RESOLVED = "resolved"
    ACCEPTED_RISK = "accepted_risk"

class PluginCategory(str, enum.Enum):
    SUBDOMAIN_ENUM = "subdomain_enum"
    HTTP_PROBE = "http_probe"
    PORT_SCAN = "port_scan"
    WEB_CRAWL = "web_crawl"
    VULN_SCAN = "vuln_scan"
    DNS_ENUM = "dns_enum"
    CLOUD_ENUM = "cloud_enum"
    DIR_FUZZ = "dir_fuzz"        # Directory/file fuzzing (ffuf)
    JS_ANALYSIS = "js_analysis"
    HISTORICAL_URL = "historical_url"

class DNSRecordType(str, enum.Enum):
    A = "A"
    AAAA = "AAAA"
    CNAME = "CNAME"
    MX = "MX"
    NS = "NS"
    TXT = "TXT"
    SOA = "SOA"
    SRV = "SRV"
    PTR = "PTR"

class NotificationType(str, enum.Enum):
    NEW_SUBDOMAIN = "new_subdomain"
    NEW_FINDING = "new_finding"
    SCAN_COMPLETE = "scan_complete"
    SCAN_STARTED = "scan_started"
    CONTENT_CHANGE = "content_change"
    CERTIFICATE_EXPIRY = "certificate_expiry"

class ScheduleFrequency(str, enum.Enum):
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"
    CUSTOM = "custom"

class ScanProfile(str, enum.Enum):
    STEALTH = "stealth"         # Tier 1 only (passive, zero target traffic)
    STANDARD = "standard"       # Tier 1 auto + Tier 2 auto + Tier 3 gated
    AUTONOMOUS = "autonomous"   # Tier 1+2 auto + Tier 3 auto on top-N ROI
    CUSTOM = "custom"           # User picks individual tools

class ScanTier(str, enum.Enum):
    PASSIVE = "passive"         # Tier 1: zero traffic (subfinder, crt.sh, gau)
    VALIDATION = "validation"   # Tier 2: light probing (httpx, ROI scoring)
    ACTIVE = "active"           # Tier 3: heavy fuzzing/scanning (ffuf, nuclei, katana)

