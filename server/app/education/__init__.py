"""Educational content system — teaches beginners the methodology."""

from app.education.content import EducationalContent, get_content, list_all_content
from app.education.report_builder import (
    SEVERITY_GUIDANCE,
    generate_report,
    get_severity_info,
    get_poc_tip,
    get_vulnerability_references,
    get_default_remediation,
)

from app.education.checklists import (
    API_CHECKLIST,
    TEMPLATES,
    WEB_APP_CHECKLIST,
    get_template,
    list_templates,
)

from app.education.playbooks import (
    PlaybookMatch,
    PlaybookRecommender,
)

__all__ = [
    "EducationalContent",
    "get_content",
    "list_all_content",
    "SEVERITY_GUIDANCE",
    "generate_report",
    "get_severity_info",
    "get_poc_tip",
    "get_vulnerability_references",
    "get_default_remediation",
    "WEB_APP_CHECKLIST",
    "API_CHECKLIST",
    "TEMPLATES",
    "get_template",
    "list_templates",
    "PlaybookMatch",
    "PlaybookRecommender",
]

