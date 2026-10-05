"""
SQLAlchemy ORM models for all database tables.

ALL model modules MUST be imported here so that SQLAlchemy's mapper
can resolve cross-module string-based relationships (e.g., relationship("Organization")
used in targets.py needs identity.py to be loaded first).
"""

from app.models.enums import *          # noqa: F401, F403
from app.models.identity import *       # noqa: F401, F403
from app.models.targets import *        # noqa: F401, F403
from app.models.assets import *         # noqa: F401, F403
from app.models.urls import *           # noqa: F401, F403
from app.models.findings import *       # noqa: F401, F403
from app.models.scanning import *       # noqa: F401, F403
from app.models.agent import *          # noqa: F401, F403
from app.models.integrations import *   # noqa: F401, F403
from app.models.education import *      # noqa: F401, F403
from app.models.wordlists import *      # noqa: F401, F403
from app.models.traffic import *        # noqa: F401, F403
