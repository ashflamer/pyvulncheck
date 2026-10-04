"""HTTP entry points."""

from app.templating import render_tag
from app.config import load_settings


def widget_view(request):
    # attacker-influenced keys flow straight into the xmlattr filter
    return render_tag(request.get("attrs", {}))


def health_view(request):
    return {"status": "ok", "settings": load_settings("config.yaml")}
