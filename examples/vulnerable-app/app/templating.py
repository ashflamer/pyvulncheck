"""Renders user-supplied attributes into HTML. This is the reachable one."""

from jinja2 import Environment
from jinja2.filters import do_xmlattr


def build_environment() -> Environment:
    return Environment(autoescape=True)


def render_tag(attributes: dict) -> str:
    """Called by the view layer with attributes taken from the request."""
    environment = build_environment()
    return "<div " + do_xmlattr(environment, attributes) + ">"
