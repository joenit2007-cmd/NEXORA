"""Role-based access control decorators."""

from functools import wraps
from flask import abort, flash, redirect, url_for
from flask_login import current_user


def role_required(*allowed_roles: str):
    """Restrict access to authenticated users matching one of allowed_roles."""

    def decorator(view_func):
        @wraps(view_func)
        def wrapped(*args, **kwargs):
            if not current_user.is_authenticated:
                flash("Authentication required.", "warning")
                return redirect(url_for("auth.login"))
            if current_user.role not in allowed_roles:
                abort(403)
            return view_func(*args, **kwargs)

        return wrapped

    return decorator
