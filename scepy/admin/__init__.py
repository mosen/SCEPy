from flask import Blueprint
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView

admin_app = Blueprint('admin_app', __name__)
admin = Admin(admin_app, name='SCEPy', template_mode='bootstrap3')

admin.add_view(ModelView())
