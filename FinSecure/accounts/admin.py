from django.contrib import admin
from .models import personal, income, expenses, savings, assets, financial_goals, risk_profile

admin.site.register(personal)
admin.site.register(income)
admin.site.register(expenses)
admin.site.register(savings)
admin.site.register(assets)
admin.site.register(financial_goals)
admin.site.register(risk_profile)
