from django.contrib import admin
from .models import Personal, Income, Expenses, Savings, Assets, FinancialGoals, RiskProfile

admin.site.register(Personal)
admin.site.register(Income)
admin.site.register(Expenses)
admin.site.register(Savings)
admin.site.register(Assets)
admin.site.register(FinancialGoals)
admin.site.register(RiskProfile)
