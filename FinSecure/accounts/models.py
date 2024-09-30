from django.db import models
from django.contrib.auth.models import User


class Personal(models.Model):
    MARITAL_STATUS_CHOICES = [
        ('Single', 'Single'),
        ('Married', 'Married'),
        ('Divorced', 'Divorced'),
        ('Widowed', 'Widowed'),
    ]

    user = models.OneToOneField(User, on_delete=models.CASCADE)
    name = models.TextField()
    email = models.TextField()
    phone = models.TextField()
    age = models.TextField()
    retirement_age = models.TextField()
    marital_status = models.TextField()
    dependents = models.TextField()

    def __str__(self):
        return self.user.username


class Income(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    monthly_income = models.TextField()
    other_sources = models.TextField()
    expected_salary_growth = models.TextField()
    employment_type = models.TextField()
    employer_contributions = models.TextField()
    
    def __str__(self):
        return self.user.username


class Expenses(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    monthly_expenses = models.TextField()
    annual_expenses = models.TextField()
    one_time_expenses = models.TextField()
    debt = models.TextField()
    
    def __str__(self):
        return self.user.username


class Savings(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    current_savings = models.TextField()
    retirement_savings = models.TextField()
    investments = models.TextField()
    return_on_investments = models.TextField()
    
    def __str__(self):
        return self.user.username


class Assets(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    real_estates = models.TextField()
    vehicles = models.TextField()
    liabilities = models.TextField()
    other_assets = models.TextField()
    
    def __str__(self):
        return self.user.username


class FinancialGoals(models.Model):
    RETIREMENT_LIFESTYLE_CHOICES = [
        ('luxurious', 'Luxurious'),
        ('comfortable', 'Comfortable'),
        ('moderate', 'Moderate'),
        ('frugal', 'Frugal')
    ]
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    retirement_lifestyle = models.CharField(max_length=20, choices=RETIREMENT_LIFESTYLE_CHOICES)
    
    def __str__(self):
        return self.user.username


class RiskProfile(models.Model):
    RISK_TOLERANCE_CHOICES = [
        ('High', 'High'),
        ('Medium', 'Medium'),
        ('Low', 'Low')
    ]
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    risk_tolerance = models.CharField(max_length=10, choices=RISK_TOLERANCE_CHOICES)
    
    def __str__(self):
        return self.user.username
