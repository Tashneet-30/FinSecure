from django.db import models
from django.contrib.auth.models import User
from .utils.fields import EncryptedField


class Personal(models.Model):
    MARITAL_STATUS_CHOICES = [
        ('Single', 'Single'),
        ('Married', 'Married'),
        ('Divorced', 'Divorced'),
        ('Widowed', 'Widowed'),
    ]

    user = models.OneToOneField(User, on_delete=models.CASCADE)
    name = models.CharField(max_length=50)
    email = models.EmailField()
    phone = models.CharField(max_length=15)  # Increased length for phone numbers
    age = models.IntegerField()
    retirement_age = models.IntegerField()
    marital_status = models.CharField(max_length=20, choices=MARITAL_STATUS_CHOICES)
    dependents = models.IntegerField()

    def __str__(self):
        return self.user.username


class Income(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    monthly_income = models.DecimalField(max_digits=10, decimal_places=2)  # Use DecimalField for financial data
    other_sources = models.DecimalField(max_digits=10, decimal_places=2)
    expected_salary_growth = models.DecimalField(max_digits=5, decimal_places=2)
    employment_type = models.CharField(max_length=10)
    employer_contributions = models.DecimalField(max_digits=10, decimal_places=2)
    
    def __str__(self):
        return self.user.username


class Expenses(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    monthly_expenses = models.DecimalField(max_digits=10, decimal_places=2)
    annual_expenses = models.DecimalField(max_digits=10, decimal_places=2)
    one_time_expenses = models.DecimalField(max_digits=10, decimal_places=2)
    debt = models.DecimalField(max_digits=10, decimal_places=2)
    
    def __str__(self):
        return self.user.username


class Savings(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    current_savings = models.DecimalField(max_digits=10, decimal_places=2)
    retirement_savings = models.DecimalField(max_digits=10, decimal_places=2)
    investments = models.DecimalField(max_digits=10, decimal_places=2)
    return_on_investments = models.DecimalField(max_digits=10, decimal_places=2)
    
    def __str__(self):
        return self.user.username


class Assets(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    real_estates = models.DecimalField(max_digits=10, decimal_places=2)
    vehicles = models.DecimalField(max_digits=10, decimal_places=2)
    liabilities = models.DecimalField(max_digits=10, decimal_places=2)
    other_assets = models.DecimalField(max_digits=10, decimal_places=2)
    
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
